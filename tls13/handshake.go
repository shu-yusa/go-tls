package tls13

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
)

type (
	tlsContext struct {
		secrets                      Secrets
		trafficSecrets               HandshakeTrafficSecrets
		applicationTrafficSecrets    ApplicationTrafficSecrets
		handshakeClientHello         []byte
		handshakeServerHello         []byte
		handshakeEncryptedExtensions []byte
		handshakeCertificate         []byte
		handshakeCertificateVerify   []byte
		serverFinished               []byte
	}

	sequenceNumbers struct {
		handshakeKeySeqNum uint64
		appKeyClientSeqNum uint64
		appKeyServerSeqNum uint64
	}
)

var (
	acceptableGetRequest = "GET / HTTP/1.1\r\nHost: localhost\r\n"
	internalErroAlert    = Alert{Level: fatal, Description: internal_error}
)

func Server(logger *log.Logger) {
	listener, err := net.Listen("tcp", ":443")
	if err != nil {
		log.Fatalf("Failed to listen on port 443: %v", err)
	}
	defer listener.Close()
	logger.Println("Listening on port 443")

	for {
		conn, err := listener.Accept()
		logger.Printf("Accepted connection from %s\n\n", conn.RemoteAddr().String())
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go func(conn net.Conn) {
			defer conn.Close()
			tlsContext := &tlsContext{}
			sequenceNumbers := sequenceNumbers{
				handshakeKeySeqNum: 0,
				appKeyClientSeqNum: 0,
				appKeyServerSeqNum: 0,
			}
			handshakeFinished := false
			applicationDataBuffer := make([]byte, 0)
			for {
				alert := handleMessage(conn, logger, tlsContext, &sequenceNumbers, &handshakeFinished, &applicationDataBuffer)
				logger.Printf("Sequence numbers: %v\n", sequenceNumbers.appKeyServerSeqNum)
				if alert != nil {
					logger.Println("Sending alert to the client")
					var key, iv []byte
					if tlsContext.applicationTrafficSecrets.ServerWriteKey != nil {
						key = tlsContext.applicationTrafficSecrets.ServerWriteKey
						iv = tlsContext.applicationTrafficSecrets.ServerWriteIV
					} else {
						key = tlsContext.trafficSecrets.ServerWriteKey
						iv = tlsContext.trafficSecrets.ServerWriteIV
					}
					encryptedResponse, _ := NewTLSCipherMessageText(
						key,
						iv,
						TLSInnerPlainText{
							Content:     alert.Bytes(),
							contentType: AlertRecord,
						},
						sequenceNumbers.appKeyServerSeqNum,
					)
					conn.Write(encryptedResponse.Bytes())
					break
				}
			}
		}(conn)
	}
}

func handleMessage(
	conn net.Conn,
	logger *log.Logger,
	tlsContext *tlsContext,
	seqNum *sequenceNumbers,
	handshakeFinished *bool,
	applicationBuffer *[]byte,
) *Alert {
	// Read TLS record
	tlsHeaderBuffer := make([]byte, 5)
	_, err := conn.Read(tlsHeaderBuffer)
	if err != nil {
		logger.Printf("Error in reading from connection: %v\n", err)
		return &internalErroAlert
	}
	length := binary.BigEndian.Uint16(tlsHeaderBuffer[3:5])

	payloadBuffer := make([]byte, length)
	_, err = io.ReadFull(conn, payloadBuffer)
	if err != nil {
		logger.Printf("Error reading payload from connection: %v\n", err)
		return &internalErroAlert
	}

	tlsRecord := &TLSRecord{
		ContentType:         ContentType(tlsHeaderBuffer[0]),
		LegacyRecordVersion: ProtocolVersion(binary.BigEndian.Uint16(tlsHeaderBuffer[1:3])),
		Length:              length,
		Fragment:            payloadBuffer,
	}
	logger.Printf("TLS Record payload: %x\n", payloadBuffer)

	switch tlsRecord.ContentType {
	case HandshakeRecord: // 22 stands for Handshake record type
		logger.Println("Received TLS Handshake message")
		logger.Printf("Legacy version: %s (%x)\n", ProtocolVersionName[tlsRecord.LegacyRecordVersion], tlsRecord.LegacyRecordVersion)
		logger.Printf("Record length: %d bytes\n", tlsRecord.Length)

		msgType := HandshakeType(tlsRecord.Fragment[0])
		// extract 3 bytes
		handshakeLength := (uint32(tlsRecord.Fragment[1]) << 16) | (uint32(tlsRecord.Fragment[2]) << 8) | uint32(tlsRecord.Fragment[3])
		logger.Println(fmt.Sprintf("Handshake msg_type: %d\n", msgType))
		switch msgType {
		case ClientHello: // 0x01
			logger.Println("Received ClientHello message")
			logger.Println("Handshake: ClientHello")
			logger.Printf("Handshake message length: %d bytes\n", handshakeLength)
			logger.Println()
			clientHello := NewClientHello(tlsRecord.Fragment[4 : 4+handshakeLength])
			logger.Printf("Legacy version: %s (%x)\n", ProtocolVersionName[clientHello.LegacyVersion], clientHello.LegacyVersion)
			logger.Printf("Random: %x\n", clientHello.Random)
			logger.Printf("LegacySessionIDLength: %d\n", len(clientHello.LegacySessionID))
			logger.Printf("LegacySessionID: %x\n", clientHello.LegacySessionID)
			logger.Println("CipherSuites")
			for _, cipherSuite := range clientHello.CipherSuites {
				logger.Printf("  CipherSuite: %s (%x)\n", CipherSuiteName[cipherSuite], cipherSuite)
			}
			logger.Printf("LegacyCompressionMethodLength: %d\n", len(clientHello.LegacyCompressionMethod))
			logger.Printf("LegacyCompressionMethod: %x\n\n", clientHello.LegacyCompressionMethod)

			logger.Println("Extensions")
			extensions := clientHello.ParseExtensions(logger)
			logger.Println()

			keyShareExtension := extensions[KeyShareExtensionType].(KeyShareExtension)

			keySharedEntry, selectedCurve := keyShareExtension.SelectECDHKeyShare()
			if selectedCurve == nil {
				logger.Println("Unsupported curve")
				return &internalErroAlert
			}
			hasher := sha256.New
			logger.Printf("Selected curve: %s (%x)\n", NamedGroupName[keySharedEntry.Group], keySharedEntry.Group)

			clientECDHPublicKey := keySharedEntry.KeyExchangeData

			// ServerHello message
			ecdhServerPrivateKey, err := selectedCurve.GenerateKey(rand.Reader)
			if err != nil {
				logger.Println("Error in calculating ECDH private key")
				return &internalErroAlert
			}
			logger.Printf("ECDH Server Private key:%x\n", ecdhServerPrivateKey.Bytes())
			logger.Printf("ECDH Server Public key:%x\n", ecdhServerPrivateKey.PublicKey().Bytes())
			serverHello, err := NewServerHello(ecdhServerPrivateKey.PublicKey(), keySharedEntry.Group, TLS_AES_128_GCM_SHA256, clientHello.LegacySessionID)
			if err != nil {
				logger.Println("Error constructing ServerHello message:", err)
				return &internalErroAlert
			}
			handshakeServerHello := Handshake[ServerHelloMessage]{
				MsgType:          ServerHello,
				Length:           uint32(len(serverHello.Bytes())),
				HandshakeMessage: serverHello,
			}
			serverHelloTLSRecord := TLSRecord{
				ContentType:         HandshakeRecord, // 0x16
				LegacyRecordVersion: TLS12,           // 0x0303
				Length:              uint16(len(handshakeServerHello.Bytes())),
				Fragment:            handshakeServerHello.Bytes(),
			}
			logger.Printf("ServerHello: %x\n\n", serverHelloTLSRecord.Bytes())
			conn.Write(serverHelloTLSRecord.Bytes())

			// // ChangeCipherSpec message
			// conn.Write(TLSPlainText{
			// 	contentType:         ChangeCipherSpecRecord, // 0x14
			// 	legacyRecordVersion: TLS12,                  // 0x0303
			// 	length:              1,
			// 	fragment:            []byte{1},
			// }.Bytes())

			secrets, err := GenerateSecrets(hasher, selectedCurve, clientECDHPublicKey, ecdhServerPrivateKey)
			if err != nil {
				logger.Println("Error generating secrets:", err)
				return &internalErroAlert
			}
			logger.Printf("Shared secret(pre-master secret): %x\n", secrets.SharedSecret)
			logger.Printf("Early Secret: %x\n", secrets.EarlySecret)
			logger.Printf("Handshake Secret: %x\n", secrets.HandshakeSecret)
			trafficSecrets, err := secrets.HandshakeTrafficKeys(tlsRecord.Fragment, serverHelloTLSRecord.Fragment, 16, 12)
			if err != nil {
				logger.Println("Error in deriving handshake keys:", err)
			}
			logger.Printf("Client Handshake Traffic Secret: %x\n", trafficSecrets.ClientHandshakeTrafficSecret)
			logger.Printf("Server Handshake Traffic Secret: %x\n", trafficSecrets.ServerHandshakeTrafficSecret)
			logger.Printf("Server write key: %x\n", trafficSecrets.ServerWriteKey)
			logger.Printf("Server IV: %x\n\n", trafficSecrets.ServerWriteIV)

			// EncryptedExtensions message
			encryptedExtensions := EncryptedExtensionsMessage{
				Extensions: []Extension{},
			}
			handshakeEncryptedExtensions := Handshake[EncryptedExtensionsMessage]{
				MsgType:          EncryptedExtensions,
				Length:           uint32(len(encryptedExtensions.Bytes())),
				HandshakeMessage: encryptedExtensions,
			}
			encryptedExtensionsTLSRecord, err := NewTLSCipherMessageText(
				trafficSecrets.ServerWriteKey,
				trafficSecrets.ServerWriteIV,
				TLSInnerPlainText{
					Content:     handshakeEncryptedExtensions.Bytes(),
					contentType: HandshakeRecord,
				},
				0,
			)
			logger.Printf("Encrypted EncryptedExtensions TLS Record: %x\n\n", encryptedExtensionsTLSRecord.Bytes())
			conn.Write(encryptedExtensionsTLSRecord.Bytes())

			// Certificate message
			serverCert, err := tls.LoadX509KeyPair("server.crt", "server.key")
			if err != nil {
				logger.Println("Error in loading server certificate:", err)
				return &internalErroAlert
			}
			certificate := CertificateMessage{
				CertificateRequestContext: []byte{},
				CertificateList: []CertificateEntry{
					{
						CertType: X509,
						CertData: serverCert.Certificate[0],
					},
				},
			}
			handshakeCertificate := Handshake[CertificateMessage]{
				MsgType:          Certificate,
				Length:           uint32(len(certificate.Bytes())),
				HandshakeMessage: certificate,
			}
			logger.Printf("Certificate: %x\n", certificate.Bytes())
			logger.Printf("Certificate Length: %d\n\n", len(certificate.Bytes()))
			certificateTLSRecord, err := NewTLSCipherMessageText(
				trafficSecrets.ServerWriteKey,
				trafficSecrets.ServerWriteIV,
				TLSInnerPlainText{
					Content:     handshakeCertificate.Bytes(),
					contentType: HandshakeRecord,
				},
				1,
			)
			if err != nil {
				logger.Println("Error in encrypting Certificate message:", err)
				return &internalErroAlert
			}
			logger.Printf("Certificate TLS Record: %x\n\n", certificateTLSRecord.Bytes())
			conn.Write(certificateTLSRecord.Bytes())

			// CertificateVerify message
			serverPriv, ok := serverCert.PrivateKey.(*ecdsa.PrivateKey)
			if !ok {
				logger.Println("Error in type assertion of server private key")
				return &internalErroAlert
			}
			signature, err := SignCertificate(
				serverPriv,
				tlsRecord.Fragment,                   // ClientHello
				serverHelloTLSRecord.Fragment,        // ServerHello
				handshakeEncryptedExtensions.Bytes(), // EncryptedExtensions
				handshakeCertificate.Bytes(),         // Certificate
			)
			if err != nil {
				logger.Println("Error in signing certificate:", err)
				return &internalErroAlert
			}
			logger.Printf("length of signature: %d\n", len(signature))
			logger.Printf("Signature: %x\n", signature)
			certificateVerifyMessage := CertificateVerifyMessage{
				Algorithm: ecdsa_secp256r1_sha256,
				Signature: signature,
			}
			handshakeCertificateVerify := Handshake[CertificateVerifyMessage]{
				MsgType:          CertificateVerify,
				Length:           uint32(len(certificateVerifyMessage.Bytes())),
				HandshakeMessage: certificateVerifyMessage,
			}
			certificateVerifyTLSRecord, err := NewTLSCipherMessageText(
				trafficSecrets.ServerWriteKey,
				trafficSecrets.ServerWriteIV,
				TLSInnerPlainText{
					Content:     handshakeCertificateVerify.Bytes(),
					contentType: HandshakeRecord,
				},
				2,
			)
			if err != nil {
				logger.Println("Error in encrypting CertificateVerify message:", err)
				return &internalErroAlert
			}
			logger.Printf("CertificateVerify TLS Record: %x\n\n", certificateVerifyTLSRecord.Bytes())
			conn.Write(certificateVerifyTLSRecord.Bytes())

			// Finished message
			finishedMessage, err := NewFinishedMessage(
				hasher,
				trafficSecrets.ServerHandshakeTrafficSecret,
				tlsRecord.Fragment,                   // ClientHello
				serverHelloTLSRecord.Fragment,        // ServerHello
				handshakeEncryptedExtensions.Bytes(), // EncryptedExtensions
				handshakeCertificate.Bytes(),         // Certificate
				handshakeCertificateVerify.Bytes(),   // CertificateVerify
			)
			handshakeFinished := Handshake[FinishedMessage]{
				MsgType:          Finished,
				Length:           uint32(len(finishedMessage.Bytes())),
				HandshakeMessage: finishedMessage,
			}
			if err != nil {
				logger.Println("Error in generating finished key:", err)
				return &internalErroAlert
			}
			finishedTLSRecord, err := NewTLSCipherMessageText(
				trafficSecrets.ServerWriteKey,
				trafficSecrets.ServerWriteIV,
				TLSInnerPlainText{
					Content:     handshakeFinished.Bytes(),
					contentType: HandshakeRecord,
				},
				3,
			)
			if err != nil {
				logger.Println("Error in encrypting Finished message:", err)
				return &internalErroAlert
			}
			logger.Printf("Finished TLS Record: %x\n\n", finishedTLSRecord.Bytes())
			conn.Write(finishedTLSRecord.Bytes())

			// St[]byteore traffic secrets
			tlsContext.secrets = *secrets
			tlsContext.trafficSecrets = *trafficSecrets
			tlsContext.handshakeClientHello = tlsRecord.Fragment
			tlsContext.handshakeServerHello = serverHelloTLSRecord.Fragment
			tlsContext.handshakeEncryptedExtensions = handshakeEncryptedExtensions.Bytes()
			tlsContext.handshakeCertificate = handshakeCertificate.Bytes()
			tlsContext.handshakeCertificateVerify = handshakeCertificateVerify.Bytes()
			tlsContext.serverFinished = handshakeFinished.Bytes()
		}
	case ChangeCipherSpecRecord:
		logger.Printf("Received TLS ChangeCipherSpec message. Ignored.\n\n")
	case ApplicationDataRecord: // 23 stands for ApplicationData record type
		logger.Println("Received TLS ApplicationData message")
		logger.Printf("Sequence number: %d\n", seqNum.appKeyClientSeqNum)

		var key, iv []byte
		var sequence uint64
		if *handshakeFinished {
			key = tlsContext.applicationTrafficSecrets.ClientWriteKey
			iv = tlsContext.applicationTrafficSecrets.ClientWriteIV
			sequence = seqNum.appKeyClientSeqNum
			seqNum.appKeyClientSeqNum++
		} else {
			key = tlsContext.trafficSecrets.ClientWriteKey
			iv = tlsContext.trafficSecrets.ClientWriteIV
			sequence = seqNum.handshakeKeySeqNum
			seqNum.handshakeKeySeqNum++
		}
		logger.Printf("Key: %x\n", key)
		logger.Printf("IV: %x\n", iv)
		decrypedRecord, err := DecryptTLSInnerPlaintext(key, iv, tlsRecord.Fragment, sequence, tlsHeaderBuffer)
		if err != nil {
			logger.Println("Error in decrypting ApplicationData:", err)
			return &internalErroAlert
		}
		logger.Printf("Length of decrypted data: %d\n", len(decrypedRecord))
		decrypedRecord = RemoveZeroPaddingFromTail(decrypedRecord)
		if len(decrypedRecord) == 0 {
			logger.Println("Error in decrypting ApplicationData")
			return &internalErroAlert
		}
		tlsInnerPlainText := TLSInnerPlainText{
			Content:     decrypedRecord[:len(decrypedRecord)-1],
			contentType: ContentType(decrypedRecord[len(decrypedRecord)-1]),
		}
		// get content type from the last byte
		logger.Printf("Received Content type: %s (%d)\n", ContentTypeName[tlsInnerPlainText.contentType], tlsInnerPlainText.contentType)
		switch tlsInnerPlainText.contentType {
		case HandshakeRecord:
			logger.Printf("Decrypted ApplicationData: %x\n", tlsInnerPlainText.Content)
			msgType := HandshakeType(tlsInnerPlainText.Content[0])
			logger.Printf("Handshake msg_type: %d\n", msgType)
			// extract 3 bytes
			handshakeLength := (uint32(tlsInnerPlainText.Content[1]) << 16) | (uint32(tlsInnerPlainText.Content[2]) << 8) | uint32(tlsInnerPlainText.Content[3])
			logger.Printf("Handshake message length: %d bytes\n", handshakeLength)
			switch msgType {
			case Finished:
				clientSentFinishedMessage := FinishedMessage{
					VerifyData: tlsInnerPlainText.Content[4 : handshakeLength+4],
				}
				serverCalculatedFinishedMessage, err := NewFinishedMessage(
					sha256.New,
					tlsContext.trafficSecrets.ClientHandshakeTrafficSecret,
					tlsContext.handshakeClientHello,
					tlsContext.handshakeServerHello,
					tlsContext.handshakeEncryptedExtensions,
					tlsContext.handshakeCertificate,
					tlsContext.handshakeCertificateVerify,
					tlsContext.serverFinished,
				)
				if err != nil {
					logger.Println("Error in generating client finished message:", err)
					return &internalErroAlert
				}
				if !bytes.Equal(clientSentFinishedMessage.VerifyData, serverCalculatedFinishedMessage.VerifyData) {
					logger.Println("Client Finished message does not match")
					return &internalErroAlert
				}
				logger.Printf("Client Finished Message: %x\n", clientSentFinishedMessage.Bytes())
				logger.Printf("Client Finished message matches. Connection established!\n\n")
				*handshakeFinished = true
				appTrafficSecrets, err := tlsContext.secrets.ApplicationTrafficKeys(
					tlsContext.handshakeClientHello,
					tlsContext.handshakeServerHello,
					tlsContext.handshakeEncryptedExtensions,
					tlsContext.handshakeCertificate,
					tlsContext.handshakeCertificateVerify,
					tlsContext.serverFinished,
					16,
					12,
				)
				if err != nil {
					logger.Println("Error in deriving application traffic secrets:", err)
					return &internalErroAlert
				}
				logger.Printf("Client Application Traffic Secret: %x\n", appTrafficSecrets.ClientApplicationTrafficSecret)
				logger.Printf("Server Application Traffic Secret: %x\n", appTrafficSecrets.ServerApplicationTrafficSecret)
				tlsContext.applicationTrafficSecrets = *appTrafficSecrets
			default:
				logger.Println("Unhandled message")
			}
		case ApplicationDataRecord:
			logger.Printf("Decrypted ApplicationData: %s\n", tlsInnerPlainText.Content)
			*applicationBuffer = append(*applicationBuffer, tlsInnerPlainText.Content...)
			requestMessage := string(*applicationBuffer)
			if strings.HasSuffix(requestMessage, "\r\n\r\n") {
				if strings.HasPrefix(requestMessage, acceptableGetRequest) {
					logger.Println("Received HTTP GET request")
					response := "HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\nHello, TLS 1.3!\n"
					encryptedResponse, err := NewTLSCipherMessageText(
						tlsContext.applicationTrafficSecrets.ServerWriteKey,
						tlsContext.applicationTrafficSecrets.ServerWriteIV,
						TLSInnerPlainText{
							Content:     []byte(response),
							contentType: ApplicationDataRecord,
						},
						seqNum.appKeyServerSeqNum,
					)
					if err != nil {
						logger.Println("Error in encrypting response:", err)
						return &internalErroAlert
					}
					logger.Printf("Encrypted response: %x\n", encryptedResponse.Bytes())
					conn.Write(encryptedResponse.Bytes())
					logger.Println("Sent hello TLS1.3 response")
					seqNum.appKeyServerSeqNum++
				}
				return &Alert{Level: warning, Description: close_notify}
			}
			logger.Printf("Application buffer:\n%s\n", *applicationBuffer)
		case AlertRecord:
			// Return error to the client
			return &internalErroAlert
		default:

		}
	default:
		logger.Println("Received unsupported message")
	}
	return nil
}
