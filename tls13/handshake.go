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
	// tlsContext holds secrets and handshake messages used over a connection
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

	// sequenceNumbers is a counter used in the calculation of AEAD nonce.
	// It is incremented for each record sent, and is reset to zero whenever the encryption key changes.
	sequenceNumbers struct {
		handshakeKeySeqNum uint64
		appKeyClientSeqNum uint64
		appKeyServerSeqNum uint64
	}
)

var (
	// This TLS server only supports HTTP GET request to the root path
	acceptableGetRequest = "GET / HTTP/1.1\r\nHost: localhost\r\n"
	internalErrorAlert   = Alert{Level: fatal, Description: internal_error}
)

func Server(logger *log.Logger) {
	listener, err := net.Listen("tcp", ":443")
	if err != nil {
		log.Fatalf("Failed to listen on port 443: %v", err)
	}
	defer func(listener net.Listener) {
		if err := listener.Close(); err != nil {
			log.Printf("Failed to close listener: %v", err)
		}
	}(listener)
	logger.Println("Listening on port 443")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}
		logger.Printf("Accepted connection from %s\n\n", conn.RemoteAddr().String())

		go func(conn net.Conn) {
			defer func(conn net.Conn) {
				if err := conn.Close(); err != nil {
					logger.Printf("Failed to close connection: %v\n", err)
				}
			}(conn)
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
				if alert != nil {
					logger.Println("Sending an Alert record to the client")
					var key, iv []byte
					if handshakeFinished {
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
					if _, err = conn.Write(encryptedResponse.Bytes()); err != nil {
						logger.Printf("Failed to send data: %v\n", err)
					}
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
		return &internalErrorAlert
	}
	length := binary.BigEndian.Uint16(tlsHeaderBuffer[3:5])

	payloadBuffer := make([]byte, length)
	_, err = io.ReadFull(conn, payloadBuffer)
	if err != nil {
		logger.Printf("Error reading payload from connection: %v\n", err)
		return &internalErrorAlert
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
				return &internalErrorAlert
			}
			hasher := sha256.New
			logger.Printf("Selected curve: %s (%x)\n", NamedGroupName[keySharedEntry.Group], keySharedEntry.Group)

			clientECDHPublicKey := keySharedEntry.KeyExchangeData

			// ServerHello message
			ecdhServerPrivateKey, err := selectedCurve.GenerateKey(rand.Reader)
			if err != nil {
				logger.Println("Error in calculating ECDH private key")
				return &internalErrorAlert
			}
			logger.Printf("ECDH Server Private key:%x\n", ecdhServerPrivateKey.Bytes())
			logger.Printf("ECDH Server Public key:%x\n", ecdhServerPrivateKey.PublicKey().Bytes())
			serverHello, err := NewServerHello(ecdhServerPrivateKey.PublicKey(), keySharedEntry.Group, TLS_AES_128_GCM_SHA256, clientHello.LegacySessionID)
			if err != nil {
				logger.Println("Error constructing ServerHello message:", err)
				return &internalErrorAlert
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
			if _, err := conn.Write(serverHelloTLSRecord.Bytes()); err != nil {
				return &internalErrorAlert
			}

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
				return &internalErrorAlert
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
			if _, err = conn.Write(encryptedExtensionsTLSRecord.Bytes()); err != nil {
				return &internalErrorAlert
			}

			// Certificate message
			serverCert, err := tls.LoadX509KeyPair("server.crt", "server.key")
			if err != nil {
				logger.Println("Error in loading server certificate:", err)
				return &internalErrorAlert
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
				return &internalErrorAlert
			}
			logger.Printf("Certificate TLS Record: %x\n\n", certificateTLSRecord.Bytes())
			if _, err = conn.Write(certificateTLSRecord.Bytes()); err != nil {
				return &internalErrorAlert
			}

			// CertificateVerify message
			serverPriv, ok := serverCert.PrivateKey.(*ecdsa.PrivateKey)
			if !ok {
				logger.Println("Error in type assertion of server private key")
				return &internalErrorAlert
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
				return &internalErrorAlert
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
				return &internalErrorAlert
			}
			logger.Printf("CertificateVerify TLS Record: %x\n\n", certificateVerifyTLSRecord.Bytes())
			if _, err = conn.Write(certificateVerifyTLSRecord.Bytes()); err != nil {
				return &internalErrorAlert
			}

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
				return &internalErrorAlert
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
				return &internalErrorAlert
			}
			logger.Printf("Finished TLS Record: %x\n\n", finishedTLSRecord.Bytes())
			if _, err = conn.Write(finishedTLSRecord.Bytes()); err != nil {
				return &internalErrorAlert
			}

			// Store traffic secrets
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
		decryptedRecord, err := DecryptTLSInnerPlaintext(key, iv, tlsRecord.Fragment, sequence, tlsHeaderBuffer)
		if err != nil {
			logger.Println("Error in decrypting ApplicationData:", err)
			return &internalErrorAlert
		}
		logger.Printf("Length of decrypted data: %d\n", len(decryptedRecord))
		decryptedRecord = RemoveZeroPaddingFromTail(decryptedRecord)
		if len(decryptedRecord) == 0 {
			logger.Println("Error in decrypting ApplicationData")
			return &internalErrorAlert
		}
		tlsInnerPlainText := TLSInnerPlainText{
			Content:     decryptedRecord[:len(decryptedRecord)-1],
			contentType: ContentType(decryptedRecord[len(decryptedRecord)-1]),
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
					return &internalErrorAlert
				}
				if !bytes.Equal(clientSentFinishedMessage.VerifyData, serverCalculatedFinishedMessage.VerifyData) {
					logger.Println("Client Finished message does not match")
					return &internalErrorAlert
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
					return &internalErrorAlert
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
						return &internalErrorAlert
					}
					logger.Printf("Encrypted response: %x\n", encryptedResponse.Bytes())
					if _, err = conn.Write(encryptedResponse.Bytes()); err != nil {
						return &Alert{Level: warning, Description: close_notify}
					}
					logger.Println("Sent hello TLS1.3 response")
					seqNum.appKeyServerSeqNum++
				}
				return &Alert{Level: warning, Description: close_notify}
			}
			logger.Printf("Application buffer:\n%s\n", *applicationBuffer)
		case AlertRecord:
			// Return error to the client
			return &internalErrorAlert
		default:

		}
	default:
		logger.Println("Received unsupported message")
	}
	return nil
}
