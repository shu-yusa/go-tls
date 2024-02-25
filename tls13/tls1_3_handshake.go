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
		trafficSecrets               TrafficSecrets
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
	internalErroAlert    = Alert{level: fatal, description: internal_error}
)

func Server() {
	listener, err := net.Listen("tcp", ":443")
	if err != nil {
		log.Fatalf("Failed to listen on port 443: %v", err)
	}
	defer listener.Close()
	fmt.Println("Listening on port 443")

	for {
		conn, err := listener.Accept()
		fmt.Printf("Accepted connection from %s\n\n", conn.RemoteAddr().String())
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
				alert := handleMessage(conn, tlsContext, &sequenceNumbers, &handshakeFinished, &applicationDataBuffer)
				fmt.Printf("Sequence numbers: %v\n", sequenceNumbers.appKeyServerSeqNum)
				if alert != nil {
					fmt.Println("Sending alert to the client")
					var key, iv []byte
					if tlsContext.applicationTrafficSecrets.serverWriteKey != nil {
						key = tlsContext.applicationTrafficSecrets.serverWriteKey
						iv = tlsContext.applicationTrafficSecrets.serverWriteIV
					} else {
						key = tlsContext.trafficSecrets.serverWriteKey
						iv = tlsContext.trafficSecrets.serverWriteIV
					}
					encryptedResponse, _ := NewTLSCipherMessageText(
						key,
						iv,
						TLSInnerPlainText{
							content:     alert.Bytes(),
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
	tlsContext *tlsContext,
	seqNum *sequenceNumbers,
	handshakeFinished *bool,
	applicationBuffer *[]byte,
) *Alert {
	// Read TLS record
	tlsHeaderBuffer := make([]byte, 5)
	_, err := conn.Read(tlsHeaderBuffer)
	if err != nil {
		fmt.Printf("Error in reading from connection: %v\n", err)
		return &internalErroAlert
	}
	length := binary.BigEndian.Uint16(tlsHeaderBuffer[3:5])

	payloadBuffer := make([]byte, length)
	_, err = io.ReadFull(conn, payloadBuffer)
	if err != nil {
		fmt.Printf("Error reading payload from connection: %v\n", err)
		return &internalErroAlert
	}

	tlsRecord := &TLSRecord{
		contentType:         ContentType(tlsHeaderBuffer[0]),
		legacyRecordVersion: ProtocolVersion(binary.BigEndian.Uint16(tlsHeaderBuffer[1:3])),
		length:              length,
		fragment:            payloadBuffer,
	}
	fmt.Printf("TLS Record payload: %x\n", payloadBuffer)

	switch tlsRecord.contentType {
	case HandshakeRecord: // 22 stands for Handshake record type
		fmt.Println("Received TLS Handshake message")
		fmt.Printf("Legacy version: %s (%x)\n", ProtocolVersionName[tlsRecord.legacyRecordVersion], tlsRecord.legacyRecordVersion)
		fmt.Printf("Record length: %d bytes\n", tlsRecord.length)

		msgType := HandshakeType(tlsRecord.fragment[0])
		// extract 3 bytes
		handshakeLength := (uint32(tlsRecord.fragment[1]) << 16) | (uint32(tlsRecord.fragment[2]) << 8) | uint32(tlsRecord.fragment[3])
		fmt.Println(fmt.Sprintf("Handshake msg_type: %d\n", msgType))
		switch msgType {
		case ClientHello: // 0x01
			fmt.Println("Received ClientHello message")
			fmt.Println("Handshake: ClientHello")
			fmt.Printf("Handshake message length: %d bytes\n", handshakeLength)
			fmt.Println()
			clientHello := NewClientHello(tlsRecord.fragment[4 : 4+handshakeLength])
			fmt.Printf("Legacy version: %s (%x)\n", ProtocolVersionName[clientHello.legacyVersion], clientHello.legacyVersion)
			fmt.Printf("Random: %x\n", clientHello.random)
			fmt.Printf("LegacySessionIDLength: %d\n", len(clientHello.legacySessionID))
			fmt.Printf("LegacySessionID: %x\n", clientHello.legacySessionID)
			fmt.Println("CipherSuites")
			for _, cipherSuite := range clientHello.cipherSuites {
				fmt.Printf("  CipherSuite: %s (%x)\n", CipherSuiteName[cipherSuite], cipherSuite)
			}
			fmt.Printf("LegacyCompressionMethodLength: %d\n", len(clientHello.legacyCompressionMethod))
			fmt.Printf("LegacyCompressionMethod: %x\n\n", clientHello.legacyCompressionMethod)

			fmt.Println("Extensions")
			extensions := clientHello.parseExtensions()
			fmt.Println()

			keyShareExtension := extensions[KeyShareExtensionType].(KeyShareExtension)

			keySharedEntry, selectedCurve := keyShareExtension.selectECDHKeyShare()
			if selectedCurve == nil {
				fmt.Println("Unsupported curve")
				return &internalErroAlert
			}
			hasher := sha256.New
			fmt.Printf("Selected curve: %s (%x)\n", NamedGroupName[keySharedEntry.group], keySharedEntry.group)

			clientECDHPublicKey := keySharedEntry.keyExchangeData

			// ServerHello message
			ecdhServerPrivateKey, err := selectedCurve.GenerateKey(rand.Reader)
			if err != nil {
				fmt.Println("Error in calculating ECDH private key")
				return &internalErroAlert
			}
			fmt.Printf("ECDH Server Private key:%x\n", ecdhServerPrivateKey.Bytes())
			fmt.Printf("ECDH Server Public key:%x\n", ecdhServerPrivateKey.PublicKey().Bytes())
			serverHello, err := NewServerHello(ecdhServerPrivateKey.PublicKey(), keySharedEntry.group, TLS_AES_128_GCM_SHA256, clientHello.legacySessionID)
			if err != nil {
				fmt.Println("Error constructing ServerHello message:", err)
				return &internalErroAlert
			}
			handshakeServerHello := Handshake[ServerHelloMessage]{
				msgType:          ServerHello,
				length:           uint32(len(serverHello.Bytes())),
				handshakeMessage: serverHello,
			}
			serverHelloTLSRecord := TLSRecord{
				contentType:         HandshakeRecord, // 0x16
				legacyRecordVersion: TLS12,           // 0x0303
				length:              uint16(len(handshakeServerHello.Bytes())),
				fragment:            handshakeServerHello.Bytes(),
			}
			fmt.Printf("ServerHello: %x\n\n", serverHelloTLSRecord.Bytes())
			conn.Write(serverHelloTLSRecord.Bytes())

			// // ChangeCipherSpec message
			// conn.Write(TLSPlainText{
			// 	contentType:         ChangeCipherSpecRecord, // 0x14
			// 	legacyRecordVersion: TLS12,                  // 0x0303
			// 	length:              1,
			// 	fragment:            []byte{1},
			// }.Bytes())

			secrets, err := generateSecrets(hasher, selectedCurve, clientECDHPublicKey, ecdhServerPrivateKey)
			if err != nil {
				fmt.Println("Error generating secrets:", err)
				return &internalErroAlert
			}
			fmt.Printf("Shared secret(pre-master secret): %x\n", secrets.sharedSecret)
			fmt.Printf("Early Secret: %x\n", secrets.earlySecret)
			fmt.Printf("Handshake Secret: %x\n", secrets.handshakeSecret)
			trafficSecrets, err := secrets.handshakeTrafficKeys(tlsRecord.fragment, serverHelloTLSRecord.fragment, 16, 12)
			if err != nil {
				fmt.Println("Error in deriving handshake keys:", err)
			}
			fmt.Printf("Server write key: %x\n", trafficSecrets.serverWriteKey)
			fmt.Printf("Server IV: %x\n\n", trafficSecrets.serverWriteIV)

			// EncryptedExtensions message
			encryptedExtensions := EncryptedExtensionsMessage{
				extensions: []Extension{},
			}
			handshakeEncryptedExtensions := Handshake[EncryptedExtensionsMessage]{
				msgType:          EncryptedExtensions,
				length:           uint32(len(encryptedExtensions.Bytes())),
				handshakeMessage: encryptedExtensions,
			}
			encryptedExtensionsTLSRecord, err := NewTLSCipherMessageText(
				trafficSecrets.serverWriteKey,
				trafficSecrets.serverWriteIV,
				TLSInnerPlainText{
					content:     handshakeEncryptedExtensions.Bytes(),
					contentType: HandshakeRecord,
				},
				0,
			)
			fmt.Printf("Encrypted EncryptedExtensions TLS Record: %x\n\n", encryptedExtensionsTLSRecord.Bytes())
			conn.Write(encryptedExtensionsTLSRecord.Bytes())

			// Certificate message
			serverCert, err := tls.LoadX509KeyPair("server.crt", "server.key")
			if err != nil {
				fmt.Println("Error in loading server certificate:", err)
				return &internalErroAlert
			}
			certificate := CertificateMessage{
				certificateRequestContext: []byte{},
				certificateList: []CertificateEntry{
					{
						certType: X509,
						certData: serverCert.Certificate[0],
					},
				},
			}
			handshakeCertificate := Handshake[CertificateMessage]{
				msgType:          Certificate,
				length:           uint32(len(certificate.Bytes())),
				handshakeMessage: certificate,
			}
			fmt.Printf("Certificate: %x\n", certificate.Bytes())
			fmt.Printf("Certificate Length: %d\n\n", len(certificate.Bytes()))
			certificateTLSRecord, err := NewTLSCipherMessageText(
				trafficSecrets.serverWriteKey,
				trafficSecrets.serverWriteIV,
				TLSInnerPlainText{
					content:     handshakeCertificate.Bytes(),
					contentType: HandshakeRecord,
				},
				1,
			)
			if err != nil {
				fmt.Println("Error in encrypting Certificate message:", err)
				return &internalErroAlert
			}
			fmt.Printf("Certificate TLS Record: %x\n\n", certificateTLSRecord.Bytes())
			conn.Write(certificateTLSRecord.Bytes())

			// CertificateVerify message
			serverPriv, ok := serverCert.PrivateKey.(*ecdsa.PrivateKey)
			if !ok {
				fmt.Println("Error in type assertion of server private key")
				return &internalErroAlert
			}
			signature, err := signCertificate(
				serverPriv,
				tlsRecord.fragment,                   // ClientHello
				serverHelloTLSRecord.fragment,        // ServerHello
				handshakeEncryptedExtensions.Bytes(), // EncryptedExtensions
				handshakeCertificate.Bytes(),         // Certificate
			)
			if err != nil {
				fmt.Println("Error in signing certificate:", err)
				return &internalErroAlert
			}
			fmt.Printf("length of signature: %d\n", len(signature))
			fmt.Printf("Signature: %x\n", signature)
			certificateVerifyMessage := CertificateVerifyMessage{
				algorithm: ecdsa_secp256r1_sha256,
				signature: signature,
			}
			handshakeCertificateVerify := Handshake[CertificateVerifyMessage]{
				msgType:          CertificateVerify,
				length:           uint32(len(certificateVerifyMessage.Bytes())),
				handshakeMessage: certificateVerifyMessage,
			}
			certificateVerifyTLSRecord, err := NewTLSCipherMessageText(
				trafficSecrets.serverWriteKey,
				trafficSecrets.serverWriteIV,
				TLSInnerPlainText{
					content:     handshakeCertificateVerify.Bytes(),
					contentType: HandshakeRecord,
				},
				2,
			)
			if err != nil {
				fmt.Println("Error in encrypting CertificateVerify message:", err)
				return &internalErroAlert
			}
			fmt.Printf("CertificateVerify TLS Record: %x\n\n", certificateVerifyTLSRecord.Bytes())
			conn.Write(certificateVerifyTLSRecord.Bytes())

			// Finished message
			finishedMessage, err := newFinishedMessage(
				hasher,
				trafficSecrets.serverHandshakeTrafficSecret,
				tlsRecord.fragment,                   // ClientHello
				serverHelloTLSRecord.fragment,        // ServerHello
				handshakeEncryptedExtensions.Bytes(), // EncryptedExtensions
				handshakeCertificate.Bytes(),         // Certificate
				handshakeCertificateVerify.Bytes(),   // CertificateVerify
			)
			handshakeFinished := Handshake[FinishedMessage]{
				msgType:          Finished,
				length:           uint32(len(finishedMessage.Bytes())),
				handshakeMessage: finishedMessage,
			}
			if err != nil {
				fmt.Println("Error in generating finished key:", err)
				return &internalErroAlert
			}
			finishedTLSRecord, err := NewTLSCipherMessageText(
				trafficSecrets.serverWriteKey,
				trafficSecrets.serverWriteIV,
				TLSInnerPlainText{
					content:     handshakeFinished.Bytes(),
					contentType: HandshakeRecord,
				},
				3,
			)
			if err != nil {
				fmt.Println("Error in encrypting Finished message:", err)
				return &internalErroAlert
			}
			fmt.Printf("Finished TLS Record: %x\n\n", finishedTLSRecord.Bytes())
			conn.Write(finishedTLSRecord.Bytes())

			// St[]byteore traffic secrets
			tlsContext.secrets = *secrets
			tlsContext.trafficSecrets = *trafficSecrets
			tlsContext.handshakeClientHello = tlsRecord.fragment
			tlsContext.handshakeServerHello = serverHelloTLSRecord.fragment
			tlsContext.handshakeEncryptedExtensions = handshakeEncryptedExtensions.Bytes()
			tlsContext.handshakeCertificate = handshakeCertificate.Bytes()
			tlsContext.handshakeCertificateVerify = handshakeCertificateVerify.Bytes()
			tlsContext.serverFinished = handshakeFinished.Bytes()
		}
	case ChangeCipherSpecRecord:
		fmt.Printf("Received TLS ChangeCipherSpec message. Ignored.\n\n")
	case ApplicationDataRecord: // 23 stands for ApplicationData record type
		fmt.Println("Received TLS ApplicationData message")
		fmt.Printf("Sequence number: %d\n", seqNum.appKeyClientSeqNum)

		var key, iv []byte
		var sequence uint64
		if *handshakeFinished {
			key = tlsContext.applicationTrafficSecrets.clientWriteKey
			iv = tlsContext.applicationTrafficSecrets.clientWriteIV
			sequence = seqNum.appKeyClientSeqNum
			seqNum.appKeyClientSeqNum++
		} else {
			key = tlsContext.trafficSecrets.clientWriteKey
			iv = tlsContext.trafficSecrets.clientWriteIV
			sequence = seqNum.handshakeKeySeqNum
			seqNum.handshakeKeySeqNum++
		}
		fmt.Printf("Key: %x\n", key)
		fmt.Printf("IV: %x\n", iv)
		decrypedRecord, err := decryptTLSInnerPlaintext(key, iv, tlsRecord.fragment, sequence, tlsHeaderBuffer)
		if err != nil {
			fmt.Println("Error in decrypting ApplicationData:", err)
			return &internalErroAlert
		}
		fmt.Printf("Length of decrypted data: %d\n", len(decrypedRecord))
		decrypedRecord = RemoveZeroPaddingFromTail(decrypedRecord)
		if len(decrypedRecord) == 0 {
			fmt.Println("Error in decrypting ApplicationData")
			return &internalErroAlert
		}
		tlsInnerPlainText := TLSInnerPlainText{
			content:     decrypedRecord[:len(decrypedRecord)-1],
			contentType: ContentType(decrypedRecord[len(decrypedRecord)-1]),
		}
		// get content type from the last byte
		fmt.Printf("Received Content type: %s (%d)\n", ContentTypeName[tlsInnerPlainText.contentType], tlsInnerPlainText.contentType)
		switch tlsInnerPlainText.contentType {
		case HandshakeRecord:
			fmt.Printf("Decrypted ApplicationData: %x\n", tlsInnerPlainText.content)
			msgType := HandshakeType(tlsInnerPlainText.content[0])
			fmt.Printf("Handshake msg_type: %d\n", msgType)
			// extract 3 bytes
			handshakeLength := (uint32(tlsInnerPlainText.content[1]) << 16) | (uint32(tlsInnerPlainText.content[2]) << 8) | uint32(tlsInnerPlainText.content[3])
			fmt.Printf("Handshake message length: %d bytes\n", handshakeLength)
			switch msgType {
			case Finished:
				clientSentFinishedMessage := FinishedMessage{
					verifyData: tlsInnerPlainText.content[4 : handshakeLength+4],
				}
				serverCalculatedFinishedMessage, err := newFinishedMessage(
					sha256.New,
					tlsContext.trafficSecrets.clientHandshakeTrafficSecret,
					tlsContext.handshakeClientHello,
					tlsContext.handshakeServerHello,
					tlsContext.handshakeEncryptedExtensions,
					tlsContext.handshakeCertificate,
					tlsContext.handshakeCertificateVerify,
					tlsContext.serverFinished,
				)
				if err != nil {
					fmt.Println("Error in generating client finished message:", err)
					return &internalErroAlert
				}
				if !bytes.Equal(clientSentFinishedMessage.verifyData, serverCalculatedFinishedMessage.verifyData) {
					fmt.Println("Client Finished message does not match")
					return &internalErroAlert
				}
				fmt.Printf("Client Finished Message: %x\n", clientSentFinishedMessage.Bytes())
				fmt.Printf("Client Finished message matches. Connection established!\n\n")
				*handshakeFinished = true
				applicationTrafficSecrets, err := tlsContext.secrets.applicationTrafficKeys(
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
					fmt.Println("Error in deriving application traffic secrets:", err)
					return &internalErroAlert
				}
				tlsContext.applicationTrafficSecrets = *applicationTrafficSecrets
			default:
				fmt.Println("Unhandled message")
			}
		case ApplicationDataRecord:
			fmt.Printf("Decrypted ApplicationData: %s\n", tlsInnerPlainText.content)
			*applicationBuffer = append(*applicationBuffer, tlsInnerPlainText.content...)
			requestMessage := string(*applicationBuffer)
			if strings.HasSuffix(requestMessage, "\r\n\r\n") {
				if strings.HasPrefix(requestMessage, acceptableGetRequest) {
					fmt.Println("Received HTTP GET request")
					response := "HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\nHello, TLS 1.3!\n"
					encryptedResponse, err := NewTLSCipherMessageText(
						tlsContext.applicationTrafficSecrets.serverWriteKey,
						tlsContext.applicationTrafficSecrets.serverWriteIV,
						TLSInnerPlainText{
							content:     []byte(response),
							contentType: ApplicationDataRecord,
						},
						seqNum.appKeyServerSeqNum,
					)
					if err != nil {
						fmt.Println("Error in encrypting response:", err)
						return &internalErroAlert
					}
					fmt.Printf("Encrypted response: %x\n", encryptedResponse.Bytes())
					conn.Write(encryptedResponse.Bytes())
					fmt.Println("Sent hello TLS1.3 response")
					seqNum.appKeyServerSeqNum++
				}
				return &Alert{level: warning, description: close_notify}
			}
			fmt.Printf("Application buffer:\n%s\n", *applicationBuffer)
		case AlertRecord:
			// Return error to the client
			return &internalErroAlert
		default:

		}
		// fmt.Printf("ServerHello: %x\n", handshakeResponse.Bytes())
		// conn.Write(handshakeResponse.Bytes())
	default:
		fmt.Println("Received some message")
	}

	// response := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
	// conn.Write([]byte(response))
	return nil
}
