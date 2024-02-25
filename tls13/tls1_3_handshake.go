package tls13

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
)

type (
	tlsContext struct {
		trafficSecrets               TrafficSecrets
		handshakeClientHello         []byte
		handshakeServerHello         []byte
		handshakeEncryptedExtensions []byte
		handshakeCertificate         []byte
		handshakeCertificateVerify   []byte
		serverFinished               []byte
	}
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
			for {
				handleMessage(conn, tlsContext)
			}
		}(conn)
	}
}

func handleMessage(conn net.Conn, tlsContext *tlsContext) {
	// Read TLS record
	tlsHeaderBuffer := make([]byte, 5)
	_, err := conn.Read(tlsHeaderBuffer)
	if err != nil {
		fmt.Printf("Error in reading from connection: %v\n", err)
		return
	}
	length := binary.BigEndian.Uint16(tlsHeaderBuffer[3:5])

	payloadBuffer := make([]byte, length)
	_, err = io.ReadFull(conn, payloadBuffer)
	if err != nil {
		fmt.Printf("Error reading payload from connection: %v\n", err)
		return
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

			// ServerHello message
			ecdhServerPrivateKey, err := ecdh.P256().GenerateKey(rand.Reader)
			if err != nil {
				fmt.Println("Error in calculating ECDH private key")
				return
			}
			fmt.Printf("ECDH Server Private key:%x\n", ecdhServerPrivateKey.Bytes())
			fmt.Printf("ECDH Server Public key:%x\n", ecdhServerPrivateKey.PublicKey().Bytes())
			serverHello, err := NewServerHello(ecdhServerPrivateKey.PublicKey(), secp256r1, TLS_AES_128_GCM_SHA256, clientHello.legacySessionID)
			if err != nil {
				fmt.Println("Error constructing ServerHello message:", err)
				return
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

			// // ChangeCipherSpec message, is this necessary?
			// conn.Write(TLSPlainText{
			// 	contentType:         ChangeCipherSpecRecord, // 0x14
			// 	legacyRecordVersion: TLS12,                  // 0x0303
			// 	length:              1,
			// 	fragment:            []byte{1},
			// }.Bytes())

			keyShareExtension := extensions[KeyShareExtensionType].(KeyShareExtension)
			clientECDHPublicKey := keyShareExtension.clientShares[0].keyExchangeData
			secrets, err := generateSecrets(sha256.New, ecdh.P256(), clientECDHPublicKey, ecdhServerPrivateKey)
			if err != nil {
				fmt.Println("Error generating secrets:", err)
				return
			}
			fmt.Printf("Shared secret(pre-master secret): %x\n", secrets.sharedSecret)
			fmt.Printf("Early Secret: %x\n", secrets.earlySecret)
			fmt.Printf("Handshake Secret: %x\n", secrets.handshakeSecret)
			trafficSecrets, err := secrets.trafficKeys(tlsRecord.fragment, serverHelloTLSRecord.fragment, 16, 12)
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
			encryptedExtensionsTLSRecord, err := NewTLSCipherMessageText(trafficSecrets, TLSInnerPlainText{
				content:     handshakeEncryptedExtensions.Bytes(),
				contentType: HandshakeRecord,
			}, 0)
			fmt.Printf("Encrypted EncryptedExtensions TLS Record: %x\n\n", encryptedExtensionsTLSRecord.Bytes())
			conn.Write(encryptedExtensionsTLSRecord.Bytes())

			// Certificate message
			serverCert, err := tls.LoadX509KeyPair("server.crt", "server.key")
			if err != nil {
				fmt.Println("Error in loading server certificate:", err)
				return
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
			certificateTLSRecord, err := NewTLSCipherMessageText(trafficSecrets, TLSInnerPlainText{
				content:     handshakeCertificate.Bytes(),
				contentType: HandshakeRecord,
			}, 1)
			if err != nil {
				fmt.Println("Error in encrypting Certificate message:", err)
				return
			}
			fmt.Printf("Certificate TLS Record: %x\n\n", certificateTLSRecord.Bytes())
			conn.Write(certificateTLSRecord.Bytes())

			// CertificateVerify message
			serverPriv, ok := serverCert.PrivateKey.(*ecdsa.PrivateKey)
			if !ok {
				fmt.Println("Error in type assertion of server private key")
				return
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
				return
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
			certificateVerifyTLSRecord, err := NewTLSCipherMessageText(trafficSecrets, TLSInnerPlainText{
				content:     handshakeCertificateVerify.Bytes(),
				contentType: HandshakeRecord,
			}, 2)
			if err != nil {
				fmt.Println("Error in encrypting CertificateVerify message:", err)
				return
			}
			fmt.Printf("CertificateVerify TLS Record: %x\n\n", certificateVerifyTLSRecord.Bytes())
			conn.Write(certificateVerifyTLSRecord.Bytes())

			// Finished message
			finishedMessage, err := newFinishedMessage(
				sha256.New,
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
				return
			}
			finishedTLSRecord, err := NewTLSCipherMessageText(trafficSecrets, TLSInnerPlainText{
				content:     handshakeFinished.Bytes(),
				contentType: HandshakeRecord,
			}, 3)
			if err != nil {
				fmt.Println("Error in encrypting Finished message:", err)
				return
			}
			fmt.Printf("Finished TLS Record: %x\n\n", finishedTLSRecord.Bytes())
			conn.Write(finishedTLSRecord.Bytes())

			// Store traffic secrets
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
		decrypedRecord, err := decryptTLSInnerPlaintext(tlsContext.trafficSecrets, tlsRecord.fragment, 0, tlsHeaderBuffer)
		if err != nil {
			fmt.Println("Error in decrypting ApplicationData:", err)
			return
		}
		fmt.Printf("Length of decrypted data: %d\n", len(decrypedRecord))
		decrypedRecord = RemoveZeroPaddingFromTail(decrypedRecord)
		if len(decrypedRecord) == 0 {
			fmt.Println("Error in decrypting ApplicationData")
			return
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
					verifyData: tlsInnerPlainText.content[4:],
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
					return
				}
				if !bytes.Equal(clientSentFinishedMessage.verifyData, serverCalculatedFinishedMessage.verifyData) {
					fmt.Println("Client Finished message does not match")
					return
				}
				fmt.Printf("Client Finished Message: %x\n", clientSentFinishedMessage.Bytes())
				fmt.Println("Client Finished message matches. Connection established!")
			default:
				fmt.Println("Unhandled message")
			}
		case ApplicationDataRecord:
		case AlertRecord:
		default:

		}
		// fmt.Printf("ServerHello: %x\n", handshakeResponse.Bytes())
		// conn.Write(handshakeResponse.Bytes())
	default:
		fmt.Println("Received some message")
	}

	// response := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
	// conn.Write([]byte(response))
}
