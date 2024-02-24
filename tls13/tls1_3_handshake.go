package tls13

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"log"
	"net"
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
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	fmt.Printf("Accepted connection from %s\n\n", conn.RemoteAddr().String())

	// Read TLS record
	tcpBuffer := make([]byte, 19*1024)
	n, err := conn.Read(tcpBuffer)
	if err != nil {
		fmt.Printf("Error in reading from connection: %v\n", err)
		return
	}
	if n <= 0 {
		fmt.Println("Received non-TLS message")
	}

	length := binary.BigEndian.Uint16(tcpBuffer[3:5])
	tlsRecord := &TLSPlainText{
		ContentType:         ContentType(tcpBuffer[0]),
		LegacyRecordVersion: ProtocolVersion(binary.BigEndian.Uint16(tcpBuffer[1:3])),
		Length:              length,
		Fragment:            tcpBuffer[5 : 5+length],
	}

	if tlsRecord.ContentType == HandshakeRecord { // 22 stands for Handshake record type
		fmt.Println("Received TLS Handshake message")
		fmt.Printf("Legacy version: %s (%x)\n", ProtocolVersionName[tlsRecord.LegacyRecordVersion], tlsRecord.LegacyRecordVersion)
		fmt.Printf("Record length: %d bytes\n", tlsRecord.Length)

		msgType := HandshakeType(tlsRecord.Fragment[0])
		// extract 3 bytes
		handshakeLength := (uint32(tlsRecord.Fragment[1]) << 16) | (uint32(tlsRecord.Fragment[2]) << 8) | uint32(tlsRecord.Fragment[3])
		fmt.Println(fmt.Sprintf("Handshake msg_type: %d\n", msgType))
		if msgType == ClientHello { // 0x01
			fmt.Println("Received ClientHello message")
			fmt.Println("Handshake: ClientHello")
			fmt.Printf("Handshake message length: %d bytes\n", handshakeLength)
			fmt.Println()
			clientHello := NewClientHello(tlsRecord.Fragment[4 : 4+handshakeLength])
			fmt.Printf("Legacy version: %s (%x)\n", ProtocolVersionName[clientHello.LegacyVersion], clientHello.LegacyVersion)
			fmt.Printf("Random: %x\n", clientHello.Random)
			fmt.Printf("LegacySessionIDLength: %d\n", len(clientHello.LegacySessionID))
			fmt.Printf("LegacySessionID: %x\n", clientHello.LegacySessionID)
			fmt.Println("CipherSuites")
			for _, cipherSuite := range clientHello.CipherSuites {
				fmt.Printf("  CipherSuite: %s (%x)\n", CipherSuiteName[cipherSuite], cipherSuite)
			}
			fmt.Printf("LegacyCompressionMethodLength: %d\n", len(clientHello.LegacyCompressionMethod))
			fmt.Printf("LegacyCompressionMethod: %x\n\n", clientHello.LegacyCompressionMethod)

			fmt.Println("Extensions")
			extensions := clientHello.parseExtensions()
			fmt.Println()

			// ServerHello message
			ecdhServerPrivateKey, err := ecdh.P256().GenerateKey(rand.Reader)
			if err != nil {
				fmt.Println("Error in calculating ECDH private key")
				return
			}
			serverHello, err := NewServerHello(ecdhServerPrivateKey.PublicKey(), secp256r1, TLS_AES_128_GCM_SHA256, clientHello.LegacySessionID)
			if err != nil {
				fmt.Println("Error constructing ServerHello message:", err)
				return
			}
			fmt.Printf("ECDH Server Private key:%x\n", ecdhServerPrivateKey.Bytes())
			fmt.Printf("ECDH Server Public key:%x\n", ecdhServerPrivateKey.PublicKey().Bytes())
			serverHelloHandshake := Handshake[ServerHelloMessage]{
				MsgType:          ServerHello,
				Length:           uint32(len(serverHello.Bytes())),
				HandshakeMessage: serverHello,
			}

			serverHelloTLSRecord := TLSPlainText{
				ContentType:         HandshakeRecord, // 0x16
				LegacyRecordVersion: TLS12,           // 0x0303
				Length:              uint16(len(serverHelloHandshake.Bytes())),
				Fragment:            serverHelloHandshake.Bytes(),
			}
			fmt.Printf("ServerHello: %x\n\n", serverHelloTLSRecord.Bytes())
			conn.Write(serverHelloTLSRecord.Bytes())

			// ChangeCipherSpec message, is this necessary?
			conn.Write(TLSPlainText{
				ContentType:         ChangeCipherSpecRecord, // 0x14
				LegacyRecordVersion: TLS12,                  // 0x0303
				Length:              1,
				Fragment:            []byte{1},
			}.Bytes())

			keyShareExtension := extensions[KeyShareExtensionType].(KeyShareExtension)
			clientECDHPublicKey := keyShareExtension.ClientShares[0].KeyExchangeData
			secrets, err := generateSecrets(sha256.New, ecdh.P256(), clientECDHPublicKey, ecdhServerPrivateKey)
			if err != nil {
				fmt.Println("Error generating secrets:", err)
				return
			}
			fmt.Printf("Shared secret(pre-master secret): %x\n", secrets.SharedSecret)
			fmt.Printf("Early Secret: %x\n", secrets.EarlySecret)
			fmt.Printf("Handshake Secret: %x\n", secrets.HandshakeSecret)
			serverWriteKey, serverWriteIV, err := secrets.HandshakeKeys(tlsRecord.Fragment, serverHelloTLSRecord.Fragment, 16, 12)
			if err != nil {
				fmt.Println("Error in deriving handshake keys:", err)
			}
			fmt.Printf("Server write key: %x\n", serverWriteKey)
			fmt.Printf("Server IV: %x\n\n", serverWriteIV)

			// EncryptedExtensions message
			encryptedExtensions := EncryptedExtensionsMessage{
				Extensions: []Extension{},
			}
			encryptedExtensionsHandshakeMessage := Handshake[EncryptedExtensionsMessage]{
				MsgType:          EncryptedExtensions,
				Length:           uint32(len(encryptedExtensions.Bytes())),
				HandshakeMessage: encryptedExtensions,
			}
			encryptedExtensionsTLSRecord, err := NewTLSCipherMessageText(serverWriteKey, serverWriteIV, TLSInnerPlainText{
				Content:     encryptedExtensionsHandshakeMessage.Bytes(),
				ContentType: HandshakeRecord,
			}, 0)
			fmt.Printf("Encrypted EncryptedExtensions TLS Record: %x\n\n", encryptedExtensionsTLSRecord.Bytes())
			conn.Write(encryptedExtensionsTLSRecord.Bytes())

			// Certificate message
			serverCert, err := tls.LoadX509KeyPair("server.crt", "server.key")
			if err != nil {
				fmt.Println("Error in loading server certificate:", err)
				return
			}
			certificateMessage := CertificateMessage{
				CertificateRequestContext: []byte{},
				CertificateList: []CertificateEntry{
					{
						CertType: X509,
						CertData: serverCert.Certificate[0],
					},
				},
			}
			certificateMessageHandshakeMessage := Handshake[CertificateMessage]{
				MsgType:          Certificate,
				Length:           uint32(len(certificateMessage.Bytes())),
				HandshakeMessage: certificateMessage,
			}
			fmt.Printf("Certificate: %x\n", certificateMessage.Bytes())
			fmt.Printf("Certificate Length: %d\n\n", len(certificateMessage.Bytes()))
			certificateTLSRecord, err := NewTLSCipherMessageText(serverWriteKey, serverWriteIV, TLSInnerPlainText{
				Content:     certificateMessageHandshakeMessage.Bytes(),
				ContentType: HandshakeRecord,
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
				tlsRecord.Fragment,                          // ClientHello
				serverHelloTLSRecord.Fragment,               // ServerHello
				encryptedExtensionsHandshakeMessage.Bytes(), // EncryptedExtensions
				certificateMessageHandshakeMessage.Bytes(),  // Certificate
			)
			if err != nil {
				fmt.Println("Error in signing certificate:", err)
				return
			}
			fmt.Printf("Signature: %x\n", signature)
			certificateVerifyMessage := CertificateVerifyMessage{
				algorithm: ecdsa_secp256r1_sha256,
				signature: signature,
			}

			certificateVerifyTLSRecord, err := NewTLSCipherMessageText(serverWriteKey, serverWriteIV, TLSInnerPlainText{
				Content: Handshake[CertificateVerifyMessage]{
					MsgType:          CertificateVerify,
					Length:           uint32(len(certificateVerifyMessage.Bytes())),
					HandshakeMessage: certificateVerifyMessage,
				}.Bytes(),
				ContentType: HandshakeRecord,
			}, 2)
			if err != nil {
				fmt.Println("Error in encrypting CertificateVerify message:", err)
				return
			}
			fmt.Printf("CertificateVerify TLS Record: %x\n\n", certificateVerifyTLSRecord.Bytes())
			conn.Write(certificateVerifyTLSRecord.Bytes())

			// TODO: implement Finished message
		}

		// fmt.Printf("ServerHello: %x\n", handshakeResponse.Bytes())
		// conn.Write(handshakeResponse.Bytes())
	}

	// response := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
	// conn.Write([]byte(response))
}
