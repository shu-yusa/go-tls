package tls13

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"log"
	"net"
)

func HandleClientHello(
	conn net.Conn,
	handshakeLength uint32,
	clientHelloBytes []byte,
	logger *log.Logger,
) (*TLSContext, *Alert) {
	// 4 bytes offset by TLS Record ContentType and Length
	clientHello := NewClientHello(clientHelloBytes[4 : 4+handshakeLength])
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
		return nil, &Alert{Level: fatal, Description: handshake_failure}
	}
	hasher := sha256.New
	logger.Printf("Selected curve: %s (%x)\n", NamedGroupName[keySharedEntry.Group], keySharedEntry.Group)

	clientECDHPublicKey := keySharedEntry.KeyExchangeData

	// ServerHello message
	ecdhServerPrivateKey, err := selectedCurve.GenerateKey(rand.Reader)
	if err != nil {
		logger.Println("Error in calculating ECDH private key")
		return nil, &internalErrorAlert
	}
	logger.Printf("ECDH Server Private key:%x\n", ecdhServerPrivateKey.Bytes())
	logger.Printf("ECDH Server Public key:%x\n", ecdhServerPrivateKey.PublicKey().Bytes())
	serverHello, err := NewServerHello(ecdhServerPrivateKey.PublicKey(), keySharedEntry.Group, TLS_AES_128_GCM_SHA256, clientHello.LegacySessionID)
	if err != nil {
		logger.Println("Error constructing ServerHello message:", err)
		return nil, &internalErrorAlert
	}
	handshakeServerHelloBytes := Handshake[ServerHelloMessage]{
		MsgType:          ServerHello,
		Length:           uint32(len(serverHello.Bytes())),
		HandshakeMessage: serverHello,
	}.Bytes()
	serverHelloTLSRecord := TLSRecord{
		ContentType:         HandshakeRecord, // 0x16
		LegacyRecordVersion: TLS12,           // 0x0303
		Length:              uint16(len(handshakeServerHelloBytes)),
		Fragment:            handshakeServerHelloBytes,
	}
	logger.Printf("ServerHello: %x\n", serverHelloTLSRecord.Bytes())
	if _, err := conn.Write(serverHelloTLSRecord.Bytes()); err != nil {
		return nil, &internalErrorAlert
	}
	logger.Printf("ServerHello sent\n\n")

	// // ChangeCipherSpec message
	// conn.Write(TLSPlainText{
	// 	contentType:         ChangeCipherSpecRecord, // 0x14
	// 	legacyRecordVersion: TLS12,                  // 0x0303
	// 	length:              1,
	// 	fragment:            []byte{1},
	// }.Bytes())

	logger.Printf("Key schedule\n")
	secrets, err := GenerateSecrets(hasher, selectedCurve, clientECDHPublicKey, ecdhServerPrivateKey)
	if err != nil {
		logger.Println("Error generating secrets:", err)
		return nil, &internalErrorAlert
	}
	logger.Printf("Shared secret(pre-master secret): %x\n", secrets.SharedSecret)
	logger.Printf("Early Secret: %x\n", secrets.EarlySecret)
	logger.Printf("Handshake Secret: %x\n", secrets.HandshakeSecret)
	logger.Printf("Master Secret: %x\n", secrets.MasterSecret)
	trafficSecrets, err := secrets.HandshakeTrafficKeys(clientHelloBytes, serverHelloTLSRecord.Fragment, 16, 12)
	if err != nil {
		logger.Println("Error in deriving handshake keys:", err)
	}
	logger.Printf("Client Handshake Traffic Secret: %x\n", trafficSecrets.ClientHandshakeTrafficSecret)
	logger.Printf("Server Handshake Traffic Secret: %x\n", trafficSecrets.ServerHandshakeTrafficSecret)
	logger.Printf("Server write key: %x\n", trafficSecrets.ServerWriteKey)
	logger.Printf("Server IV: %x\n", trafficSecrets.ServerWriteIV)
	logger.Printf("Client write key: %x\n", trafficSecrets.ClientWriteKey)
	logger.Printf("Client IV: %x\n\n", trafficSecrets.ClientWriteIV)

	// EncryptedExtensions message
	encryptedExtensionsMessage := EncryptedExtensionsMessage{
		Extensions: []Extension{},
	}
	handshakeEncryptedExtensions := Handshake[EncryptedExtensionsMessage]{
		MsgType:          EncryptedExtensions,
		Length:           uint32(len(encryptedExtensionsMessage.Bytes())),
		HandshakeMessage: encryptedExtensionsMessage,
	}
	logger.Printf("EncryptedExtensions: %x\n", encryptedExtensionsMessage.Bytes())
	logger.Printf("EncryptedExtensions Length: %d\n", len(encryptedExtensionsMessage.Bytes()))
	encryptedExtensionsTLSRecord, err := NewTLSCipherMessageText(
		trafficSecrets.ServerWriteKey,
		trafficSecrets.ServerWriteIV,
		TLSInnerPlainText{
			Content:     handshakeEncryptedExtensions.Bytes(),
			ContentType: HandshakeRecord,
		},
		0,
	)
	logger.Printf("Encrypted EncryptedExtensions TLS Record: %x\n", encryptedExtensionsTLSRecord.Bytes())
	if _, err = conn.Write(encryptedExtensionsTLSRecord.Bytes()); err != nil {
		return nil, &internalErrorAlert
	}
	logger.Printf("EncryptedExtensions sent\n\n")

	// Certificate message
	serverCert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		logger.Println("Error in loading server certificate:", err)
		return nil, &internalErrorAlert
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
	handshakeCertificate := Handshake[CertificateMessage]{
		MsgType:          Certificate,
		Length:           uint32(len(certificateMessage.Bytes())),
		HandshakeMessage: certificateMessage,
	}
	logger.Printf("Certificate: %x\n", certificateMessage.Bytes())
	logger.Printf("Certificate Length: %d\n", len(certificateMessage.Bytes()))
	certificateTLSRecord, err := NewTLSCipherMessageText(
		trafficSecrets.ServerWriteKey,
		trafficSecrets.ServerWriteIV,
		TLSInnerPlainText{
			Content:     handshakeCertificate.Bytes(),
			ContentType: HandshakeRecord,
		},
		1,
	)
	if err != nil {
		logger.Println("Error in encrypting Certificate message:", err)
		return nil, &internalErrorAlert
	}
	logger.Printf("Encrypted Certificate TLS Record: %x\n", certificateTLSRecord.Bytes())
	if _, err = conn.Write(certificateTLSRecord.Bytes()); err != nil {
		return nil, &internalErrorAlert
	}
	logger.Printf("Certificate sent\n\n")

	// CertificateVerify message
	signature, err := SignCertificate(
		hasher,
		serverCert.PrivateKey,
		[][]byte{
			clientHelloBytes,                     // ClientHello
			serverHelloTLSRecord.Fragment,        // ServerHello
			handshakeEncryptedExtensions.Bytes(), // EncryptedExtensions
			handshakeCertificate.Bytes(),         // Certificate
		},
	)
	if err != nil {
		logger.Println("Error in signing certificate:", err)
		return nil, &internalErrorAlert
	}
	logger.Printf("Signature: %x\n", signature)
	logger.Printf("Signature length: %d\n", len(signature))
	var algorithm SignatureScheme
	switch serverCert.PrivateKey.(type) {
	case ed25519.PrivateKey:
		algorithm = Ed25519
	case *ecdsa.PrivateKey:
		algorithm = ECDSA_SECP256R1_SHA256
	default:
		logger.Println("Unsupported signature algorithm")
		return nil, &Alert{Level: fatal, Description: handshake_failure}
	}
	// Check if client supports the signature algorithm
	if !extensions[SignatureAlgorithmsExtensionType].(SignatureAlgorithmsExtension).SupportsAlgorithm(algorithm) {
		logger.Printf("Client does not support the signature algorithm: %s", SignatureAlgorithmName[algorithm])
		return nil, &Alert{Level: fatal, Description: handshake_failure}
	}

	certificateVerifyMessage := CertificateVerifyMessage{
		Algorithm: algorithm,
		Signature: signature,
	}
	handshakeCertificateVerify := Handshake[CertificateVerifyMessage]{
		MsgType:          CertificateVerify,
		Length:           uint32(len(certificateVerifyMessage.Bytes())),
		HandshakeMessage: certificateVerifyMessage,
	}
	logger.Printf("CertificateVerify: %x\n", certificateVerifyMessage.Bytes())
	logger.Printf("CertificateVerify Length: %d\n", len(certificateVerifyMessage.Bytes()))
	certificateVerifyTLSRecord, err := NewTLSCipherMessageText(
		trafficSecrets.ServerWriteKey,
		trafficSecrets.ServerWriteIV,
		TLSInnerPlainText{
			Content:     handshakeCertificateVerify.Bytes(),
			ContentType: HandshakeRecord,
		},
		2,
	)
	if err != nil {
		logger.Println("Error in encrypting CertificateVerify message:", err)
		return nil, &internalErrorAlert
	}
	logger.Printf("Encrypted CertificateVerify TLS Record: %x\n", certificateVerifyTLSRecord.Bytes())
	if _, err = conn.Write(certificateVerifyTLSRecord.Bytes()); err != nil {
		return nil, &internalErrorAlert
	}
	logger.Printf("CertificateVerify sent\n\n")

	// Finished message
	finishedMessage, err := NewFinishedMessage(
		hasher,
		trafficSecrets.ServerHandshakeTrafficSecret,
		[][]byte{
			clientHelloBytes,                     // ClientHello
			serverHelloTLSRecord.Fragment,        // ServerHello
			handshakeEncryptedExtensions.Bytes(), // EncryptedExtensions
			handshakeCertificate.Bytes(),         // Certificate
			handshakeCertificateVerify.Bytes(),   // CertificateVerify
		},
	)
	handshakeFinished := Handshake[FinishedMessage]{
		MsgType:          Finished,
		Length:           uint32(len(finishedMessage.Bytes())),
		HandshakeMessage: finishedMessage,
	}
	if err != nil {
		logger.Println("Error in generating finished key:", err)
		return nil, &internalErrorAlert
	}
	logger.Printf("Finished: %x\n", finishedMessage.Bytes())
	logger.Printf("Finished Length: %d\n", len(finishedMessage.Bytes()))
	finishedTLSRecord, err := NewTLSCipherMessageText(
		trafficSecrets.ServerWriteKey,
		trafficSecrets.ServerWriteIV,
		TLSInnerPlainText{
			Content:     handshakeFinished.Bytes(),
			ContentType: HandshakeRecord,
		},
		3,
	)
	if err != nil {
		logger.Println("Error in encrypting Finished message:", err)
		return nil, &internalErrorAlert
	}
	logger.Printf("Encrypted Finished TLS Record: %x\n", finishedTLSRecord.Bytes())
	if _, err = conn.Write(finishedTLSRecord.Bytes()); err != nil {
		return nil, &internalErrorAlert
	}
	logger.Printf("Finished sent\n\n")

	// Store traffic secrets for subsequent messages
	return &TLSContext{
		Secrets:                      *secrets,
		TrafficSecrets:               *trafficSecrets,
		HandshakeClientHello:         clientHelloBytes,
		HandshakeServerHello:         serverHelloTLSRecord.Fragment,
		HandshakeEncryptedExtensions: handshakeEncryptedExtensions.Bytes(),
		HandshakeCertificate:         handshakeCertificate.Bytes(),
		HandshakeCertificateVerify:   handshakeCertificateVerify.Bytes(),
		ServerFinished:               handshakeFinished.Bytes(),
	}, nil
}
