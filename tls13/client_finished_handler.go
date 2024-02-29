package tls13

import (
	"bytes"
	"crypto/sha256"
	"log"
)

func handleFinished(
	handshakeLength uint32,
	finishedBytes []byte,
	prevTLSContext *TLSContext,
	logger *log.Logger,
) (*TLSContext, *Alert) {
	// 4 bytes offset by TLS Record ContentType and Length
	clientSentFinishedMessage := FinishedMessage{
		VerifyData: finishedBytes[4 : handshakeLength+4],
	}
	serverCalculatedFinishedMessage, err := NewFinishedMessage(
		sha256.New,
		prevTLSContext.TrafficSecrets.ClientHandshakeTrafficSecret,
		[][]byte{
			prevTLSContext.HandshakeClientHello,
			prevTLSContext.HandshakeServerHello,
			prevTLSContext.HandshakeEncryptedExtensions,
			prevTLSContext.HandshakeCertificate,
			prevTLSContext.HandshakeCertificateVerify,
			prevTLSContext.ServerFinished,
		},
	)
	if err != nil {
		logger.Println("Error in generating client finished message:", err)
		return prevTLSContext, &internalErrorAlert
	}
	// Finished message verification
	if !bytes.Equal(clientSentFinishedMessage.VerifyData, serverCalculatedFinishedMessage.VerifyData) {
		logger.Println("Client Finished message does not match")
		return prevTLSContext, &internalErrorAlert
	}
	logger.Printf("Client Finished Message: %x\n", clientSentFinishedMessage.Bytes())
	logger.Printf("Client Finished message matches. Connection established!\n\n")
	appTrafficSecrets, err := prevTLSContext.Secrets.ApplicationTrafficKeys(
		prevTLSContext.HandshakeClientHello,
		prevTLSContext.HandshakeServerHello,
		prevTLSContext.HandshakeEncryptedExtensions,
		prevTLSContext.HandshakeCertificate,
		prevTLSContext.HandshakeCertificateVerify,
		prevTLSContext.ServerFinished,
		16,
		12,
	)
	if err != nil {
		logger.Println("Error in deriving application traffic secrets:", err)
		return prevTLSContext, &internalErrorAlert
	}
	logger.Printf("Client Application Traffic Secret: %x\n", appTrafficSecrets.ClientApplicationTrafficSecret)
	logger.Printf("Server Application Traffic Secret: %x\n", appTrafficSecrets.ServerApplicationTrafficSecret)
	newTLSContext := prevTLSContext
	newTLSContext.ApplicationTrafficSecrets = *appTrafficSecrets
	return newTLSContext, nil
}
