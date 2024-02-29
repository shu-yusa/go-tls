package tls13

import (
	"log"
	"net"
	"strings"
)

func handleApplicationData(
	conn net.Conn,
	tlsInnerPlainText TLSInnerPlainText,
	prevTLSContext *TLSContext,
	seqNum *sequenceNumbers,
	applicationBuffer *[]byte,
	logger *log.Logger,
) *Alert {
	logger.Printf("Decrypted ApplicationData: \n%s\n", tlsInnerPlainText.Content)
	*applicationBuffer = append(*applicationBuffer, tlsInnerPlainText.Content...)
	requestMessage := string(*applicationBuffer)
	if strings.HasSuffix(requestMessage, "\r\n\r\n") {
		if strings.HasPrefix(requestMessage, acceptableGetRequest) {
			logger.Println("Received HTTP GET request")
			response := "HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\nHello, TLS 1.3!\n"
			encryptedResponse, err := NewTLSCipherMessageText(
				prevTLSContext.ApplicationTrafficSecrets.ServerWriteKey,
				prevTLSContext.ApplicationTrafficSecrets.ServerWriteIV,
				TLSInnerPlainText{
					Content:     []byte(response),
					ContentType: ApplicationDataRecord,
				},
				seqNum.AppKeyServerSeqNum,
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
			seqNum.AppKeyServerSeqNum++
		}
		logger.Printf("Send close_notify to client\n")
		return &Alert{Level: warning, Description: close_notify}
	}
	logger.Printf("Application buffer:\n%s\n", *applicationBuffer)
	return nil
}
