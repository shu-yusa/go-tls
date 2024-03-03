package tls13

import (
	"io"
	"log"
	"testing"
)

func TestClientHello(t *testing.T) {
	mockConn := &MockConn{}
	tlsInnerPlainText := TLSInnerPlainText{
		Content:     []byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"),
		ContentType: ApplicationDataRecord,
	}
	seqNum := &sequenceNumbers{}
	applicationBuffer := make([]byte, 0)

	// Exercise SUT
	alert := HandleApplicationData(mockConn, tlsInnerPlainText, TestTLSContext, seqNum, &applicationBuffer, log.New(io.Discard, "", 0))

	// Verify result
	expectedAlert := &Alert{Level: warning, Description: close_notify}
	if *alert != *expectedAlert {
		t.Errorf("Expected close_notify alert to be returned")
	}

	response := mockConn.writeBuffer.Bytes()
	decryptedRecord, err := DecryptTLSInnerPlaintext(
		TestTLSContext.ApplicationTrafficSecrets.ServerWriteKey,
		TestTLSContext.ApplicationTrafficSecrets.ServerWriteIV,
		response[5:], // record fragment
		0,
		response[0:5], // record header
	)
	if err != nil {
		t.Errorf("Error in decrypting the response: %v", err)
	}

	decryptedTLSInnerPlainText := TLSInnerPlainText{
		Content:     decryptedRecord[:len(decryptedRecord)-1],
		ContentType: ContentType(decryptedRecord[len(decryptedRecord)-1]),
	}

	expectedResponse := "HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\nHello, TLS 1.3!\n"
	if string(decryptedTLSInnerPlainText.Content) != expectedResponse {
		t.Errorf("Expected response not written to conn.Write for a valid request")
	}
}
