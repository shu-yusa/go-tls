package tls13

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
)

type (
	// TLSContext holds secrets and handshake messages used over a connection
	TLSContext struct {
		Secrets                      Secrets
		TrafficSecrets               HandshakeTrafficSecrets
		ApplicationTrafficSecrets    ApplicationTrafficSecrets
		HandshakeClientHello         []byte
		HandshakeServerHello         []byte
		HandshakeEncryptedExtensions []byte
		HandshakeCertificate         []byte
		HandshakeCertificateVerify   []byte
		ServerFinished               []byte
	}

	// sequenceNumbers is a counter used in the calculation of AEAD nonce.
	// It is incremented for each record sent, and is reset to zero whenever the encryption key changes.
	sequenceNumbers struct {
		HandshakeKeySeqNum uint64
		AppKeyClientSeqNum uint64
		AppKeyServerSeqNum uint64
	}
)

func (c TLSContext) FinishedHandshake() bool {
	return c.ApplicationTrafficSecrets.ServerApplicationTrafficSecret != nil
}

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
			prevTLSContext := TLSContext{}
			sequenceNumbers := sequenceNumbers{
				HandshakeKeySeqNum: 0,
				AppKeyClientSeqNum: 0,
				AppKeyServerSeqNum: 0,
			}
			applicationDataBuffer := make([]byte, 0)
			for {
				newTLSContext, alert := handleMessage(conn, logger, &prevTLSContext, &sequenceNumbers, &applicationDataBuffer)
				if alert != nil {
					logger.Println("Sending Alert record to the client")
					var key, iv []byte
					var seqNum uint64
					if newTLSContext == nil {
						panic("Error before handshake is finished.")
					}
					if newTLSContext.FinishedHandshake() {
						key = newTLSContext.ApplicationTrafficSecrets.ServerWriteKey
						iv = newTLSContext.ApplicationTrafficSecrets.ServerWriteIV
						seqNum = sequenceNumbers.HandshakeKeySeqNum
					} else {
						key = newTLSContext.TrafficSecrets.ServerWriteKey
						iv = newTLSContext.TrafficSecrets.ServerWriteIV
						seqNum = sequenceNumbers.AppKeyServerSeqNum
					}
					encryptedResponse, _ := NewTLSCipherMessageText(
						key,
						iv,
						TLSInnerPlainText{
							Content:     alert.Bytes(),
							ContentType: AlertRecord,
						},
						seqNum,
					)
					if _, err = conn.Write(encryptedResponse.Bytes()); err != nil {
						logger.Printf("Failed to send data: %v\n", err)
					}
					break
				}
				prevTLSContext = *newTLSContext
			}
		}(conn)
	}
}

func handleMessage(
	conn net.Conn,
	logger *log.Logger,
	prevTLSContext *TLSContext,
	seqNum *sequenceNumbers,
	applicationBuffer *[]byte,
) (*TLSContext, *Alert) {
	// Read TLS record
	tlsHeaderBuffer := make([]byte, 5)
	_, err := conn.Read(tlsHeaderBuffer)
	if err != nil {
		logger.Printf("Error in reading from connection: %v\n", err)
		return prevTLSContext, &internalErrorAlert
	}
	length := binary.BigEndian.Uint16(tlsHeaderBuffer[3:5])

	payloadBuffer := make([]byte, length)
	_, err = io.ReadFull(conn, payloadBuffer)
	if err != nil {
		logger.Printf("Error reading payload from connection: %v\n", err)
		return prevTLSContext, &internalErrorAlert
	}

	tlsRecord := &TLSRecord{
		ContentType:         ContentType(tlsHeaderBuffer[0]),
		LegacyRecordVersion: ProtocolVersion(binary.BigEndian.Uint16(tlsHeaderBuffer[1:3])),
		Length:              length,
		Fragment:            payloadBuffer,
	}
	logger.Printf("----------- Received TLS Record ----------------")
	logger.Printf("Client TLS Record payload: %x\n", payloadBuffer)
	logger.Printf("Legacy version: %s (%x)\n", ProtocolVersionName[tlsRecord.LegacyRecordVersion], tlsRecord.LegacyRecordVersion)
	logger.Printf("Record length: %d\n\n", tlsRecord.Length)
	logger.Printf("Received TLS %s message (%x)\n", ContentTypeName[tlsRecord.ContentType], tlsRecord.ContentType)

	switch tlsRecord.ContentType {
	case HandshakeRecord: // 22 stands for Handshake record type
		msgType := HandshakeType(tlsRecord.Fragment[0])
		// extract 3 bytes
		handshakeLength := (uint32(tlsRecord.Fragment[1]) << 16) | (uint32(tlsRecord.Fragment[2]) << 8) | uint32(tlsRecord.Fragment[3])
		logger.Printf(fmt.Sprintf("Handshake Type: %s (%d)\n", HandshakeTypeName[msgType], msgType))
		logger.Printf("Handshake message length: %d\n", handshakeLength)
		switch msgType {
		case ClientHello: // 0x01
			return HandleClientHello(conn, handshakeLength, tlsRecord.Fragment, logger)
		}
	case ChangeCipherSpecRecord:
		logger.Printf("Ignored.\n")
	case ApplicationDataRecord: // 23 stands for ApplicationData record type (Wrapping data structure)
		var key, iv []byte
		var sequence uint64
		if prevTLSContext.FinishedHandshake() {
			key = prevTLSContext.ApplicationTrafficSecrets.ClientWriteKey
			iv = prevTLSContext.ApplicationTrafficSecrets.ClientWriteIV
			sequence = seqNum.AppKeyClientSeqNum
			seqNum.AppKeyClientSeqNum++
		} else {
			key = prevTLSContext.TrafficSecrets.ClientWriteKey
			iv = prevTLSContext.TrafficSecrets.ClientWriteIV
			sequence = seqNum.HandshakeKeySeqNum
			seqNum.HandshakeKeySeqNum++
		}
		logger.Printf("Key: %x\n", key)
		logger.Printf("IV: %x\n", iv)
		decryptedRecord, err := DecryptTLSInnerPlaintext(key, iv, tlsRecord.Fragment, sequence, tlsHeaderBuffer)
		if err != nil {
			logger.Println("Error in decrypting ApplicationData:", err)
			return prevTLSContext, &internalErrorAlert
		}
		logger.Printf("Length of decrypted data: %d\n", len(decryptedRecord))
		decryptedRecord = RemoveZeroPaddingFromTail(decryptedRecord)
		tlsInnerPlainText := TLSInnerPlainText{
			Content:     decryptedRecord[:len(decryptedRecord)-1],
			ContentType: ContentType(decryptedRecord[len(decryptedRecord)-1]),
		}
		// get content type from the last byte
		logger.Printf("Inner Content type: %s (%d)\n", ContentTypeName[tlsInnerPlainText.ContentType], tlsInnerPlainText.ContentType)
		switch tlsInnerPlainText.ContentType {
		case HandshakeRecord:
			logger.Printf("Decrypted ApplicationData: %x\n", tlsInnerPlainText.Content)
			msgType := HandshakeType(tlsInnerPlainText.Content[0])
			logger.Printf(fmt.Sprintf("Handshake Type: %s (%d)\n", HandshakeTypeName[msgType], msgType))
			// extract 3 bytes
			handshakeLength := (uint32(tlsInnerPlainText.Content[1]) << 16) | (uint32(tlsInnerPlainText.Content[2]) << 8) | uint32(tlsInnerPlainText.Content[3])
			logger.Printf("Handshake message length: %d bytes\n", handshakeLength)
			switch msgType {
			case Finished:
				return HandleFinished(handshakeLength, tlsInnerPlainText.Content, prevTLSContext, logger)
			default:
				logger.Println("Unhandled message")
			}
		case ApplicationDataRecord:
			if alert := HandleApplicationData(conn, tlsInnerPlainText, prevTLSContext, seqNum, applicationBuffer, logger); alert != nil {
				return prevTLSContext, alert
			}
		case AlertRecord:
			// Return error to the client
			logger.Printf("Received Alert: %x", tlsInnerPlainText.Content)
			return prevTLSContext, &internalErrorAlert
		default:
			logger.Println("Unsupported message")
		}
	default:
		logger.Println("Received unsupported message")
	}
	return prevTLSContext, nil
}
