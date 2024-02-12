package tls13

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
)

// ServerHelloMessage はServerHelloメッセージの構造を模倣します。
type (
	ContentType     uint8
	ProtocolVersion uint16
	HandShakeType   uint8
	ExtensionType   uint16

	ServerHelloMessage struct {
		ProtocolVersion   string
		RandomBytes       string
		SessionID         string // TLS 1.3では通常空
		CipherSuite       string
		CompressionMethod string
		Extensions        []string
	}
	TLSPlainText struct {
		TLSContentType      ContentType
		LegacyRecordVersion ProtocolVersion
		Length              uint16
		Fragment            []byte
	}
	HandShakeMessage[T any] struct {
		MsgType HandShakeType
		Length  uint32
		Message T
	}
	ClientHelloMessage struct {
		LegacyVersion           string
		Random                  string
		CipherSuite             string
		LegacyCompressionMethod string
		Extensions              []string
	}

	Extension struct {
		Type   ExtensionType
		Length uint16
		Data   []byte
	}
)

const (
	Invalid          ContentType = 0
	ChangeCipherSpec ContentType = 20
	Alert            ContentType = 21
	Handshake        ContentType = 22
	ApplicationData  ContentType = 23

	TLS10 ProtocolVersion = 0x0301
	TLS11 ProtocolVersion = 0x0302
	TLS12 ProtocolVersion = 0x0303
	TLS13 ProtocolVersion = 0x0304

	ClientHello HandShakeType = 1
	ServerHello HandShakeType = 2
	Certificate HandShakeType = 11
	Finished    HandShakeType = 20

	// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
	SupportedPointFormatsExtension = 11
	SupportedGroupsExtension       = 10
	SessionTicketExtension         = 35
	EncryptThenMacExtension        = 22
	ExtendedMasterSecretExtension  = 23
	SignatureAlgorithmsExtension   = 13
)

var ExtensionName = map[ExtensionType]string{
	SupportedPointFormatsExtension: "Supported Point Formats",
	SupportedGroupsExtension:       "Supported Groups",
	SignatureAlgorithmsExtension:   "Signature Algorithms",
	SessionTicketExtension:         "Session Ticket",
	EncryptThenMacExtension:        "Encrypt-then-MAC",
	ExtendedMasterSecretExtension:  "Extended Master Secret",
	SupportedVersionsExtension:     "Supported Versions",
	PSKKeyExchangeModesExtension:   "PSK Key Exchange Modes",
	KeyShareExtension:              "Key Share",
}

// NewServerHelloMessage は新しいServerHelloメッセージを生成します。
func NewServerHelloMessage() *ServerHelloMessage {
	return &ServerHelloMessage{
		ProtocolVersion:   "TLS 1.3",
		RandomBytes:       generateRandomBytes(32),
		SessionID:         "",
		CipherSuite:       "TLS_AES_128_GCM_SHA256",
		CompressionMethod: "null",
		Extensions:        []string{}, // ここに必要な拡張を追加
	}
}

// generateRandomBytes は指定された長さのランダムバイト列を生成します。
func generateRandomBytes(length int) string {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		panic("failed to generate random bytes")
	}
	return hex.EncodeToString(bytes)
}

// func main() {
// 	serverHello := NewServerHelloMessage()
// 	fmt.Printf("ServerHello: %+v\n", serverHello)
// }

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
	fmt.Printf("Accepted connection from %s\n", conn.RemoteAddr().String())

	// クライアントからのデータを読み取る簡単な例
	header := make([]byte, 19*1024) // 一般的なバッファサイズ
	n, err := conn.Read(header)
	if err != nil {
		fmt.Printf("Error reading from connection: %v\n", err)
		return
	}
	if n <= 0 {
		fmt.Println("Received non-TLS message")
	}

	length := binary.BigEndian.Uint16(header[3:5])
	tlsRecord := &TLSPlainText{
		TLSContentType:      ContentType(header[0]),
		LegacyRecordVersion: ProtocolVersion(binary.BigEndian.Uint16(header[1:3])),
		Length:              length,
		Fragment:            header[5 : 5+length],
	}

	if tlsRecord.TLSContentType == Handshake { // 22 stands for Handshake record type
		fmt.Println("Received TLS Handshake message")
		fmt.Printf("Legacy version: %x\n", tlsRecord.LegacyRecordVersion)
		fmt.Printf("Record length: %d bytes\n", tlsRecord.Length)

		// extract 3 bytes
		msgType := HandShakeType(tlsRecord.Fragment[0])
		handshakeLength := (uint32(tlsRecord.Fragment[1]) << 16) | (uint32(tlsRecord.Fragment[2]) << 8) | uint32(tlsRecord.Fragment[3])
		fmt.Println(fmt.Sprintf("Handshake msg_type: %d\n", msgType))
		if msgType == ClientHello { // 1 for ClientHello
			fmt.Println("Received ClientHello message")
			handShake := &HandShakeMessage[ClientHelloMessage]{
				MsgType: msgType,
				Length:  handshakeLength,
				Message: ClientHelloMessage{},
			}
			fmt.Println("Handshake: ClientHello")
			fmt.Printf("Handshake message length: %d bytes\n", handShake.Length)
			clientHelloBuffer := tlsRecord.Fragment[4 : 4+handShake.Length]
			legacyVersion := ProtocolVersion(binary.BigEndian.Uint16(clientHelloBuffer[0:2])) // 2 bytes
			fmt.Printf("Legacy version: %x\n", legacyVersion)
			fmt.Println(len(clientHelloBuffer))
			random := hex.EncodeToString(clientHelloBuffer[2:34]) // 32 bytes
			fmt.Printf("Random: %s\n", random)
			legacySessionIDLength := uint8(clientHelloBuffer[34]) // 1 byte
			fmt.Printf("LegacySessionIDLength: %d\n", legacySessionIDLength)
			legacySessionID := hex.EncodeToString(clientHelloBuffer[35 : 35+legacySessionIDLength])
			fmt.Printf("LegacySessionID: %s\n", legacySessionID)
			cipherSuiteLength := binary.BigEndian.Uint16(clientHelloBuffer[35+legacySessionIDLength : 35+legacySessionIDLength+2]) // 2 bytes
			fmt.Printf("CipherSuiteLength: %d\n", cipherSuiteLength)
			for i := 0; i < int(cipherSuiteLength); i += 2 {
				cipherSuite := binary.BigEndian.Uint16(clientHelloBuffer[35+int(legacySessionIDLength)+2+i : 35+int(legacySessionIDLength)+2+i+2])
				fmt.Printf("CipherSuite: %x\n", cipherSuite)
			}
			legacyCompressionMethodLength := uint8(clientHelloBuffer[35+int(legacySessionIDLength)+2+int(cipherSuiteLength)])
			fmt.Printf("LegacyCompressionMethodLength: %d\n", legacyCompressionMethodLength)
			legacyCompressionOffset := 35 + int(legacySessionIDLength) + 2 + int(cipherSuiteLength) + 1
			legacyCompressionMethod := clientHelloBuffer[legacyCompressionOffset : legacyCompressionOffset+int(legacyCompressionMethodLength)]
			fmt.Printf("LegacyCompressionMethod: %d\n", legacyCompressionMethod)
			extensionOffset := 35 + int(legacySessionIDLength) + 2 + int(cipherSuiteLength) + 1 + int(legacyCompressionMethodLength)
			extensionLength := binary.BigEndian.Uint16(clientHelloBuffer[extensionOffset : extensionOffset+2])
			fmt.Printf("ExtensionLength: %d\n", extensionLength)

			// https://tex2e.github.io/rfc-translater/html/rfc4492.html Supported Point Formats Extension (Extension Type 11)
			var extensions []Extension
			cursor := extensionOffset + 2
			for cursor < extensionOffset+2+int(extensionLength) {
				length := binary.BigEndian.Uint16(clientHelloBuffer[cursor+2 : cursor+4])
				extension := Extension{
					Type:   ExtensionType(binary.BigEndian.Uint16(clientHelloBuffer[cursor : cursor+2])),
					Length: length,
					Data:   clientHelloBuffer[cursor+4 : cursor+4+int(length)],
				}
				extensions = append(extensions, extension)
				// fmt.Printf("Extension type: %d\n", extension.Type)
				fmt.Printf("Extension type: %s (%d)\n", ExtensionName[extension.Type], extension.Type)
				fmt.Printf("Extension length: %d\n", length)
				fmt.Printf("Extension data: %x\n\n", clientHelloBuffer[cursor+4:cursor+4+int(length)])
				cursor += 4 + int(length)
			}

		}
	}

	// クライアントに対して簡単な応答を送信
	response := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
	conn.Write([]byte(response))
}
