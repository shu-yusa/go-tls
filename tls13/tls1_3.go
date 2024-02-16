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

	SupportedPointFormatsExtension struct {
		Length         uint8
		ECPointFormats []uint8
	}

	SupportedGroupExtension struct {
		Length         uint16
		NamedGroupList []uint16
	}

	SignatureAlgorithmsExtension struct {
		Length                       uint16
		SupportedSignatureAlgorithms []uint16
	}

	KeyShareEntry struct {
		Group           uint16
		Length          uint16
		KeyExchangeData []byte
	}

	KeyShareExtension struct {
		Length       uint16
		ClientShares []KeyShareEntry
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
	ServerNameExtensionType                 = 0
	StatusRequestExtensionType              = 5
	SupportedPointFormatsExtensionType      = 11
	SupportedGroupsExtensionType            = 10
	ApplicationLayerProtocolNegotiationType = 16
	SignedCertificateTimestampExtensionType = 18
	CompressCertificateExtensionType        = 27
	SessionTicketExtensionType              = 35
	EncryptThenMacExtensionType             = 22
	ExtendedMasterSecretExtensionType       = 23
	SignatureAlgorithmsExtensionType        = 13
	SupportedVersionsExtensionType          = 43
	PSKKeyExchangeModesExtensionType        = 45
	KeyShareExtensionType                   = 51
	EncryptedClientHelloExtensionType       = 65037
	RenegotiationInfoExtensionType          = 65281
)

var ExtensionName = map[ExtensionType]string{
	ServerNameExtensionType:                 "Server Name",
	StatusRequestExtensionType:              "Status Request",
	SupportedPointFormatsExtensionType:      "Supported Point Formats",
	SupportedGroupsExtensionType:            "Supported Groups",
	ApplicationLayerProtocolNegotiationType: "Application Layer Protocol Negotiation",
	SignedCertificateTimestampExtensionType: "Signed Certificate Timestamp",
	CompressCertificateExtensionType:        "Compress Certificate",
	SignatureAlgorithmsExtensionType:        "Signature Algorithms",
	SessionTicketExtensionType:              "Session Ticket",
	EncryptThenMacExtensionType:             "Encrypt-then-MAC",
	ExtendedMasterSecretExtensionType:       "Extended Master Secret",
	SupportedVersionsExtensionType:          "Supported Versions",
	PSKKeyExchangeModesExtensionType:        "PSK Key Exchange Modes",
	KeyShareExtensionType:                   "Key Share",
	EncryptedClientHelloExtensionType:       "Encrypted Client Hello",
	RenegotiationInfoExtensionType:          "Renegotiation Info",
}

var ECPointFormatName = map[uint8]string{
	0: "uncompressed",
	1: "ansiX962_compressed_prime",
	2: "ansiX962_compressed_char2",
}

var NamedGroupName = map[uint16]string{
	0x0017: "secp256r1",
	0x0018: "secp384r1",
	0x0019: "secp521r1",
	0x001d: "x25519",
	0x001e: "x448",
	0x0100: "ffdhe2048",
	0x0101: "ffdhe3072",
	0x0102: "ffdhe4096",
	0x0103: "ffdhe6144",
	0x0104: "ffdhe8192",
}

var SignatureAlgorithmName = map[uint16]string{
	0x0403: "ecdsa_secp256r1_sha256",
	0x0503: "ecdsa_secp384r1_sha384",
	0x0603: "ecdsa_secp521r1_sha512",
	0x0807: "ed25519",
	0x0808: "ed448",
	0x0809: "rsa_pss_pss_sha256",
	0x080a: "rsa_pss_pss_sha384",
	0x080b: "rsa_pss_pss_sha512",
	0x081a: "ecdsa_brainpoolP256r1tls13_sha256",
	0x081b: "ecdsa_brainpoolP384r1tls13_sha384",
	0x081c: "ecdsa_brainpoolP512r1tls13_sha512",
	0x0804: "rsa_pss_rsae_sha256",
	0x0805: "rsa_pss_rsae_sha384",
	0x0806: "rsa_pss_rsae_sha512",
	0x0401: "rsa_pkcs1_sha256",
	0x0501: "rsa_pkcs1_sha384",
	0x0601: "rsa_pkcs1_sha512",
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

			// https://tex2e.github.io/rfc-translater/html/rfc8422.html#5-1-2--Supported-Point-Formats-Extension Supported Point Formats Extension (Extension Type 11)
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
				fmt.Printf("Extension type: %s (%d)\n", ExtensionName[extension.Type], extension.Type)
				fmt.Printf("Extension length: %d\n", length)
				switch extension.Type {
				case SupportedPointFormatsExtensionType:
					length := uint8(extension.Data[0])
					var ECPointFormats []uint8
					for i := 0; i < int(length); i++ {
						ECPointFormat := uint8(extension.Data[1+i])
						ECPointFormats = append(ECPointFormats, ECPointFormat)
						fmt.Printf("  ECPointFormat: %s (%x)\n", ECPointFormatName[ECPointFormat], ECPointFormat)
					}
				case SupportedGroupsExtensionType:
					length := binary.BigEndian.Uint16(extension.Data[0:2])
					var NamedGroupList []uint16
					for i := 0; i < int(length); i += 2 {
						NamedGroup := binary.BigEndian.Uint16(extension.Data[2+i : 2+i+2])
						NamedGroupList = append(NamedGroupList, NamedGroup)
						fmt.Printf("  Named Group: %s (%x)\n", NamedGroupName[NamedGroup], NamedGroup)
					}
				case SignatureAlgorithmsExtensionType:
					length := binary.BigEndian.Uint16(extension.Data[0:2])
					fmt.Println("length signature algoriths extension", length)
					var signatureAlgorithms []uint16
					for i := 0; i < int(length); i += 2 {
						signatureAlgorithm := binary.BigEndian.Uint16(extension.Data[2+i : 2+i+2])
						signatureAlgorithms = append(signatureAlgorithms, signatureAlgorithm)
						fmt.Printf("  Signature algorithm: %s (%x)\n", SignatureAlgorithmName[signatureAlgorithm], signatureAlgorithm)
					}
				case KeyShareExtensionType:
					// 33 Extension Type = key share
					// 00 26 Extension Length = 38
					// 00 24 Key Share Entry Length = 36
					// 00 1d 00 20 74 f9 64-f7 c7 d9 8a 47 d0 2c ae 6c bb 9f 24 49 3c 85 59-ef 98 76 bc 8e 3d 1e f8 34 46 78 3e 5e
					length := binary.BigEndian.Uint16(extension.Data[0:2])
					fmt.Println("length key share extension", length)
					var clientShares []KeyShareEntry
					keyShareCursor := 2
					for keyShareCursor < int(length) {
						group := binary.BigEndian.Uint16(extension.Data[keyShareCursor : keyShareCursor+2])
						keyExchangeDataLength := binary.BigEndian.Uint16(extension.Data[keyShareCursor+2 : keyShareCursor+4])
						clientShare := KeyShareEntry{
							Group:           group,
							Length:          keyExchangeDataLength,
							KeyExchangeData: extension.Data[keyShareCursor+4 : keyShareCursor+4+int(keyExchangeDataLength)],
						}
						clientShares = append(clientShares, clientShare)
						fmt.Printf("  Group: %s (%x)\n", NamedGroupName[group], group)
						fmt.Printf("  Length: %d\n", keyExchangeDataLength)
						fmt.Printf("  KeyExchangeData: %x\n", clientShare.KeyExchangeData)
						keyShareCursor += 4 + int(keyExchangeDataLength)
					}

					// for cursor < extensionOffset+2+int(extensionLength) {
					// 	cursor += 6
					// 	group := binary.BigEndian.Uint16(extension.Data[cursor : cursor+2])
					// 	keyExchangeDataLength := binary.BigEndian.Uint16(clientHelloBuffer[cursor+2 : cursor+4])

					// 	keyExchangeData := clientHelloBuffer[cursor+4 : cursor+4+int(keyExchangeDataLength)]
					// 	clientShare := KeyShareEntry{
					// 		Group:           group,
					// 		KeyExchangeData: keyExchangeData,
					// 	}
					// 	clientShares = append(clientShares, clientShare)
					// 	fmt.Printf("  Group: %s (%x)\n", NamedGroupName[group], group)
					// 	fmt.Printf("  KeyExchangeData: %x\n", keyExchangeData)
					// 	cursor += 4 + int(keyExchangeDataLength)
					// }

				default:
					if length > 0 {
						fmt.Printf("Extension data: %x\n", clientHelloBuffer[cursor+4:cursor+4+int(length)])
					}
				}
				fmt.Println()
				cursor += 4 + int(length)
			}

		}
	}

	// クライアントに対して簡単な応答を送信
	response := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
	conn.Write([]byte(response))
}
