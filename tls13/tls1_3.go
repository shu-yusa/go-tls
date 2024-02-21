package tls13

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"log"
	"net"

	"golang.org/x/crypto/hkdf"
)

// ServerHelloMessage はServerHelloメッセージの構造を模倣します。
type (
	Serializable interface {
		ToBytes() []byte
	}

	ContentType     uint8
	ProtocolVersion uint16
	HandshakeType   uint8
	ExtensionType   uint16
	CertificateType uint8

	TLSPlainText struct {
		TLSContentType      ContentType
		LegacyRecordVersion ProtocolVersion
		Length              uint16
		Fragment            []byte
	}

	TLSCipherMessageText struct {
		ContentType     ContentType
		LegacyVersion   ProtocolVersion
		Length          uint16
		EncryptedRecord []byte
	}
	HandshakeMessage[T Serializable] struct {
		MsgType HandshakeType
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
	ServerHelloMessage struct {
		LegacyVersion     ProtocolVersion
		RandomBytes       [32]byte
		SessionID         []byte
		CipherSuite       uint16
		CompressionMethod uint8
		Extensions        []Extension
	}

	Extension struct {
		Type   ExtensionType
		Length uint16
		Data   []byte
	}

	SupportedVersionsExtension struct {
		SelectedVersion ProtocolVersion
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

	HKDFLabel struct {
		Length  uint16
		Label   string
		Context []byte
	}

	Secrets struct {
		Hash                           func() hash.Hash
		EarlySecret                    []byte
		HandshakeSecret                []byte
		MasterSecret                   []byte
		ClientHandshakeTrafficSecret   []byte
		ServerHandshakeTrafficSecret   []byte
		ClientApplicationTrafficSecret []byte
		ServerApplicationTrafficSecret []byte
	}

	CertificateEntry struct {
		CertType CertificateType
		CertData []byte
	}

	CertificateMessage struct {
		CertificateRequestContext []byte
		CertificateList           []CertificateEntry
	}
)

const (
	Invalid          ContentType = 0x00
	ChangeCipherSpec ContentType = 0x14
	Alert            ContentType = 0x15
	Handshake        ContentType = 0x16
	ApplicationData  ContentType = 0x17

	TLS10 ProtocolVersion = 0x0301
	TLS11 ProtocolVersion = 0x0302
	TLS12 ProtocolVersion = 0x0303
	TLS13 ProtocolVersion = 0x0304

	ClientHello       HandshakeType = 0x01
	ServerHello       HandshakeType = 0x02
	Certificate       HandshakeType = 0x0b
	CertificateVerify HandshakeType = 0x0f
	Finished          HandshakeType = 0x14

	X509         CertificateType = 0x01
	RawPublicKey CertificateType = 0x02

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

// https://tex2e.github.io/rfc-translater/html/rfc8422.html#6--Cipher-Suites
// https://tex2e.github.io/rfc-translater/html/rfc7905.html
// https://datatracker.ietf.org/doc/html/rfc5288
// https://tex2e.github.io/rfc-translater/html/rfc5246.html#A-5--The-Cipher-Suite
var CipherSuiteName = map[uint16]string{
	0x1301: "TLS_AES_128_GCM_SHA256",
	0x1302: "TLS_AES_256_GCM_SHA384",
	0x1303: "TLS_CHACHA20_POLY1305_SHA256",
	0x1304: "TLS_AES_128_CCM_SHA256",
	0x1305: "TLS_AES_128_CCM_8_SHA256",
	0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	0xc013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	0xc014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256",
	0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384",

	0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
	0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",

	0xcca8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	0xcca9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
}

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

func NewTLSCipherMessageText(encryptedRecord []byte) *TLSCipherMessageText {
	return &TLSCipherMessageText{
		ContentType:     ApplicationData,
		LegacyVersion:   TLS12,
		Length:          uint16(len(encryptedRecord)),
		EncryptedRecord: encryptedRecord,
	}
}

func (t TLSCipherMessageText) ToBytes() []byte {
	return append([]byte{
		byte(uint8(t.ContentType)),
		byte(uint8(t.LegacyVersion >> 8)),
		byte(uint8(t.LegacyVersion)),
		byte(uint8(t.Length >> 8)),
		byte(uint8(t.Length)),
	}, t.EncryptedRecord...)
}

func (t TLSPlainText) ToBytes() []byte {
	return append([]byte{
		byte(uint8(t.TLSContentType)),
		byte(uint8(t.LegacyRecordVersion >> 8)),
		byte(uint8(t.LegacyRecordVersion)),
		byte(uint8(t.Length >> 8)),
		byte(uint8(t.Length)),
	}, t.Fragment...)
}

func (ch ClientHelloMessage) ToBytes() []byte {
	return []byte{}
}

func (sh ServerHelloMessage) ToBytes() []byte {
	serverHello := []byte{}
	serverHello = append(serverHello, byte(uint8(sh.LegacyVersion>>8)))
	serverHello = append(serverHello, byte(uint8(sh.LegacyVersion)))
	serverHello = append(serverHello, sh.RandomBytes[:]...)
	serverHello = append(serverHello, byte(uint8(len(sh.SessionID))))
	serverHello = append(serverHello, sh.SessionID...)
	serverHello = append(serverHello, byte(uint8(sh.CipherSuite>>8)))
	serverHello = append(serverHello, byte(uint8(sh.CipherSuite)))
	serverHello = append(serverHello, sh.CompressionMethod)

	// length as uint16
	extensionLength := 0
	for _, extension := range sh.Extensions {
		extensionLength += 4 + int(extension.Length)
	}

	serverHello = append(serverHello, byte(uint8(extensionLength>>8)))
	serverHello = append(serverHello, byte(uint8(extensionLength)))
	for _, extension := range sh.Extensions {
		serverHello = append(serverHello, extension.ToBytes()...)
	}
	return serverHello
}

func (hs HandshakeMessage[T]) ToBytes() []byte {
	handshake := []byte{}
	handshake = append(handshake, byte(uint8(hs.MsgType)))
	handshake = append(handshake, byte(uint8(hs.Length>>16)))
	handshake = append(handshake, byte(uint8(hs.Length>>8)))
	handshake = append(handshake, byte(uint8(hs.Length)))
	handshake = append(handshake, hs.Message.ToBytes()...)
	return handshake
}

func (e Extension) ToBytes() []byte {
	extension := []byte{}
	extension = append(extension, byte(uint8(e.Type>>8)))
	extension = append(extension, byte(uint8(e.Type)))
	extension = append(extension, byte(uint8(e.Length>>8)))
	extension = append(extension, byte(uint8(e.Length)))
	extension = append(extension, e.Data...)
	return extension
}

func (kse KeyShareExtension) ToBytes() []byte {
	extension := []byte{}
	for _, clientShare := range kse.ClientShares {
		extension = append(extension, byte(uint8(clientShare.Group>>8)))
		extension = append(extension, byte(uint8(clientShare.Group)))
		extension = append(extension, byte(uint8(clientShare.Length>>8)))
		extension = append(extension, byte(uint8(clientShare.Length)))
		extension = append(extension, clientShare.KeyExchangeData...)
	}
	return extension
}

func (l HKDFLabel) ToBytes() []byte {
	label := []byte{}
	label = append(label, byte(uint8(l.Length>>8)))
	label = append(label, byte(uint8(l.Length)))
	// "tls13 "プレフィックスとLabelを連結し、バイトに変換
	labelBytes := []byte("tls13 " + l.Label)
	// Labelの長さを先頭に追加
	label = append(label, byte(len(labelBytes)))
	label = append(label, labelBytes...)

	// Contextをバイトに変換
	contextBytes := []byte(l.Context)
	// Contextの長さを先頭に追加
	label = append(label, byte(len(contextBytes)))
	label = append(label, contextBytes...)
	return label
}

func (s *Secrets) HandshakeKeys(clientHello []byte, serverHello []byte, keyLength int, ivLength int) ([]byte, []byte, error) {
	messages := sha256.Sum256(append(clientHello, serverHello...))
	hkdfExpand := hkdf.Expand(s.Hash, s.HandshakeSecret, HKDFLabel{
		Length:  32,
		Label:   "c hs traffic",
		Context: messages[:],
	}.ToBytes())

	clientHandshakeTrafficSecret := make([]byte, 32)
	_, err := hkdfExpand.Read(clientHandshakeTrafficSecret)
	if err != nil {
		return nil, nil, err
	}

	hkdfExpand = hkdf.Expand(s.Hash, s.HandshakeSecret, HKDFLabel{
		Length:  32,
		Label:   "s hs traffic",
		Context: messages[:],
	}.ToBytes())

	serverHandshakeTrafficSecret := make([]byte, 32)
	if _, err := hkdfExpand.Read(serverHandshakeTrafficSecret); err != nil {
		return nil, nil, err
	}
	fmt.Printf("Server Handshake Traffic Secret: %x\n", serverHandshakeTrafficSecret)

	hkdfExpand = hkdf.Expand(s.Hash, serverHandshakeTrafficSecret, HKDFLabel{
		Length:  uint16(keyLength),
		Label:   "key",
		Context: []byte{},
	}.ToBytes())
	serverWriteKey := make([]byte, keyLength)
	if _, err := hkdfExpand.Read(serverWriteKey); err != nil {
		return nil, nil, err
	}
	hkdfExpand = hkdf.Expand(s.Hash, serverHandshakeTrafficSecret, HKDFLabel{
		Length:  uint16(ivLength),
		Label:   "iv",
		Context: []byte{},
	}.ToBytes())
	serverWriteIV := make([]byte, ivLength)
	if _, err := hkdfExpand.Read(serverWriteIV); err != nil {
		return nil, nil, err
	}
	return serverWriteKey, serverWriteIV, nil
}

func (ce CertificateEntry) ToBytes() []byte {
	certEntry := []byte{}
	// 証明書データの長さを3バイトで表現
	length := len(ce.CertData)
	certEntry = append(certEntry, byte(length>>16), byte(length>>8), byte(length))
	certEntry = append(certEntry, ce.CertData...)
	certEntry = append(certEntry, 0, 0) // extensions
	return certEntry
}

func (c CertificateMessage) ToBytes() []byte {
	cert := []byte{}
	// 証明書リクエストコンテキストの長さを1バイトで表現
	cert = append(cert, byte(len(c.CertificateRequestContext)))
	cert = append(cert, c.CertificateRequestContext...)
	// 証明書リストの長さを3バイトで表現
	length := 0
	for _, entry := range c.CertificateList {
		length += 3 + len(entry.CertData)
	}
	cert = append(cert, byte(length>>16), byte(length>>8), byte(length))
	for _, entry := range c.CertificateList {
		cert = append(cert, entry.ToBytes()...)
	}
	return cert
}

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

	var handshakeResponse TLSPlainText
	if tlsRecord.TLSContentType == Handshake { // 22 stands for Handshake record type
		var clientECDHPublicKey []byte
		fmt.Println("Received TLS Handshake message")
		fmt.Printf("Legacy version: %x\n", tlsRecord.LegacyRecordVersion)
		fmt.Printf("Record length: %d bytes\n", tlsRecord.Length)

		// extract 3 bytes
		msgType := HandshakeType(tlsRecord.Fragment[0])
		handshakeLength := (uint32(tlsRecord.Fragment[1]) << 16) | (uint32(tlsRecord.Fragment[2]) << 8) | uint32(tlsRecord.Fragment[3])
		fmt.Println(fmt.Sprintf("Handshake msg_type: %d\n", msgType))
		if msgType == ClientHello { // 1 for ClientHello
			fmt.Println("Received ClientHello message")
			handshake := &HandshakeMessage[ClientHelloMessage]{
				MsgType: msgType,
				Length:  handshakeLength,
				Message: ClientHelloMessage{},
			}
			fmt.Println("Handshake: ClientHello")
			fmt.Printf("Handshake message length: %d bytes\n", handshake.Length)
			clientHelloBuffer := tlsRecord.Fragment[4 : 4+handshake.Length]
			legacyVersion := ProtocolVersion(binary.BigEndian.Uint16(clientHelloBuffer[0:2])) // 2 bytes
			fmt.Printf("Legacy version: %x\n", legacyVersion)
			random := hex.EncodeToString(clientHelloBuffer[2:34]) // 32 bytes
			fmt.Printf("Random: %s\n", random)
			legacySessionIDLength := uint8(clientHelloBuffer[34]) // 1 byte
			fmt.Printf("LegacySessionIDLength: %d\n", legacySessionIDLength)
			legacySessionID := clientHelloBuffer[35 : 35+legacySessionIDLength]
			fmt.Printf("LegacySessionID: %x\n", legacySessionID)
			cipherSuiteLength := binary.BigEndian.Uint16(clientHelloBuffer[35+legacySessionIDLength : 35+legacySessionIDLength+2]) // 2 bytes
			fmt.Printf("CipherSuiteLength: %d\n", cipherSuiteLength)
			for i := 0; i < int(cipherSuiteLength); i += 2 {
				cipherSuite := binary.BigEndian.Uint16(clientHelloBuffer[35+int(legacySessionIDLength)+2+i : 35+int(legacySessionIDLength)+2+i+2])
				fmt.Printf("  CipherSuite: %s (%x)\n", CipherSuiteName[cipherSuite], cipherSuite)
			}
			legacyCompressionMethodLength := uint8(clientHelloBuffer[35+int(legacySessionIDLength)+2+int(cipherSuiteLength)])
			fmt.Printf("LegacyCompressionMethodLength: %d\n", legacyCompressionMethodLength)
			legacyCompressionOffset := 35 + int(legacySessionIDLength) + 2 + int(cipherSuiteLength) + 1
			legacyCompressionMethod := clientHelloBuffer[legacyCompressionOffset : legacyCompressionOffset+int(legacyCompressionMethodLength)]
			fmt.Printf("LegacyCompressionMethod: %d\n", legacyCompressionMethod)
			extensionOffset := 35 + int(legacySessionIDLength) + 2 + int(cipherSuiteLength) + 1 + int(legacyCompressionMethodLength)
			extensionLength := binary.BigEndian.Uint16(clientHelloBuffer[extensionOffset : extensionOffset+2])
			fmt.Println()
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
					fmt.Println("Signature algoriths extension length:", length)
					var signatureAlgorithms []uint16
					for i := 0; i < int(length); i += 2 {
						signatureAlgorithm := binary.BigEndian.Uint16(extension.Data[2+i : 2+i+2])
						signatureAlgorithms = append(signatureAlgorithms, signatureAlgorithm)
						fmt.Printf("  Signature algorithm: %s (%x)\n", SignatureAlgorithmName[signatureAlgorithm], signatureAlgorithm)
					}
				case KeyShareExtensionType:
					length := binary.BigEndian.Uint16(extension.Data[0:2])
					fmt.Println("Key share extension length:", length)
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
						clientECDHPublicKey = clientShare.KeyExchangeData
						keyShareCursor += 4 + int(keyExchangeDataLength)
					}
				default:
					if length > 0 {
						fmt.Printf("Extension data: %x\n", clientHelloBuffer[cursor+4:cursor+4+int(length)])
					}
				}
				fmt.Println()
				cursor += 4 + int(length)
			}
			// TLS_AES_128_GCM_SHA256, secp256r1
			ecdhServerPrivateKey, serverHello, err := constructServerHello(ecdh.P256(), 0x0017, 0x1301, legacySessionID)
			if err != nil {
				fmt.Println("Error constructing ServerHello message:", err)
				return
			}
			serverHelloHandshake := HandshakeMessage[ServerHelloMessage]{
				MsgType: ServerHello,
				Length:  uint32(len(serverHello.ToBytes())),
				Message: *serverHello,
			}

			handshakeResponse = TLSPlainText{
				TLSContentType:      Handshake, // 0x16
				LegacyRecordVersion: TLS12,     // 0x0303
				Length:              uint16(len(serverHelloHandshake.ToBytes())),
				Fragment:            serverHelloHandshake.ToBytes(),
			}
			fmt.Printf("ServerHello: %x\n\n", handshakeResponse.ToBytes())
			conn.Write(handshakeResponse.ToBytes())

			secrets, err := generateSecrets(ecdh.P256(), clientECDHPublicKey, ecdhServerPrivateKey)
			if err != nil {
				fmt.Println("Error generating secrets:", err)
				return
			}
			serverWriteKey, serverWriteIV, err := secrets.HandshakeKeys(tlsRecord.Fragment, handshakeResponse.Fragment, 16, 12)
			fmt.Printf("Server write key: %x\n", serverWriteKey)
			fmt.Printf("Server IV: %x\n\n", serverWriteIV)
			//
			certificateMessage, err := constructCertificate()
			if err != nil {
				fmt.Println("Error constructing certificate:", err)
				return
			}
			fmt.Printf("Certificate: %x\n\n", certificateMessage.ToBytes())
			// TODO: Encrypt the certificate to construct Certificate message
			// AES_128_GCMで暗号化
			encryptedHandshakeCertificateMessage, err := encryptCertificateMessage(serverWriteKey, serverWriteIV, HandshakeMessage[CertificateMessage]{
				MsgType: Certificate,
				Length:  uint32(len(certificateMessage.ToBytes())),
				Message: *certificateMessage,
			}.ToBytes())
			if err != nil {
				fmt.Println("Error encrypting message:", err)
				return
			}

			fmt.Printf("Encrypted Message: %x\n\n", encryptedHandshakeCertificateMessage)

			certificateTLSRecord := NewTLSCipherMessageText(encryptedHandshakeCertificateMessage)
			fmt.Printf("Certificate TLS Record: %x\n\n", certificateTLSRecord.ToBytes())
			conn.Write(certificateTLSRecord.ToBytes())
		}

		// fmt.Printf("ServerHello: %x\n", handshakeResponse.ToBytes())
		// conn.Write(handshakeResponse.ToBytes())
	}

	// クライアントに対して簡単な応答を送信
	// response := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
	// conn.Write([]byte(response))
}

func generateSecrets(curve ecdh.Curve, clientPublicKeyBytes []byte, serverPrivateKey *ecdh.PrivateKey) (*Secrets, error) {
	// Pre-master Secret
	clientPublicKey, err := curve.NewPublicKey(clientPublicKeyBytes)
	if err != nil {
		return nil, err
	}
	sharedSecret, err := serverPrivateKey.ECDH(clientPublicKey)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Shared secret(pre-master secret): %x\n", sharedSecret)

	// Early Secret
	hash := sha256.New
	earlySecret := hkdf.Extract(hash, []byte{}, make([]byte, hash().Size()))
	fmt.Printf("Early Secret: %x\n", earlySecret)

	hkdfExpand := hkdf.Expand(sha256.New, earlySecret, HKDFLabel{
		Length:  32,
		Label:   "derived",
		Context: []byte{},
	}.ToBytes())
	secretState := make([]byte, 32)
	_, err = io.ReadFull(hkdfExpand, secretState)
	if err != nil {
		return nil, err
	}
	// fmt.Printf("Secret state: %x\n", secretState)

	// Handshake Secret
	handshakeSecret := hkdf.Extract(sha256.New, sharedSecret, secretState)
	fmt.Printf("Handshake Secret: %x\n", handshakeSecret)

	hkdfExpand = hkdf.Expand(sha256.New, handshakeSecret, HKDFLabel{
		Length:  32,
		Label:   "derived",
		Context: []byte{},
	}.ToBytes())
	secretState = make([]byte, 32)
	_, err = io.ReadFull(hkdfExpand, secretState)
	if err != nil {
		return nil, err
	}
	// fmt.Printf("Secret state: %x\n", secretState)

	// Derive Master Secret
	masterSecret := hkdf.Extract(sha256.New, []byte{}, secretState)
	fmt.Printf("Master Secret: %x\n", masterSecret)
	return &Secrets{
		Hash:            hash,
		EarlySecret:     earlySecret,
		HandshakeSecret: handshakeSecret,
		MasterSecret:    masterSecret,
	}, nil
}

func encryptCertificateMessage(key, iv, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := iv // GCMモードではnonceとしてIVを使用
	encrypted := aesgcm.Seal(nil, nonce, plaintext, nil)
	return encrypted, nil
}

func constructCertificate() (*CertificateMessage, error) {
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		return nil, err
	}
	certificateEntry := CertificateEntry{
		CertType: X509,
		CertData: cert.Certificate[0],
	}

	return &CertificateMessage{
		CertificateRequestContext: []byte{},
		CertificateList:           []CertificateEntry{certificateEntry},
	}, nil
}

func constructServerHello(curve ecdh.Curve, namedGroup uint16, cipherSuite uint16, sessionID []byte) (*ecdh.PrivateKey, *ServerHelloMessage, error) {
	// ランダムデータの生成 (32バイト)
	randomData := make([]byte, 32)
	_, err := rand.Read(randomData)
	if err != nil {
		return nil, nil, err
	}

	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	privateKey.PublicKey()
	fmt.Printf("Private key:%x\n", privateKey.Bytes())
	fmt.Printf("Public key:%x\n", privateKey.PublicKey().Bytes())

	keyShareExtension := KeyShareExtension{
		Length: 2 + 2 + uint16(len(privateKey.PublicKey().Bytes())),
		ClientShares: []KeyShareEntry{
			{
				Group:           namedGroup,
				Length:          uint16(len(privateKey.PublicKey().Bytes())),
				KeyExchangeData: privateKey.PublicKey().Bytes(),
			},
		},
	}

	return privateKey, &ServerHelloMessage{
		LegacyVersion:     TLS12,
		RandomBytes:       [32]byte(randomData),
		SessionID:         sessionID,
		CipherSuite:       cipherSuite,
		CompressionMethod: 0x00,
		Extensions: []Extension{
			{
				Type:   SupportedVersionsExtensionType,
				Length: 2,
				Data:   []byte{0x03, 0x04}, // TLS 1.3
			},
			{
				Type:   KeyShareExtensionType,
				Length: keyShareExtension.Length,
				Data:   keyShareExtension.ToBytes(),
			},
		},
	}, nil
}
