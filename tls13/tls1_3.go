package tls13

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"hash"
	"log"
	"net"

	"golang.org/x/crypto/hkdf"
)

type (
	HandshakeEncoder interface {
		Bytes() []byte
	}

	ContentType     uint8 // Record protocol
	ProtocolVersion uint16
	HandshakeType   uint8
	ExtensionType   uint16
	CertificateType uint8

	CipherSuite        uint16
	NamedGroup         uint16
	SignatureScheme    uint16
	PSKKeyExchangeMode uint8

	// TLS Record before encryption
	TLSPlainText struct {
		ContentType         ContentType
		LegacyRecordVersion ProtocolVersion
		Length              uint16
		Fragment            []byte
	}

	// TLS Record used as a payload for encryption
	TLSInnerPlainText struct {
		Content     []byte
		ContentType ContentType // real content type
		Zeros       []byte      // padding
	}

	TLSCipherMessageText struct {
		ContentType     ContentType
		LegacyVersion   ProtocolVersion
		Length          uint16
		EncryptedRecord []byte // Encrypted TLSInnerPlainText
	}

	Handshake[T HandshakeEncoder] struct {
		MsgType          HandshakeType
		Length           uint32
		HandshakeMessage T
	}

	// HandshakeEncoder
	ClientHelloMessage struct {
		LegacyVersion           ProtocolVersion
		Random                  []byte
		LegacySessionID         []byte
		CipherSuites            []CipherSuite
		LegacyCompressionMethod []byte
		Extensions              []Extension
	}
	ServerHelloMessage struct {
		LegacyVersion     ProtocolVersion
		RandomBytes       [32]byte
		SessionID         []byte
		CipherSuite       CipherSuite
		CompressionMethod uint8
		Extensions        []Extension
	}
	EncryptedExtensionsMessage struct {
		Extensions []Extension
	}

	Extension struct {
		Type   ExtensionType
		Length uint16
		Data   []byte
	}

	ClientSupportedVersionsExtension struct {
		SelectedVersions []ProtocolVersion
	}

	SupportedPointFormatsExtension struct {
		Length         uint8
		ECPointFormats []uint8
	}

	PSKKeyExchangeModesExtension struct {
		Length  uint8
		KEModes []PSKKeyExchangeMode
	}

	SupportedGroupExtension struct {
		Length         uint16
		NamedGroupList []NamedGroup
	}

	SignatureAlgorithmsExtension struct {
		Length                       uint16
		SupportedSignatureAlgorithms []SignatureScheme
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
	InvalidRecord          ContentType = 0x00
	ChangeCipherSpecRecord ContentType = 0x14
	AlertRecord            ContentType = 0x15
	HandshakeRecord        ContentType = 0x16
	ApplicationDataRecord  ContentType = 0x17

	TLS10 ProtocolVersion = 0x0301
	TLS11 ProtocolVersion = 0x0302
	TLS12 ProtocolVersion = 0x0303
	TLS13 ProtocolVersion = 0x0304

	ClientHello         HandshakeType = 0x01
	ServerHello         HandshakeType = 0x02
	EncryptedExtensions HandshakeType = 0x08
	Certificate         HandshakeType = 0x0b
	CertificateVerify   HandshakeType = 0x0f
	Finished            HandshakeType = 0x14

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

	// CipherSuites
	TLS_AES_128_GCM_SHA256                        CipherSuite = 0x1301
	TLS_AES_256_GCM_SHA384                        CipherSuite = 0x1302
	TLS_CHACHA20_POLY1305_SHA256                  CipherSuite = 0x1303
	TLS_AES_128_CCM_SHA256                        CipherSuite = 0x1304
	TLS_AES_128_CCM_8_SHA256                      CipherSuite = 0x1305
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       CipherSuite = 0xc02b
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       CipherSuite = 0xc02c
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256         CipherSuite = 0xc02f
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384         CipherSuite = 0xc030
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA            CipherSuite = 0xc013
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA            CipherSuite = 0xc014
	TLS_RSA_WITH_AES_128_GCM_SHA256               CipherSuite = 0x009c
	TLS_RSA_WITH_AES_256_GCM_SHA384               CipherSuite = 0x009d
	TLS_RSA_WITH_AES_128_CBC_SHA                  CipherSuite = 0x002f
	TLS_RSA_WITH_AES_256_CBC_SHA                  CipherSuite = 0x0035
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   CipherSuite = 0xcca8
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 CipherSuite = 0xcca9

	// NamedGroups for Elliptic Curve
	secp256r1 NamedGroup = 0x0017
	secp384r1 NamedGroup = 0x0018
	secp521r1 NamedGroup = 0x0019
	x25519    NamedGroup = 0x001d
	x448      NamedGroup = 0x001e
	ffdhe2048 NamedGroup = 0x0100
	ffdhe3072 NamedGroup = 0x0101
	ffdhe4096 NamedGroup = 0x0102
	ffdhe6144 NamedGroup = 0x0103
	ffdhe8192 NamedGroup = 0x0104

	// SignatureSchemes
	ecdsa_secp256r1_sha256            SignatureScheme = 0x0403
	ecdsa_secp384r1_sha384            SignatureScheme = 0x0503
	ecdsa_secp521r1_sha512            SignatureScheme = 0x0603
	ed25519                           SignatureScheme = 0x0807
	ed448                             SignatureScheme = 0x0808
	rsa_pss_pss_sha256                SignatureScheme = 0x0809
	rsa_pss_pss_sha384                SignatureScheme = 0x080a
	rsa_pss_pss_sha512                SignatureScheme = 0x080b
	ecdsa_brainpoolP256r1tls13_sha256 SignatureScheme = 0x081a
	ecdsa_brainpoolP384r1tls13_sha384 SignatureScheme = 0x081b
	ecdsa_brainpoolP512r1tls13_sha512 SignatureScheme = 0x081c
	rsa_pss_rsae_sha256               SignatureScheme = 0x0804
	rsa_pss_rsae_sha384               SignatureScheme = 0x0805
	rsa_pss_rsae_sha512               SignatureScheme = 0x0806
	rsa_pkcs1_sha256                  SignatureScheme = 0x0401
	rsa_pkcs1_sha384                  SignatureScheme = 0x0501
	rsa_pkcs1_sha512                  SignatureScheme = 0x0601

	// PSKKeyExchangeMode
	psk_ke     PSKKeyExchangeMode = 0
	psk_dhe_ke PSKKeyExchangeMode = 1
)

// https://tex2e.github.io/rfc-translater/html/rfc8422.html#6--Cipher-Suites
// https://tex2e.github.io/rfc-translater/html/rfc7905.html
// https://datatracker.ietf.org/doc/html/rfc5288
// https://tex2e.github.io/rfc-translater/html/rfc5246.html#A-5--The-Cipher-Suite

var ProtocolVersionName = map[ProtocolVersion]string{
	TLS10: "TLS 1.0",
	TLS11: "TLS 1.1",
	TLS12: "TLS 1.2",
	TLS13: "TLS 1.3",
}

var CipherSuiteName = map[CipherSuite]string{
	TLS_AES_128_GCM_SHA256:                        "TLS_AES_128_GCM_SHA256",
	TLS_AES_256_GCM_SHA384:                        "TLS_AES_256_GCM_SHA384",
	TLS_CHACHA20_POLY1305_SHA256:                  "TLS_CHACHA20_POLY1305_SHA256",
	TLS_AES_128_CCM_SHA256:                        "TLS_AES_128_CCM_SHA256",
	TLS_AES_128_CCM_8_SHA256:                      "TLS_AES_128_CCM_8_SHA256",
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:       "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:       "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:         "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:         "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	TLS_RSA_WITH_AES_128_GCM_SHA256:               "TLS_RSA_WITH_AES_128_GCM_SHA256",
	TLS_RSA_WITH_AES_256_GCM_SHA384:               "TLS_RSA_WITH_AES_256_GCM_SHA384",
	TLS_RSA_WITH_AES_128_CBC_SHA:                  "TLS_RSA_WITH_AES_128_CBC_SHA",
	TLS_RSA_WITH_AES_256_CBC_SHA:                  "TLS_RSA_WITH_AES_256_CBC_SHA",
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:   "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
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

var PSKKeyExchangeModeName = map[PSKKeyExchangeMode]string{
	psk_ke:     "psk_ke",
	psk_dhe_ke: "psk_dhe_ke",
}

var NamedGroupName = map[NamedGroup]string{
	secp256r1: "secp256r1",
	secp384r1: "secp384r1",
	secp521r1: "secp521r1",
	x25519:    "x25519",
	x448:      "x448",
	ffdhe2048: "ffdhe2048",
	ffdhe3072: "ffdhe3072",
	ffdhe4096: "ffdhe4096",
	ffdhe6144: "ffdhe6144",
	ffdhe8192: "ffdhe8192",
}

var SignatureAlgorithmName = map[SignatureScheme]string{
	ecdsa_secp256r1_sha256:            "ecdsa_secp256r1_sha256",
	ecdsa_secp384r1_sha384:            "ecdsa_secp384r1_sha384",
	ecdsa_secp521r1_sha512:            "ecdsa_secp521r1_sha512",
	ed25519:                           "ed25519",
	ed448:                             "ed448",
	rsa_pss_pss_sha256:                "rsa_pss_pss_sha256",
	rsa_pss_pss_sha384:                "rsa_pss_pss_sha384",
	rsa_pss_pss_sha512:                "rsa_pss_pss_sha512",
	ecdsa_brainpoolP256r1tls13_sha256: "ecdsa_brainpoolP256r1tls13_sha256",
	ecdsa_brainpoolP384r1tls13_sha384: "ecdsa_brainpoolP384r1tls13_sha384",
	ecdsa_brainpoolP512r1tls13_sha512: "ecdsa_brainpoolP512r1tls13_sha512",
	rsa_pss_rsae_sha256:               "rsa_pss_rsae_sha256",
	rsa_pss_rsae_sha384:               "rsa_pss_rsae_sha384",
	rsa_pss_rsae_sha512:               "rsa_pss_rsae_sha512",
	rsa_pkcs1_sha256:                  "rsa_pkcs1_sha256",
	rsa_pkcs1_sha384:                  "rsa_pkcs1_sha384",
	rsa_pkcs1_sha512:                  "rsa_pkcs1_sha512",
}

func fromClientHello(clientHelloBuffer []byte) ClientHelloMessage {
	legacyVersion := ProtocolVersion(binary.BigEndian.Uint16(clientHelloBuffer[0:2])) // 2 bytes
	random := clientHelloBuffer[2:34]                                                 // 32 bytes
	legacySessionIDLength := uint8(clientHelloBuffer[34])                             // 1 byte
	legacySessionID := clientHelloBuffer[35 : 35+legacySessionIDLength]
	cipherSuiteLength := binary.BigEndian.Uint16(clientHelloBuffer[35+legacySessionIDLength : 35+legacySessionIDLength+2]) // 2 bytes
	cipherSuites := []CipherSuite{}
	for i := 0; i < int(cipherSuiteLength); i += 2 {
		cipherSuite := binary.BigEndian.Uint16(clientHelloBuffer[35+int(legacySessionIDLength)+2+i : 35+int(legacySessionIDLength)+2+i+2])
		cipherSuites = append(cipherSuites, CipherSuite(cipherSuite))
	}
	legacyCompressionMethodLength := uint8(clientHelloBuffer[35+int(legacySessionIDLength)+2+int(cipherSuiteLength)])
	legacyCompressionOffset := 35 + int(legacySessionIDLength) + 2 + int(cipherSuiteLength) + 1
	legacyCompressionMethod := clientHelloBuffer[legacyCompressionOffset : legacyCompressionOffset+int(legacyCompressionMethodLength)]

	// Extensions
	extensionOffset := 35 + int(legacySessionIDLength) + 2 + int(cipherSuiteLength) + 1 + int(legacyCompressionMethodLength)
	extensionLength := binary.BigEndian.Uint16(clientHelloBuffer[extensionOffset : extensionOffset+2])
	extensionBuffer := clientHelloBuffer[extensionOffset+2 : extensionOffset+2+int(extensionLength)]
	var extensions []Extension
	cursor := 0
	for cursor < int(extensionLength) {
		length := binary.BigEndian.Uint16(extensionBuffer[cursor+2 : cursor+4])
		extensions = append(extensions, Extension{
			Type:   ExtensionType(binary.BigEndian.Uint16(extensionBuffer[cursor : cursor+2])),
			Length: length,
			Data:   extensionBuffer[cursor+4 : cursor+4+int(length)],
		})
		cursor += 4 + int(length)
	}
	return ClientHelloMessage{
		LegacyVersion:           legacyVersion,
		Random:                  random,
		LegacySessionID:         legacySessionID,
		CipherSuites:            cipherSuites,
		LegacyCompressionMethod: legacyCompressionMethod,
		Extensions:              extensions,
	}
}

func (ch ClientHelloMessage) parseExtensions() map[ExtensionType]interface{} {
	var extensionMap = make(map[ExtensionType]interface{})
	for _, extension := range ch.Extensions {
		switch extension.Type {
		case SupportedPointFormatsExtensionType:
			fmt.Println("  - SupportedPointFormatsExtension")
			length := uint8(extension.Data[0])
			var ECPointFormats []uint8
			for i := 0; i < int(length); i++ {
				ECPointFormat := uint8(extension.Data[1+i])
				ECPointFormats = append(ECPointFormats, ECPointFormat)
				fmt.Printf("      ECPointFormat: %s (%x)\n", ECPointFormatName[ECPointFormat], ECPointFormat)
			}
			extensionMap[SupportedPointFormatsExtensionType] = SupportedPointFormatsExtension{
				Length:         length,
				ECPointFormats: ECPointFormats,
			}
		case SupportedGroupsExtensionType:
			fmt.Println("  - SupportedGroupsExtension")
			length := binary.BigEndian.Uint16(extension.Data[0:2])
			var NamedGroupList []NamedGroup
			for i := 0; i < int(length); i += 2 {
				namedGroup := binary.BigEndian.Uint16(extension.Data[2+i : 2+i+2])
				NamedGroupList = append(NamedGroupList, NamedGroup(namedGroup))
				fmt.Printf("      Named Group: %s (%x)\n", NamedGroupName[NamedGroup(namedGroup)], namedGroup)
			}
			extensionMap[SupportedGroupsExtensionType] = SupportedGroupExtension{
				Length:         length,
				NamedGroupList: NamedGroupList,
			}
		case SignatureAlgorithmsExtensionType:
			fmt.Println("  - SignatureAlgorithmsExtension")
			length := binary.BigEndian.Uint16(extension.Data[0:2])
			// fmt.Println("  SignatureAlgorithmsExtension length:", length)
			var signatureAlgorithms []SignatureScheme
			for i := 0; i < int(length); i += 2 {
				signatureScheme := binary.BigEndian.Uint16(extension.Data[2+i : 2+i+2])
				signatureAlgorithms = append(signatureAlgorithms, SignatureScheme(signatureScheme))
				fmt.Printf("      Signature algorithm: %s (%x)\n", SignatureAlgorithmName[SignatureScheme(signatureScheme)], signatureScheme)
			}
			extensionMap[SignatureAlgorithmsExtensionType] = SignatureAlgorithmsExtension{
				Length:                       length,
				SupportedSignatureAlgorithms: signatureAlgorithms,
			}
		case KeyShareExtensionType:
			fmt.Println("  - KeyShareExtension")
			length := binary.BigEndian.Uint16(extension.Data[0:2])
			// fmt.Println("  KeyShareExtension length:", length)
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
				fmt.Printf("      Group: %s (%x)\n", NamedGroupName[NamedGroup(group)], group)
				fmt.Printf("      Length: %d\n", keyExchangeDataLength)
				fmt.Printf("      KeyExchangeData: %x\n", clientShare.KeyExchangeData)
				keyShareCursor += 4 + int(keyExchangeDataLength)
			}
			extensionMap[KeyShareExtensionType] = KeyShareExtension{
				Length:       length,
				ClientShares: clientShares,
			}
		case ExtendedMasterSecretExtensionType:
			fmt.Println("  - ExtendedMasterSecretExtension")
		case SupportedVersionsExtensionType:
			// https://tex2e.github.io/rfc-translater/html/rfc8446.html#4-2-1--Supported-Versions
			fmt.Println("  - SupportedVersionsExtension")
			length := uint8(extension.Data[0])
			versions := []ProtocolVersion{}
			for i := 0; i < int(length); i += 2 {
				version := binary.BigEndian.Uint16(extension.Data[1+i : 1+i+2])
				versions = append(versions, ProtocolVersion(version))
				fmt.Printf("      Version: %s (%x)\n", ProtocolVersionName[ProtocolVersion(version)], version)
			}
			extensionMap[SupportedVersionsExtensionType] = ClientSupportedVersionsExtension{
				SelectedVersions: versions,
			}
		case PSKKeyExchangeModesExtensionType:
			fmt.Println("  - PSKKeyExchangeModesExtension")
			length := uint8(extension.Data[0])
			keModes := []PSKKeyExchangeMode{}
			for i := 0; i < int(length); i++ {
				keMode := PSKKeyExchangeMode(extension.Data[1+i])
				keModes = append(keModes, PSKKeyExchangeMode(keMode))
				fmt.Printf("      PSKKeyExchangeMode: %s (%x)\n", PSKKeyExchangeModeName[PSKKeyExchangeMode(keMode)], keMode)
			}
			extensionMap[PSKKeyExchangeModesExtensionType] = PSKKeyExchangeModesExtension{
				Length:  length,
				KEModes: keModes,
			}
		case EncryptThenMacExtensionType:
			// https://tex2e.github.io/rfc-translater/html/rfc7366.html
			fmt.Println("  - EncryptThenMacExtension")
		case SessionTicketExtensionType:
			fmt.Println("  - SessionTicketExtension")
		default:
			fmt.Printf("  - Extension data: %x\n", extension)
			extensionMap[extension.Type] = extension.Data
		}
	}
	return extensionMap
}

func NewTLSCipherMessageText(encryptedRecord []byte) *TLSCipherMessageText {
	return &TLSCipherMessageText{
		ContentType:     ApplicationDataRecord,
		LegacyVersion:   TLS12,
		Length:          uint16(len(encryptedRecord)),
		EncryptedRecord: encryptedRecord,
	}
}

func (t TLSInnerPlainText) Bytes() []byte {
	return append(append(t.Content, byte(t.ContentType)), t.Zeros...)
}

func (t TLSCipherMessageText) Bytes() []byte {
	return append([]byte{
		byte(uint8(t.ContentType)),
		byte(uint8(t.LegacyVersion >> 8)),
		byte(uint8(t.LegacyVersion)),
		byte(uint8(t.Length >> 8)),
		byte(uint8(t.Length)),
	}, t.EncryptedRecord...)
}

func (t TLSPlainText) Bytes() []byte {
	return append([]byte{
		byte(uint8(t.ContentType)),
		byte(uint8(t.LegacyRecordVersion >> 8)),
		byte(uint8(t.LegacyRecordVersion)),
		byte(uint8(t.Length >> 8)),
		byte(uint8(t.Length)),
	}, t.Fragment...)
}

func (ch ClientHelloMessage) Bytes() []byte {
	return []byte{}
}

func (sh ServerHelloMessage) Bytes() []byte {
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
		serverHello = append(serverHello, extension.Bytes()...)
	}
	return serverHello
}

func (hs Handshake[T]) Bytes() []byte {
	handshake := []byte{}
	handshake = append(handshake, byte(uint8(hs.MsgType)))
	handshake = append(handshake, byte(uint8(hs.Length>>16)))
	handshake = append(handshake, byte(uint8(hs.Length>>8)))
	handshake = append(handshake, byte(uint8(hs.Length)))
	handshake = append(handshake, hs.HandshakeMessage.Bytes()...)
	return handshake
}

func (ee EncryptedExtensionsMessage) Bytes() []byte {
	encryptedExtensions := []byte{}
	extensionLength := 0
	for _, extension := range ee.Extensions {
		extensionLength += 4 + int(extension.Length)
	}
	encryptedExtensions = append(encryptedExtensions, byte(uint8(extensionLength>>8)))
	encryptedExtensions = append(encryptedExtensions, byte(uint8(extensionLength)))
	for _, extension := range ee.Extensions {
		encryptedExtensions = append(encryptedExtensions, extension.Bytes()...)
	}
	return encryptedExtensions
}

func (e Extension) Bytes() []byte {
	extension := []byte{}
	extension = append(extension, byte(uint8(e.Type>>8)))
	extension = append(extension, byte(uint8(e.Type)))
	extension = append(extension, byte(uint8(e.Length>>8)))
	extension = append(extension, byte(uint8(e.Length)))
	extension = append(extension, e.Data...)
	return extension
}

func (kse KeyShareExtension) Bytes() []byte {
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

func (l HKDFLabel) Bytes() []byte {
	label := []byte{}
	label = append(label, byte(uint8(l.Length>>8)))
	label = append(label, byte(uint8(l.Length)))

	labelBytes := []byte(l.Label)
	label = append(label, byte(len(labelBytes)))
	label = append(label, labelBytes...)

	label = append(label, byte(len(l.Context)))
	label = append(label, l.Context...)
	return label
}

func (s *Secrets) HandshakeKeys(clientHello []byte, serverHello []byte, keyLength int, ivLength int) ([]byte, []byte, error) {
	clientHandshakeTrafficSecret, err := DeriveSecret(s.Hash, s.HandshakeSecret, "c hs traffic", [][]byte{clientHello, serverHello})
	if err != nil {
		return nil, nil, err
	}
	fmt.Printf("Client Handshake Traffic Secret: %x\n", clientHandshakeTrafficSecret)

	serverHandshakeTrafficSecret, err := DeriveSecret(s.Hash, s.HandshakeSecret, "s hs traffic", [][]byte{clientHello, serverHello})
	if err != nil {
		return nil, nil, err
	}
	fmt.Printf("Server Handshake Traffic Secret: %x\n", serverHandshakeTrafficSecret)

	serverWriteKey, err := HKDFExpandLabel(s.Hash, serverHandshakeTrafficSecret, "key", []byte{}, keyLength)
	if err != nil {
		return nil, nil, err
	}
	serverWriteIV, err := HKDFExpandLabel(s.Hash, serverHandshakeTrafficSecret, "iv", []byte{}, ivLength)
	if err != nil {
		return nil, nil, err
	}
	return serverWriteKey, serverWriteIV, nil
}

func (ce CertificateEntry) Bytes() []byte {
	certEntry := []byte{}
	// 証明書データの長さを3バイトで表現
	length := len(ce.CertData)
	certEntry = append(certEntry, byte(length>>16), byte(length>>8), byte(length))
	certEntry = append(certEntry, ce.CertData...)
	certEntry = append(certEntry, 0, 0) // extensions
	return certEntry
}

func (c CertificateMessage) Bytes() []byte {
	cert := []byte{}
	// 証明書リクエストコンテキストの長さを1バイトで表現
	cert = append(cert, byte(len(c.CertificateRequestContext)))
	cert = append(cert, c.CertificateRequestContext...)
	length := 0
	for _, entry := range c.CertificateList {
		length += len(entry.Bytes())
	}
	// 証明書リストの長さを3バイトで表現
	cert = append(cert, byte(length>>16), byte(length>>8), byte(length))
	for _, entry := range c.CertificateList {
		cert = append(cert, entry.Bytes()...)
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
		ContentType:         ContentType(header[0]),
		LegacyRecordVersion: ProtocolVersion(binary.BigEndian.Uint16(header[1:3])),
		Length:              length,
		Fragment:            header[5 : 5+length],
	}

	var handshakeResponse TLSPlainText
	if tlsRecord.ContentType == HandshakeRecord { // 22 stands for Handshake record type
		fmt.Println("Received TLS Handshake message")
		fmt.Printf("Legacy version: %x\n", tlsRecord.LegacyRecordVersion)
		fmt.Printf("Record length: %d bytes\n", tlsRecord.Length)

		// extract 3 bytes
		msgType := HandshakeType(tlsRecord.Fragment[0])
		handshakeLength := (uint32(tlsRecord.Fragment[1]) << 16) | (uint32(tlsRecord.Fragment[2]) << 8) | uint32(tlsRecord.Fragment[3])
		fmt.Println(fmt.Sprintf("Handshake msg_type: %d\n", msgType))
		if msgType == ClientHello { // 1 for ClientHello
			fmt.Println("Received ClientHello message")
			fmt.Println("Handshake: ClientHello")
			fmt.Printf("Handshake message length: %d bytes\n", handshakeLength)
			fmt.Println()
			clientHello := fromClientHello(tlsRecord.Fragment[4 : 4+handshakeLength])
			fmt.Printf("Legacy version: %x\n", clientHello.LegacyVersion)
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

			// ServerHello
			ecdhServerPrivateKey, serverHello, err := constructServerHello(ecdh.P256(), secp256r1, TLS_AES_128_GCM_SHA256, clientHello.LegacySessionID)
			if err != nil {
				fmt.Println("Error constructing ServerHello message:", err)
				return
			}
			serverHelloHandshake := Handshake[ServerHelloMessage]{
				MsgType:          ServerHello,
				Length:           uint32(len(serverHello.Bytes())),
				HandshakeMessage: *serverHello,
			}

			handshakeResponse = TLSPlainText{
				ContentType:         HandshakeRecord, // 0x16
				LegacyRecordVersion: TLS12,           // 0x0303
				Length:              uint16(len(serverHelloHandshake.Bytes())),
				Fragment:            serverHelloHandshake.Bytes(),
			}
			fmt.Printf("ServerHello: %x\n\n", handshakeResponse.Bytes())
			conn.Write(handshakeResponse.Bytes())

			// ChangeCipherSpec, is this necessary?
			conn.Write(TLSPlainText{
				ContentType:         ChangeCipherSpecRecord, // 0x14
				LegacyRecordVersion: TLS12,                  // 0x0303
				Length:              1,
				Fragment:            []byte{1},
			}.Bytes())

			keyShareExtension := extensions[KeyShareExtensionType].(KeyShareExtension)
			clientECDHPublicKey := keyShareExtension.ClientShares[0].KeyExchangeData
			secrets, err := generateSecrets(ecdh.P256(), clientECDHPublicKey, ecdhServerPrivateKey)
			if err != nil {
				fmt.Println("Error generating secrets:", err)
				return
			}
			serverWriteKey, serverWriteIV, err := secrets.HandshakeKeys(tlsRecord.Fragment, handshakeResponse.Fragment, 16, 12)
			fmt.Printf("Server write key: %x\n", serverWriteKey)
			fmt.Printf("Server IV: %x\n\n", serverWriteIV)

			// EncryptedExtensions
			extentions := EncryptedExtensionsMessage{
				Extensions: []Extension{},
			}
			encryptedExtensionsMessage, err := encryptMessage(serverWriteKey, serverWriteIV, TLSInnerPlainText{
				Content: Handshake[EncryptedExtensionsMessage]{
					MsgType:          EncryptedExtensions,
					Length:           uint32(len(extentions.Bytes())),
					HandshakeMessage: extentions,
				}.Bytes(),
				ContentType: HandshakeRecord,
			}.Bytes(), 0)
			if err != nil {
				fmt.Println("Error encrypting message:", err)
				return
			}
			fmt.Println("Length of EncryptedExtensions:", len(extentions.Bytes()))
			fmt.Printf("Encrypted EncryptedExtensions Message: %x\n", encryptedExtensionsMessage)
			fmt.Printf("Encrypted EncryptedExtensions Message length: %d\n\n", len(encryptedExtensionsMessage))
			encryptedExtensionsTLSRecord := NewTLSCipherMessageText(encryptedExtensionsMessage)
			fmt.Printf("Certificate TLS Record: %x\n\n", encryptedExtensionsTLSRecord)
			conn.Write(encryptedExtensionsTLSRecord.Bytes())

			certificateMessage, err := constructCertificate()
			if err != nil {
				fmt.Println("Error constructing certificate:", err)
				return
			}
			fmt.Printf("Certificate: %x\n", certificateMessage.Bytes())
			fmt.Printf("Certificate Length: %d\n\n", len(certificateMessage.Bytes()))
			// TODO: Encrypt the certificate to construct Certificate message
			// AES_128_GCMで暗号化
			encryptedHandshakeCertificateMessage, err := encryptMessage(serverWriteKey, serverWriteIV, TLSInnerPlainText{
				Content: Handshake[CertificateMessage]{
					MsgType:          Certificate,
					Length:           uint32(len(certificateMessage.Bytes())),
					HandshakeMessage: *certificateMessage,
				}.Bytes(),
				ContentType: HandshakeRecord,
			}.Bytes(), 1)
			if err != nil {
				fmt.Println("Error encrypting message:", err)
				return
			}

			fmt.Printf("Encrypted Certificate Message: %x\n", encryptedHandshakeCertificateMessage)
			fmt.Printf("Encrypted Certificate Message length: %d\n\n", len(encryptedHandshakeCertificateMessage))

			certificateTLSRecord := NewTLSCipherMessageText(encryptedHandshakeCertificateMessage)
			fmt.Printf("Certificate TLS Record: %x\n\n", certificateTLSRecord.Bytes())
			conn.Write(certificateTLSRecord.Bytes())
		}

		// fmt.Printf("ServerHello: %x\n", handshakeResponse.Bytes())
		// conn.Write(handshakeResponse.Bytes())
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
	zero32 := make([]byte, hash().Size())
	earlySecret := hkdf.Extract(hash, zero32, zero32)
	fmt.Printf("Early Secret: %x\n", earlySecret)

	secretState, err := DeriveSecret(hash, earlySecret, "derived", [][]byte{})
	if err != nil {
		return nil, err
	}
	handshakeSecret := hkdf.Extract(hash, sharedSecret, secretState)
	fmt.Printf("Handshake Secret: %x\n", handshakeSecret)

	secretState, err = DeriveSecret(hash, handshakeSecret, "derived", [][]byte{})
	if err != nil {
		return nil, err
	}
	masterSecret := hkdf.Extract(hash, zero32, secretState)
	return &Secrets{
		Hash:            hash,
		EarlySecret:     earlySecret,
		HandshakeSecret: handshakeSecret,
		MasterSecret:    masterSecret,
	}, nil
}

func encryptMessage(key, iv, plaintext []byte, sequenceNumber uint64) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	sequenceNumberBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(sequenceNumberBytes, sequenceNumber)

	paddedSequenceNumber := make([]byte, len(iv))
	copy(paddedSequenceNumber[len(iv)-8:], sequenceNumberBytes)
	fmt.Println("paddedSequenceNumber is ", paddedSequenceNumber)
	nonce := make([]byte, len(iv))
	for i := range iv {
		nonce[i] = paddedSequenceNumber[i] ^ iv[i]
	}
	fmt.Println("nonce is ", nonce)
	fmt.Println("plaintext length is ", len(plaintext))
	TLSCipherTextLength := len(plaintext) + aesgcm.Overhead()
	additional_data := []byte{
		0x17, 0x03, 0x03, byte(TLSCipherTextLength >> 8), byte(TLSCipherTextLength),
	}
	fmt.Printf("additional_data is %x\n", additional_data)
	encrypted := aesgcm.Seal(nil, nonce, plaintext, additional_data)
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

func constructServerHello(curve ecdh.Curve, namedGroup NamedGroup, cipherSuite CipherSuite, sessionID []byte) (*ecdh.PrivateKey, *ServerHelloMessage, error) {
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
				Group:           uint16(namedGroup),
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
				Data:   keyShareExtension.Bytes(),
			},
		},
	}, nil
}
