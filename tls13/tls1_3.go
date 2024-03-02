package tls13

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"log"

	"golang.org/x/crypto/hkdf"
)

type (
	ContentType      uint8 // for Record protocol
	ProtocolVersion  uint16
	HandshakeType    uint8
	ExtensionType    uint16
	CertificateType  uint8
	AlertLevel       uint8 // for Alert protocol
	AlertDescription uint8 // for Alert protocol

	CipherSuite        uint16
	NamedGroup         uint16
	SignatureScheme    uint16
	PSKKeyExchangeMode uint8
	NameType           uint8 // for ServerNameExtension

	// TLSRecord represents either TLSPlainText or TLSCipherMessageText
	TLSRecord struct {
		ContentType         ContentType
		LegacyRecordVersion ProtocolVersion
		Length              uint16
		Fragment            []byte
	}

	// TLSInnerPlainText represents TLS Record used as a payload for encryption
	TLSInnerPlainText struct {
		Content     []byte
		ContentType ContentType // real content type
		Zeros       []byte      // padding
	}

	HandshakeEncoder interface {
		Bytes() []byte
	}
	Handshake[T HandshakeEncoder] struct {
		MsgType          HandshakeType
		Length           uint32
		HandshakeMessage T
	}
	ApplicationData struct {
		Data []byte
	}
	Alert struct {
		Level       AlertLevel
		Description AlertDescription
	}

	// Handshake messages
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
	CertificateMessage struct {
		CertificateRequestContext []byte
		CertificateList           []CertificateEntry
	}
	CertificateVerifyMessage struct {
		Algorithm SignatureScheme
		Signature []byte
	}
	FinishedMessage struct {
		VerifyData []byte
	}

	CertificateEntry struct {
		CertType CertificateType
		CertData []byte
	}

	// Extensions
	Extension struct {
		ExtensionType ExtensionType
		Length        uint16
		Data          []byte
	}

	ServerNameExtension struct {
		Length         uint16
		ServerNameList []ServerName
	}
	ServerName struct {
		NameType NameType
		Length   uint16
		HostName []byte
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
		Group           NamedGroup
		Length          uint16
		KeyExchangeData []byte
	}
	KeyShareExtension struct {
		Length       uint16
		ClientShares []KeyShareEntry
	}

	RecordSizeLimitExtension uint16

	RenegotiationInfoExtension struct {
		Length                 uint8
		RegegotiatedConnection []byte
	}

	ProtocolName  []byte
	ALPNExtension struct {
		Length            uint16
		ProtocoleNameList []ProtocolName
	}

	// Data structures for key derivation
	HKDFLabel struct {
		Length  uint16
		Label   string
		Context []byte
	}

	Secrets struct {
		Hash            func() hash.Hash
		SharedSecret    []byte
		EarlySecret     []byte
		HandshakeSecret []byte
		MasterSecret    []byte
	}

	HandshakeTrafficSecrets struct {
		ClientHandshakeTrafficSecret   []byte
		ServerHandshakeTrafficSecret   []byte
		ClientApplicationTrafficSecret []byte
		ServerApplicationTrafficSecret []byte
		ServerWriteKey                 []byte
		ServerWriteIV                  []byte
		ClientWriteKey                 []byte
		ClientWriteIV                  []byte
	}

	ApplicationTrafficSecrets struct {
		ClientApplicationTrafficSecret []byte
		ServerApplicationTrafficSecret []byte
		ClientWriteKey                 []byte
		ClientWriteIV                  []byte
		ServerWriteKey                 []byte
		ServerWriteIV                  []byte
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
	SRPExtensionType                        = 12
	SupportedGroupsExtensionType            = 10
	ApplicationLayerProtocolNegotiationType = 16
	SignedCertificateTimestampExtensionType = 18
	DelegateCredentialExtensionType         = 34
	CompressCertificateExtensionType        = 27
	RecordSizeLimitExtensionType            = 28
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
	ECDSA_SECP256R1_SHA256            SignatureScheme = 0x0403
	ECDSA_SECP384R1_SHA384            SignatureScheme = 0x0503
	ECDSA_SECP521R1_SHA512            SignatureScheme = 0x0603
	Ed25519                           SignatureScheme = 0x0807
	ED448                             SignatureScheme = 0x0808
	RSA_PSS_PSS_SHA256                SignatureScheme = 0x0809
	RSA_PSS_PSS_SHA384                SignatureScheme = 0x080a
	RSA_PSS_PSS_SHA512                SignatureScheme = 0x080b
	ECDSA_BRAINPOOLp256R1TLS13_SHA256 SignatureScheme = 0x081a
	ECDSA_BRAINPOOLp384R1TLS13_SHA384 SignatureScheme = 0x081b
	ECDSA_BRAINPOOLp512R1TLS13_SHA512 SignatureScheme = 0x081c
	RSA_PSS_RSAE_SHA256               SignatureScheme = 0x0804
	RSA_PSS_RSAE_SHA384               SignatureScheme = 0x0805
	RSA_PSS_RSAE_SHA512               SignatureScheme = 0x0806
	RSA_PKCS1_SHA256                  SignatureScheme = 0x0401
	RSA_PKCS1_SHA384                  SignatureScheme = 0x0501
	RSA_PKCS1_SHA512                  SignatureScheme = 0x0601

	// PSKKeyExchangeMode
	psk_ke     PSKKeyExchangeMode = 0
	psk_dhe_ke PSKKeyExchangeMode = 1

	warning AlertLevel = 1
	fatal   AlertLevel = 2

	close_notify                    AlertDescription = 0
	unexpected_message              AlertDescription = 10
	bad_record_mac                  AlertDescription = 20
	decryption_failed               AlertDescription = 21
	record_overflow                 AlertDescription = 22
	handshake_failure               AlertDescription = 40
	bad_certificate                 AlertDescription = 42
	unsupported_certificate         AlertDescription = 43
	certificate_revoked             AlertDescription = 44
	certificate_expired             AlertDescription = 45
	certificate_unknown             AlertDescription = 46
	illegal_parameter               AlertDescription = 47
	unknown_ca                      AlertDescription = 48
	access_denied                   AlertDescription = 49
	decode_error                    AlertDescription = 50
	decrypt_error                   AlertDescription = 51
	export_restriction              AlertDescription = 60
	protocol_version                AlertDescription = 70
	insufficient_security           AlertDescription = 71
	internal_error                  AlertDescription = 80
	user_canceled                   AlertDescription = 90
	no_renegotiation                AlertDescription = 100
	unsupported_extension           AlertDescription = 110
	unrecognized_name               AlertDescription = 112
	bad_certificate_status_response AlertDescription = 113
	unknown_psk_identity            AlertDescription = 115
	certificate_required            AlertDescription = 116
	no_application_protocol         AlertDescription = 120
)

// https://tex2e.github.io/rfc-translater/html/rfc8422.html#6--Cipher-Suites
// https://tex2e.github.io/rfc-translater/html/rfc7905.html
// https://datatracker.ietf.org/doc/html/rfc5288
// https://tex2e.github.io/rfc-translater/html/rfc5246.html#A-5--The-Cipher-Suite

var (
	ProtocolVersionName = map[ProtocolVersion]string{
		TLS10: "TLS 1.0",
		TLS11: "TLS 1.1",
		TLS12: "TLS 1.2",
		TLS13: "TLS 1.3",
	}

	ContentTypeName = map[ContentType]string{
		InvalidRecord:          "Invalid Record",
		ChangeCipherSpecRecord: "Change Cipher Spec",
		AlertRecord:            "Alert",
		HandshakeRecord:        "Handshake",
		ApplicationDataRecord:  "Application Data",
	}

	HandshakeTypeName = map[HandshakeType]string{
		ClientHello:         "ClientHello",
		ServerHello:         "ServerHello",
		EncryptedExtensions: "EncryptedExtensions",
		Certificate:         "Certificate",
		CertificateVerify:   "CertificateVerify",
		Finished:            "Finished",
	}

	CipherSuiteName = map[CipherSuite]string{
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

	ExtensionName = map[ExtensionType]string{
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

	ECPointFormatName = map[uint8]string{
		0: "uncompressed",
		1: "ansiX962_compressed_prime",
		2: "ansiX962_compressed_char2",
	}

	PSKKeyExchangeModeName = map[PSKKeyExchangeMode]string{
		psk_ke:     "psk_ke",
		psk_dhe_ke: "psk_dhe_ke",
	}

	NamedGroupName = map[NamedGroup]string{
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

	SignatureAlgorithmName = map[SignatureScheme]string{
		ECDSA_SECP256R1_SHA256:            "ecdsa_secp256r1_sha256",
		ECDSA_SECP384R1_SHA384:            "ecdsa_secp384r1_sha384",
		ECDSA_SECP521R1_SHA512:            "ecdsa_secp521r1_sha512",
		Ed25519:                           "ed25519",
		ED448:                             "ed448",
		RSA_PSS_PSS_SHA256:                "rsa_pss_pss_sha256",
		RSA_PSS_PSS_SHA384:                "rsa_pss_pss_sha384",
		RSA_PSS_PSS_SHA512:                "rsa_pss_pss_sha512",
		ECDSA_BRAINPOOLp256R1TLS13_SHA256: "ecdsa_brainpoolP256r1tls13_sha256",
		ECDSA_BRAINPOOLp384R1TLS13_SHA384: "ecdsa_brainpoolP384r1tls13_sha384",
		ECDSA_BRAINPOOLp512R1TLS13_SHA512: "ecdsa_brainpoolP512r1tls13_sha512",
		RSA_PSS_RSAE_SHA256:               "rsa_pss_rsae_sha256",
		RSA_PSS_RSAE_SHA384:               "rsa_pss_rsae_sha384",
		RSA_PSS_RSAE_SHA512:               "rsa_pss_rsae_sha512",
		RSA_PKCS1_SHA256:                  "rsa_pkcs1_sha256",
		RSA_PKCS1_SHA384:                  "rsa_pkcs1_sha384",
		RSA_PKCS1_SHA512:                  "rsa_pkcs1_sha512",
	}
)

// SelectECDHKeyShare selects a Diffie-Hellman key exchange algorithm from the KeyShareExtension
func (ks KeyShareExtension) SelectECDHKeyShare() (*KeyShareEntry, ecdh.Curve) {
	supportedCurves := map[NamedGroup]ecdh.Curve{
		secp256r1: ecdh.P256(),
		secp384r1: ecdh.P384(),
		secp521r1: ecdh.P521(),
		x25519:    ecdh.X25519(),
	}
	for _, clientShare := range ks.ClientShares {
		curve, ok := supportedCurves[clientShare.Group]
		if ok {
			return &clientShare, curve
		}
	}
	return nil, nil
}

func (t TLSInnerPlainText) Bytes() []byte {
	return append(append(t.Content, byte(t.ContentType)), t.Zeros...)
}

func (hs Handshake[T]) Bytes() []byte {
	return append([]byte{
		byte(uint8(hs.MsgType)),
		byte(uint8(hs.Length >> 16)),
		byte(uint8(hs.Length >> 8)),
		byte(uint8(hs.Length)),
	}, hs.HandshakeMessage.Bytes()...)
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

	extensionBytes := []byte{}
	for _, extension := range sh.Extensions {
		extensionBytes = append(extensionBytes, extension.Bytes()...)
	}

	extensionLength := len(extensionBytes)
	serverHello = append(serverHello, byte(uint8(extensionLength>>8)))
	serverHello = append(serverHello, byte(uint8(extensionLength)))
	return append(serverHello, extensionBytes...)
}

func (e Extension) Bytes() []byte {
	return append([]byte{
		byte(uint8(e.ExtensionType >> 8)),
		byte(uint8(e.ExtensionType)),
		byte(uint8(e.Length >> 8)),
		byte(uint8(e.Length)),
	}, e.Data...)
}

func (ee EncryptedExtensionsMessage) Bytes() []byte {
	extensionsBytes := []byte{}
	for _, extension := range ee.Extensions {
		extensionsBytes = append(extensionsBytes, extension.Bytes()...)
	}

	extensionLength := len(extensionsBytes)
	encryptedExtensions := []byte{}
	encryptedExtensions = append(encryptedExtensions, byte(uint8(extensionLength>>8)))
	encryptedExtensions = append(encryptedExtensions, byte(uint8(extensionLength)))
	return append(encryptedExtensions, extensionsBytes...)
}

func (kse KeyShareExtension) Bytes() []byte {
	extension := []byte{}
	for _, clientShare := range kse.ClientShares {
		extension = append([]byte{
			byte(uint8(clientShare.Group >> 8)),
			byte(uint8(clientShare.Group)),
			byte(uint8(clientShare.Length >> 8)),
			byte(uint8(clientShare.Length)),
		}, clientShare.KeyExchangeData...)
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
	return append(label, l.Context...)
}

func (ce CertificateEntry) Bytes() []byte {
	certEntry := []byte{}
	length := len(ce.CertData)
	certEntry = append(certEntry, byte(length>>16), byte(length>>8), byte(length))
	certEntry = append(certEntry, ce.CertData...)
	certEntry = append(certEntry, 0, 0) // extensions
	return certEntry
}

func (c CertificateMessage) Bytes() []byte {
	cert := []byte{}
	// 1 byte for the length of the certificate_request_context
	cert = append(cert, byte(len(c.CertificateRequestContext)))
	cert = append(cert, c.CertificateRequestContext...)

	entryBytes := []byte{}
	for _, entry := range c.CertificateList {
		entryBytes = append(entryBytes, entry.Bytes()...)
	}

	length := len(entryBytes)
	cert = append(cert, byte(length>>16), byte(length>>8), byte(length))
	return append(cert, entryBytes...)
}

func (c CertificateVerifyMessage) Bytes() []byte {
	return append([]byte{
		byte(uint8(c.Algorithm >> 8)),
		byte(uint8(c.Algorithm)),
		byte(len(c.Signature) >> 8),
		byte(len(c.Signature)),
	}, c.Signature...)
}

func (f FinishedMessage) Bytes() []byte {
	return f.VerifyData
}

func (a Alert) Bytes() []byte {
	return []byte{byte(a.Level), byte(a.Description)}
}

// NewClientHello creates a new ClientHelloMessage from a byte slice sent by the client
func NewClientHello(clientHelloBuffer []byte) ClientHelloMessage {
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
			ExtensionType: ExtensionType(binary.BigEndian.Uint16(extensionBuffer[cursor : cursor+2])),
			Length:        length,
			Data:          extensionBuffer[cursor+4 : cursor+4+int(length)],
		})
		// 4 bytes for Type and Length
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

// ParseExtensions parses the extensions in the ClientHelloMessage with debug logging
func (ch ClientHelloMessage) ParseExtensions(logger *log.Logger) map[ExtensionType]interface{} {
	var extensionMap = make(map[ExtensionType]interface{})
	for _, extension := range ch.Extensions {
		switch extension.ExtensionType {
		case ServerNameExtensionType:
			logger.Printf("  ServerNameExtension (%x)\n", extension.ExtensionType)
			length := binary.BigEndian.Uint16(extension.Data[0:2])
			cursor := 2
			var serverNameList []ServerName
			for cursor < int(length) {
				nameType := NameType(extension.Data[cursor])
				nameLength := binary.BigEndian.Uint16(extension.Data[cursor+1 : cursor+3])
				hostName := extension.Data[cursor+3 : cursor+3+int(nameLength)]
				logger.Printf("    HostName: %s\n", hostName)
				serverNameList = append(serverNameList, ServerName{
					NameType: nameType,
					Length:   nameLength,
					HostName: hostName,
				})
				cursor += 3 + int(nameLength)
			}
			extensionMap[ServerNameExtensionType] = ServerNameExtension{
				ServerNameList: serverNameList,
			}
		case SupportedPointFormatsExtensionType:
			logger.Printf("  SupportedPointFormatsExtension (%x)\n", extension.ExtensionType)
			length := uint8(extension.Data[0])
			var ECPointFormats []uint8
			for i := 0; i < int(length); i++ {
				ECPointFormat := uint8(extension.Data[1+i])
				ECPointFormats = append(ECPointFormats, ECPointFormat)
				logger.Printf("    ECPointFormat: %s (%x)\n", ECPointFormatName[ECPointFormat], ECPointFormat)
			}
			extensionMap[SupportedPointFormatsExtensionType] = SupportedPointFormatsExtension{
				Length:         length,
				ECPointFormats: ECPointFormats,
			}
		case ApplicationLayerProtocolNegotiationType:
			logger.Printf("  ApplicationLayerProtocolNegotiation (%x)\n", extension.ExtensionType)
			length := binary.BigEndian.Uint16(extension.Data[0:2])
			cursor := 2
			protocoleNameList := []ProtocolName{}
			for cursor < int(length) {
				protocolNameLength := uint8(extension.Data[cursor])
				protocolName := extension.Data[cursor+1 : cursor+1+int(protocolNameLength)]
				protocoleNameList = append(protocoleNameList, protocolName)
				logger.Printf("    ProtocolName: %s\n", protocolName)
				cursor += 1 + int(protocolNameLength)
			}
			extensionMap[ApplicationLayerProtocolNegotiationType] = ALPNExtension{
				Length:            length,
				ProtocoleNameList: protocoleNameList,
			}
		case DelegateCredentialExtensionType:
			logger.Printf("  DelegateCredentialExtension (%x)\n", extension.ExtensionType)
			logger.Printf("    Data: %x\n", extension.Data)
		case StatusRequestExtensionType:
			logger.Printf("  StatusRequestExtension (%x)\n", extension.ExtensionType)
			logger.Printf("    Data: %x\n", extension.Data)
		case EncryptedClientHelloExtensionType:
			logger.Printf("  EncryptedClientHelloExtension (%x)\n", extension.ExtensionType)
			logger.Printf("    Data: %x\n", extension.Data)
		case SupportedGroupsExtensionType:
			logger.Printf("  SupportedGroupsExtension (%x)\n", extension.ExtensionType)
			length := binary.BigEndian.Uint16(extension.Data[0:2])
			var NamedGroupList []NamedGroup
			for i := 0; i < int(length); i += 2 {
				namedGroup := binary.BigEndian.Uint16(extension.Data[2+i : 2+i+2])
				NamedGroupList = append(NamedGroupList, NamedGroup(namedGroup))
				logger.Printf("    Named Group: %s (%x)\n", NamedGroupName[NamedGroup(namedGroup)], namedGroup)
			}
			extensionMap[SupportedGroupsExtensionType] = SupportedGroupExtension{
				Length:         length,
				NamedGroupList: NamedGroupList,
			}
		case SignatureAlgorithmsExtensionType:
			logger.Printf("  SignatureAlgorithmsExtension (%x)\n", extension.ExtensionType)
			length := binary.BigEndian.Uint16(extension.Data[0:2])
			// logger.Println("  SignatureAlgorithmsExtension length:", length)
			var signatureAlgorithms []SignatureScheme
			for i := 0; i < int(length); i += 2 {
				signatureScheme := binary.BigEndian.Uint16(extension.Data[2+i : 2+i+2])
				signatureAlgorithms = append(signatureAlgorithms, SignatureScheme(signatureScheme))
				logger.Printf("    Signature algorithm: %s (%x)\n", SignatureAlgorithmName[SignatureScheme(signatureScheme)], signatureScheme)
			}
			extensionMap[SignatureAlgorithmsExtensionType] = SignatureAlgorithmsExtension{
				Length:                       length,
				SupportedSignatureAlgorithms: signatureAlgorithms,
			}
		case KeyShareExtensionType:
			logger.Printf("  KeyShareExtension (%x)\n", extension.ExtensionType)
			length := binary.BigEndian.Uint16(extension.Data[0:2])
			// logger.Println("  KeyShareExtension length:", length)
			var clientShares []KeyShareEntry
			keyShareCursor := 2
			for keyShareCursor < int(length) {
				group := binary.BigEndian.Uint16(extension.Data[keyShareCursor : keyShareCursor+2])
				keyExchangeDataLength := binary.BigEndian.Uint16(extension.Data[keyShareCursor+2 : keyShareCursor+4])
				clientShare := KeyShareEntry{
					Group:           NamedGroup(group),
					Length:          keyExchangeDataLength,
					KeyExchangeData: extension.Data[keyShareCursor+4 : keyShareCursor+4+int(keyExchangeDataLength)],
				}
				clientShares = append(clientShares, clientShare)
				logger.Printf("    Group: %s (%x)\n", NamedGroupName[NamedGroup(group)], group)
				logger.Printf("    Length: %d\n", keyExchangeDataLength)
				logger.Printf("    KeyExchangeData: %x\n", clientShare.KeyExchangeData)
				keyShareCursor += 4 + int(keyExchangeDataLength)
			}
			extensionMap[KeyShareExtensionType] = KeyShareExtension{
				Length:       length,
				ClientShares: clientShares,
			}
		case ExtendedMasterSecretExtensionType:
			logger.Printf("  ExtendedMasterSecretExtension (%x)\n", extension.ExtensionType)
		case SupportedVersionsExtensionType:
			// https://tex2e.github.io/rfc-translater/html/rfc8446.html#4-2-1--Supported-Versions
			logger.Printf("  SupportedVersionsExtension (%x)\n", extension.ExtensionType)
			length := uint8(extension.Data[0])
			versions := []ProtocolVersion{}
			for i := 0; i < int(length); i += 2 {
				version := binary.BigEndian.Uint16(extension.Data[1+i : 1+i+2])
				versions = append(versions, ProtocolVersion(version))
				logger.Printf("    Version: %s (%x)\n", ProtocolVersionName[ProtocolVersion(version)], version)
			}
			extensionMap[SupportedVersionsExtensionType] = ClientSupportedVersionsExtension{
				SelectedVersions: versions,
			}
		case PSKKeyExchangeModesExtensionType:
			logger.Printf("  PSKKeyExchangeModesExtension (%x)\n", extension.ExtensionType)
			length := uint8(extension.Data[0])
			keModes := []PSKKeyExchangeMode{}
			for i := 0; i < int(length); i++ {
				keMode := PSKKeyExchangeMode(extension.Data[1+i])
				keModes = append(keModes, PSKKeyExchangeMode(keMode))
				logger.Printf("    PSKKeyExchangeMode: %s (%x)\n", PSKKeyExchangeModeName[PSKKeyExchangeMode(keMode)], keMode)
			}
			extensionMap[PSKKeyExchangeModesExtensionType] = PSKKeyExchangeModesExtension{
				Length:  length,
				KEModes: keModes,
			}
		case EncryptThenMacExtensionType:
			// https://tex2e.github.io/rfc-translater/html/rfc7366.html
			logger.Printf("  EncryptThenMacExtension (%x)\n", extension.ExtensionType)
		case SessionTicketExtensionType:
			logger.Println("  SessionTicketExtension")
		case RecordSizeLimitExtensionType:
			logger.Printf("  RecordSizeLimitExtension (%x)\n", extension.ExtensionType)
			logger.Printf("    RecordSizeLimit: %d bytes\n", binary.BigEndian.Uint16(extension.Data))
			extensionMap[RecordSizeLimitExtensionType] = RecordSizeLimitExtension(binary.BigEndian.Uint16(extension.Data))
		case RenegotiationInfoExtensionType:
			logger.Printf("  RenegotiationInfoExtension (%x)\n", extension.ExtensionType)
			length := uint8(extension.Data[0])
			if length > 0 {
				extensionMap[RenegotiationInfoExtensionType] = RenegotiationInfoExtension{
					Length:                 length,
					RegegotiatedConnection: extension.Data[1:length],
				}
				logger.Printf("    Renegotiated Connection: %x\n", extension.Data[1:])
			}
		default:
			logger.Printf("  Extension data: %x\n", extension)
		}
	}
	return extensionMap
}

// NewTLSCipherMessageText creates a TLS Record (ApplicationData) with encryption
func NewTLSCipherMessageText(key, iv []byte, plaintext TLSInnerPlainText, sequenceNumber uint64) (*TLSRecord, error) {
	encryptedRecord, err := EncryptTLSInnerPlaintext(key, iv, plaintext.Bytes(), sequenceNumber)
	if err != nil {
		return nil, err
	}
	return &TLSRecord{
		ContentType:         ApplicationDataRecord,
		LegacyRecordVersion: TLS12,
		Length:              uint16(len(encryptedRecord)),
		Fragment:            encryptedRecord,
	}, nil
}

func (t TLSRecord) Bytes() []byte {
	return append([]byte{
		byte(uint8(t.ContentType)),
		byte(uint8(t.LegacyRecordVersion >> 8)),
		byte(uint8(t.LegacyRecordVersion)),
		byte(uint8(t.Length >> 8)),
		byte(uint8(t.Length)),
	}, t.Fragment...)
}

// GenerateSecrets generates the various shared secrets used for key derivation
func GenerateSecrets(hash func() hash.Hash, curve ecdh.Curve, clientPublicKeyBytes []byte, serverPrivateKey *ecdh.PrivateKey) (*Secrets, error) {
	// Shared secret (Pre-master Secret)
	clientPublicKey, err := curve.NewPublicKey(clientPublicKeyBytes)
	if err != nil {
		return nil, err
	}
	sharedSecret, err := serverPrivateKey.ECDH(clientPublicKey)
	if err != nil {
		return nil, err
	}

	// Early Secret
	zero32 := make([]byte, hash().Size())
	earlySecret := hkdf.Extract(hash, zero32, zero32)

	secretState, err := DeriveSecret(hash, earlySecret, "derived", [][]byte{})
	if err != nil {
		return nil, err
	}
	handshakeSecret := hkdf.Extract(hash, sharedSecret, secretState)

	secretState, err = DeriveSecret(hash, handshakeSecret, "derived", [][]byte{})
	if err != nil {
		return nil, err
	}
	masterSecret := hkdf.Extract(hash, zero32, secretState)
	return &Secrets{
		Hash:            hash,
		SharedSecret:    sharedSecret,
		EarlySecret:     earlySecret,
		HandshakeSecret: handshakeSecret,
		MasterSecret:    masterSecret,
	}, nil
}

// HandshakeTrafficKeys generates the handshake traffic keys used in handshake messages encryption
func (s *Secrets) HandshakeTrafficKeys(clientHello []byte, serverHello []byte, keyLength int, ivLength int) (*HandshakeTrafficSecrets, error) {
	clientHandshakeTrafficSecret, err := DeriveSecret(s.Hash, s.HandshakeSecret, "c hs traffic", [][]byte{clientHello, serverHello})
	if err != nil {
		return nil, err
	}

	serverHandshakeTrafficSecret, err := DeriveSecret(s.Hash, s.HandshakeSecret, "s hs traffic", [][]byte{clientHello, serverHello})
	if err != nil {
		return nil, err
	}

	serverWriteKey, err := HKDFExpandLabel(s.Hash, serverHandshakeTrafficSecret, "key", []byte{}, keyLength)
	if err != nil {
		return nil, err
	}
	serverWriteIV, err := HKDFExpandLabel(s.Hash, serverHandshakeTrafficSecret, "iv", []byte{}, ivLength)
	if err != nil {
		return nil, err
	}
	clientWriteKey, err := HKDFExpandLabel(s.Hash, clientHandshakeTrafficSecret, "key", []byte{}, keyLength)
	if err != nil {
		return nil, err
	}
	clientWriteIV, err := HKDFExpandLabel(s.Hash, clientHandshakeTrafficSecret, "iv", []byte{}, ivLength)
	if err != nil {
		return nil, err
	}
	return &HandshakeTrafficSecrets{
		ClientHandshakeTrafficSecret:   clientHandshakeTrafficSecret,
		ServerHandshakeTrafficSecret:   serverHandshakeTrafficSecret,
		ClientApplicationTrafficSecret: nil,
		ServerApplicationTrafficSecret: nil,
		ServerWriteKey:                 serverWriteKey,
		ServerWriteIV:                  serverWriteIV,
		ClientWriteKey:                 clientWriteKey,
		ClientWriteIV:                  clientWriteIV,
	}, nil
}

// ApplicationTrafficKeys generates the application traffic keys used in application data encryption
func (s *Secrets) ApplicationTrafficKeys(
	clientHello []byte,
	serverHello []byte,
	encryptedExtensions []byte,
	certificate []byte,
	certificateVerify []byte,
	serverFinished []byte,
	keyLength int,
	ivLength int,
) (*ApplicationTrafficSecrets, error) {
	messages := [][]byte{clientHello, serverHello, encryptedExtensions, certificate, certificateVerify, serverFinished}
	clientApplicationTrafficSecret, err := DeriveSecret(s.Hash, s.MasterSecret, "c ap traffic", messages)
	if err != nil {
		return nil, err
	}

	serverApplicationTrafficSecret, err := DeriveSecret(s.Hash, s.MasterSecret, "s ap traffic", messages)
	if err != nil {
		return nil, err
	}

	serverWriteKey, err := HKDFExpandLabel(s.Hash, serverApplicationTrafficSecret, "key", []byte{}, keyLength)
	if err != nil {
		return nil, err
	}
	serverWriteIV, err := HKDFExpandLabel(s.Hash, serverApplicationTrafficSecret, "iv", []byte{}, ivLength)
	if err != nil {
		return nil, err
	}
	clientWriteKey, err := HKDFExpandLabel(s.Hash, clientApplicationTrafficSecret, "key", []byte{}, keyLength)
	if err != nil {
		return nil, err
	}
	clientWriteIV, err := HKDFExpandLabel(s.Hash, clientApplicationTrafficSecret, "iv", []byte{}, ivLength)
	if err != nil {
		return nil, err
	}
	return &ApplicationTrafficSecrets{
		ClientApplicationTrafficSecret: clientApplicationTrafficSecret,
		ServerApplicationTrafficSecret: serverApplicationTrafficSecret,
		ClientWriteKey:                 clientWriteKey,
		ClientWriteIV:                  clientWriteIV,
		ServerWriteKey:                 serverWriteKey,
		ServerWriteIV:                  serverWriteIV,
	}, nil
}

// calculateNonce calculates the nonce used in AEAD
func calculateNonce(iv []byte, sequenceNumber uint64) []byte {
	sequenceNumberBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(sequenceNumberBytes, sequenceNumber)
	paddedSequenceNumber := make([]byte, len(iv))
	copy(paddedSequenceNumber[len(iv)-8:], sequenceNumberBytes)
	nonce := make([]byte, len(iv))
	for i := range iv {
		nonce[i] = paddedSequenceNumber[i] ^ iv[i]
	}
	return nonce
}

// EncryptTLSInnerPlaintext encrypts the TLS Inner Plaintext with AES-128-GCM-SHA256
func EncryptTLSInnerPlaintext(key, iv []byte, tlsInnerPlainText []byte, sequenceNumber uint64) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// TLS Record header is used as an AEAD
	tlsCipherTextLength := len(tlsInnerPlainText) + aesgcm.Overhead()
	encrypted := aesgcm.Seal(nil, calculateNonce(iv, sequenceNumber), tlsInnerPlainText, []byte{
		byte(ApplicationDataRecord),          // 0x17
		byte(TLS12 >> 8), byte(TLS12 & 0xff), // 0x0303
		byte(tlsCipherTextLength >> 8), byte(tlsCipherTextLength),
	})
	return encrypted, nil
}

// DecryptTLSInnerPlaintext decrypts the TLS Inner Plaintext with AES-128-GCM-SHA256
func DecryptTLSInnerPlaintext(key, iv []byte, encryptedTLSInnerPlainText []byte, sequenceNumber uint64, tlsHeader []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aesgcm.Open(nil, calculateNonce(iv, sequenceNumber), encryptedTLSInnerPlainText, tlsHeader)
}

// SignCertificate signs the server certificate with the corresponding private key.
// certificate is included in the handshake messages used for the calculation of Transcript-Hash
func SignCertificate(hash func() hash.Hash, priv crypto.PrivateKey, handshakeMessages [][]byte) ([]byte, error) {
	signatureTarget := bytes.Repeat([]byte{0x20}, 64)
	signatureTarget = append(signatureTarget, []byte("TLS 1.3, server CertificateVerify")...)
	signatureTarget = append(signatureTarget, 0x00) // separator
	signatureTarget = append(signatureTarget, TranscriptHash(hash, handshakeMessages)...)

	switch privKey := priv.(type) {
	case ed25519.PrivateKey:
		// For Ed25519, the hashing is done internally, so we directly pass the message to be signed.
		return ed25519.Sign(privKey, signatureTarget), nil
	case *ecdsa.PrivateKey:
		hashed := sha256.Sum256(signatureTarget)
		return ecdsa.SignASN1(rand.Reader, privKey, hashed[:])
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", priv)
	}
}

// NewServerHello creates a new ServerHelloMessage with TLS1.3 and selected ECDH public key
func NewServerHello(publicKey *ecdh.PublicKey, namedGroup NamedGroup, cipherSuite CipherSuite, sessionID []byte) (ServerHelloMessage, error) {
	randomData := make([]byte, 32)
	_, err := rand.Read(randomData)
	if err != nil {
		return ServerHelloMessage{}, err
	}

	publicKeyBytes := publicKey.Bytes()
	keyShareExtension := KeyShareExtension{
		Length: 2 + 2 + uint16(len(publicKeyBytes)),
		ClientShares: []KeyShareEntry{
			{
				Group:           namedGroup,
				Length:          uint16(len(publicKeyBytes)),
				KeyExchangeData: publicKeyBytes,
			},
		},
	}

	return ServerHelloMessage{
		LegacyVersion:     TLS12,
		RandomBytes:       [32]byte(randomData),
		SessionID:         sessionID,
		CipherSuite:       cipherSuite,
		CompressionMethod: 0x00,
		Extensions: []Extension{
			{
				ExtensionType: SupportedVersionsExtensionType,
				Length:        2,
				Data:          []byte{byte(TLS13 >> 8), byte(TLS13 & 0xff)}, // 0x0304
			},
			{
				ExtensionType: KeyShareExtensionType,
				Length:        keyShareExtension.Length,
				Data:          keyShareExtension.Bytes(),
			},
		},
	}, nil
}

// NewFinishedMessage creates a new FinishedMessage with HMAC
func NewFinishedMessage(hash func() hash.Hash, baseKey []byte, handshakeMessages [][]byte) (FinishedMessage, error) {
	finishedKey, err := HKDFExpandLabel(hash, baseKey, "finished", []byte{}, hash().Size())
	if err != nil {
		return FinishedMessage{}, err
	}
	h := hmac.New(hash, finishedKey)
	h.Write(TranscriptHash(hash, handshakeMessages))
	return FinishedMessage{
		VerifyData: h.Sum(nil),
	}, nil
}
