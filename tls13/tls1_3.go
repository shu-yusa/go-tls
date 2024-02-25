package tls13

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"

	"golang.org/x/crypto/hkdf"
)

type (
	HandshakeEncoder interface {
		Bytes() []byte
	}

	ContentType      uint8 // Record protocol
	ProtocolVersion  uint16
	HandshakeType    uint8
	ExtensionType    uint16
	CertificateType  uint8
	AlertLevel       uint8
	AlertDescription uint8

	CipherSuite        uint16
	NamedGroup         uint16
	SignatureScheme    uint16
	PSKKeyExchangeMode uint8

	// Either of TLSPlainText or TLSCipherMessageText
	TLSRecord struct {
		contentType         ContentType
		legacyRecordVersion ProtocolVersion
		length              uint16
		fragment            []byte
	}

	// TLS Record used as a payload for encryption
	TLSInnerPlainText struct {
		content     []byte
		contentType ContentType // real content type
		zeros       []byte      // padding
	}

	Handshake[T HandshakeEncoder] struct {
		msgType          HandshakeType
		length           uint32
		handshakeMessage T
	}
	ApplicationData struct {
		data []byte
	}
	Alert struct {
		level       AlertLevel
		description AlertDescription
	}

	// HandshakeEncoder
	ClientHelloMessage struct {
		legacyVersion           ProtocolVersion
		random                  []byte
		legacySessionID         []byte
		cipherSuites            []CipherSuite
		legacyCompressionMethod []byte
		extensions              []Extension
	}
	ServerHelloMessage struct {
		legacyVersion     ProtocolVersion
		randomBytes       [32]byte
		sessionID         []byte
		cipherSuite       CipherSuite
		compressionMethod uint8
		extensions        []Extension
	}
	EncryptedExtensionsMessage struct {
		extensions []Extension
	}
	CertificateMessage struct {
		certificateRequestContext []byte
		certificateList           []CertificateEntry
	}
	CertificateVerifyMessage struct {
		algorithm SignatureScheme
		signature []byte
	}
	FinishedMessage struct {
		verifyData []byte
	}

	Extension struct {
		extensionType ExtensionType
		length        uint16
		data          []byte
	}

	ClientSupportedVersionsExtension struct {
		selectedVersions []ProtocolVersion
	}

	SupportedPointFormatsExtension struct {
		length         uint8
		ecPointFormats []uint8
	}

	PSKKeyExchangeModesExtension struct {
		length  uint8
		keModes []PSKKeyExchangeMode
	}

	SupportedGroupExtension struct {
		length         uint16
		namedGroupList []NamedGroup
	}

	SignatureAlgorithmsExtension struct {
		length                       uint16
		supportedSignatureAlgorithms []SignatureScheme
	}

	KeyShareEntry struct {
		group           NamedGroup
		length          uint16
		keyExchangeData []byte
	}

	KeyShareExtension struct {
		length       uint16
		clientShares []KeyShareEntry
	}

	HKDFLabel struct {
		length  uint16
		label   string
		context []byte
	}

	Secrets struct {
		hash            func() hash.Hash
		sharedSecret    []byte
		earlySecret     []byte
		handshakeSecret []byte
		masterSecret    []byte
	}

	TrafficSecrets struct {
		clientHandshakeTrafficSecret   []byte
		serverHandshakeTrafficSecret   []byte
		clientApplicationTrafficSecret []byte
		serverApplicationTrafficSecret []byte
		serverWriteKey                 []byte
		serverWriteIV                  []byte
		clientWriteKey                 []byte
		clientWriteIV                  []byte
	}

	ApplicationTrafficSecrets struct {
		clientApplicationTrafficSecret []byte
		serverApplicationTrafficSecret []byte
		clientWriteKey                 []byte
		clientWriteIV                  []byte
		serverWriteKey                 []byte
		serverWriteIV                  []byte
	}

	CertificateEntry struct {
		certType CertificateType
		certData []byte
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
	SupportedCurves = map[NamedGroup]ecdh.Curve{
		secp256r1: ecdh.P256(),
		x25519:    ecdh.X25519(),
	}

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
)

func (ks KeyShareExtension) selectECDHKeyShare() (*KeyShareEntry, ecdh.Curve) {
	supportedCurves := map[NamedGroup]ecdh.Curve{
		secp256r1: ecdh.P256(),
		x25519:    ecdh.X25519(),
	}
	for _, clientShare := range ks.clientShares {
		curve, ok := supportedCurves[clientShare.group]
		if ok {
			return &clientShare, curve
		}
	}
	return nil, nil
}

func (t TLSInnerPlainText) Bytes() []byte {
	return append(append(t.content, byte(t.contentType)), t.zeros...)
}

func (hs Handshake[T]) Bytes() []byte {
	return append([]byte{
		byte(uint8(hs.msgType)),
		byte(uint8(hs.length >> 16)),
		byte(uint8(hs.length >> 8)),
		byte(uint8(hs.length)),
	}, hs.handshakeMessage.Bytes()...)
}

func (sh ServerHelloMessage) Bytes() []byte {
	serverHello := []byte{}
	serverHello = append(serverHello, byte(uint8(sh.legacyVersion>>8)))
	serverHello = append(serverHello, byte(uint8(sh.legacyVersion)))
	serverHello = append(serverHello, sh.randomBytes[:]...)
	serverHello = append(serverHello, byte(uint8(len(sh.sessionID))))
	serverHello = append(serverHello, sh.sessionID...)
	serverHello = append(serverHello, byte(uint8(sh.cipherSuite>>8)))
	serverHello = append(serverHello, byte(uint8(sh.cipherSuite)))
	serverHello = append(serverHello, sh.compressionMethod)

	extensionBytes := []byte{}
	for _, extension := range sh.extensions {
		extensionBytes = append(extensionBytes, extension.Bytes()...)
	}

	extensionLength := len(extensionBytes)
	serverHello = append(serverHello, byte(uint8(extensionLength>>8)))
	serverHello = append(serverHello, byte(uint8(extensionLength)))
	return append(serverHello, extensionBytes...)
}

func (e Extension) Bytes() []byte {
	return append([]byte{
		byte(uint8(e.extensionType >> 8)),
		byte(uint8(e.extensionType)),
		byte(uint8(e.length >> 8)),
		byte(uint8(e.length)),
	}, e.data...)
}

func (ee EncryptedExtensionsMessage) Bytes() []byte {
	extensionsBytes := []byte{}
	for _, extension := range ee.extensions {
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
	for _, clientShare := range kse.clientShares {
		extension = append([]byte{
			byte(uint8(clientShare.group >> 8)),
			byte(uint8(clientShare.group)),
			byte(uint8(clientShare.length >> 8)),
			byte(uint8(clientShare.length)),
		}, clientShare.keyExchangeData...)
	}
	return extension
}

func (l HKDFLabel) Bytes() []byte {
	label := []byte{}
	label = append(label, byte(uint8(l.length>>8)))
	label = append(label, byte(uint8(l.length)))

	labelBytes := []byte(l.label)
	label = append(label, byte(len(labelBytes)))
	label = append(label, labelBytes...)

	label = append(label, byte(len(l.context)))
	return append(label, l.context...)
}

func (ce CertificateEntry) Bytes() []byte {
	certEntry := []byte{}
	length := len(ce.certData)
	certEntry = append(certEntry, byte(length>>16), byte(length>>8), byte(length))
	certEntry = append(certEntry, ce.certData...)
	certEntry = append(certEntry, 0, 0) // extensions
	return certEntry
}

func (c CertificateMessage) Bytes() []byte {
	cert := []byte{}
	// 1 byte for the length of the certificate_request_context
	cert = append(cert, byte(len(c.certificateRequestContext)))
	cert = append(cert, c.certificateRequestContext...)

	entryBytes := []byte{}
	for _, entry := range c.certificateList {
		entryBytes = append(entryBytes, entry.Bytes()...)
	}

	length := len(entryBytes)
	cert = append(cert, byte(length>>16), byte(length>>8), byte(length))
	return append(cert, entryBytes...)
}

func (c CertificateVerifyMessage) Bytes() []byte {
	return append([]byte{
		byte(uint8(c.algorithm >> 8)),
		byte(uint8(c.algorithm)),
		byte(len(c.signature) >> 8),
		byte(len(c.signature)),
	}, c.signature...)
}

func (f FinishedMessage) Bytes() []byte {
	return f.verifyData
}

func (a Alert) Bytes() []byte {
	return []byte{byte(a.level), byte(a.description)}
}

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
			extensionType: ExtensionType(binary.BigEndian.Uint16(extensionBuffer[cursor : cursor+2])),
			length:        length,
			data:          extensionBuffer[cursor+4 : cursor+4+int(length)],
		})
		// 4 bytes for Type and Length
		cursor += 4 + int(length)
	}
	return ClientHelloMessage{
		legacyVersion:           legacyVersion,
		random:                  random,
		legacySessionID:         legacySessionID,
		cipherSuites:            cipherSuites,
		legacyCompressionMethod: legacyCompressionMethod,
		extensions:              extensions,
	}
}

func (ch ClientHelloMessage) parseExtensions() map[ExtensionType]interface{} {
	var extensionMap = make(map[ExtensionType]interface{})
	for _, extension := range ch.extensions {
		switch extension.extensionType {
		case SupportedPointFormatsExtensionType:
			fmt.Println("- SupportedPointFormatsExtension")
			length := uint8(extension.data[0])
			var ECPointFormats []uint8
			for i := 0; i < int(length); i++ {
				ECPointFormat := uint8(extension.data[1+i])
				ECPointFormats = append(ECPointFormats, ECPointFormat)
				fmt.Printf("    ECPointFormat: %s (%x)\n", ECPointFormatName[ECPointFormat], ECPointFormat)
			}
			extensionMap[SupportedPointFormatsExtensionType] = SupportedPointFormatsExtension{
				length:         length,
				ecPointFormats: ECPointFormats,
			}
		case SupportedGroupsExtensionType:
			fmt.Println("- SupportedGroupsExtension")
			length := binary.BigEndian.Uint16(extension.data[0:2])
			var NamedGroupList []NamedGroup
			for i := 0; i < int(length); i += 2 {
				namedGroup := binary.BigEndian.Uint16(extension.data[2+i : 2+i+2])
				NamedGroupList = append(NamedGroupList, NamedGroup(namedGroup))
				fmt.Printf("    Named Group: %s (%x)\n", NamedGroupName[NamedGroup(namedGroup)], namedGroup)
			}
			extensionMap[SupportedGroupsExtensionType] = SupportedGroupExtension{
				length:         length,
				namedGroupList: NamedGroupList,
			}
		case SignatureAlgorithmsExtensionType:
			fmt.Println("- SignatureAlgorithmsExtension")
			length := binary.BigEndian.Uint16(extension.data[0:2])
			// fmt.Println("  SignatureAlgorithmsExtension length:", length)
			var signatureAlgorithms []SignatureScheme
			for i := 0; i < int(length); i += 2 {
				signatureScheme := binary.BigEndian.Uint16(extension.data[2+i : 2+i+2])
				signatureAlgorithms = append(signatureAlgorithms, SignatureScheme(signatureScheme))
				fmt.Printf("    Signature algorithm: %s (%x)\n", SignatureAlgorithmName[SignatureScheme(signatureScheme)], signatureScheme)
			}
			extensionMap[SignatureAlgorithmsExtensionType] = SignatureAlgorithmsExtension{
				length:                       length,
				supportedSignatureAlgorithms: signatureAlgorithms,
			}
		case KeyShareExtensionType:
			fmt.Println("- KeyShareExtension")
			length := binary.BigEndian.Uint16(extension.data[0:2])
			// fmt.Println("  KeyShareExtension length:", length)
			var clientShares []KeyShareEntry
			keyShareCursor := 2
			for keyShareCursor < int(length) {
				group := binary.BigEndian.Uint16(extension.data[keyShareCursor : keyShareCursor+2])
				keyExchangeDataLength := binary.BigEndian.Uint16(extension.data[keyShareCursor+2 : keyShareCursor+4])
				clientShare := KeyShareEntry{
					group:           NamedGroup(group),
					length:          keyExchangeDataLength,
					keyExchangeData: extension.data[keyShareCursor+4 : keyShareCursor+4+int(keyExchangeDataLength)],
				}
				clientShares = append(clientShares, clientShare)
				fmt.Printf("    Group: %s (%x)\n", NamedGroupName[NamedGroup(group)], group)
				fmt.Printf("    Length: %d\n", keyExchangeDataLength)
				fmt.Printf("    KeyExchangeData: %x\n", clientShare.keyExchangeData)
				keyShareCursor += 4 + int(keyExchangeDataLength)
			}
			extensionMap[KeyShareExtensionType] = KeyShareExtension{
				length:       length,
				clientShares: clientShares,
			}
		case ExtendedMasterSecretExtensionType:
			fmt.Println("- ExtendedMasterSecretExtension")
		case SupportedVersionsExtensionType:
			// https://tex2e.github.io/rfc-translater/html/rfc8446.html#4-2-1--Supported-Versions
			fmt.Println("- SupportedVersionsExtension")
			length := uint8(extension.data[0])
			versions := []ProtocolVersion{}
			for i := 0; i < int(length); i += 2 {
				version := binary.BigEndian.Uint16(extension.data[1+i : 1+i+2])
				versions = append(versions, ProtocolVersion(version))
				fmt.Printf("    Version: %s (%x)\n", ProtocolVersionName[ProtocolVersion(version)], version)
			}
			extensionMap[SupportedVersionsExtensionType] = ClientSupportedVersionsExtension{
				selectedVersions: versions,
			}
		case PSKKeyExchangeModesExtensionType:
			fmt.Println("- PSKKeyExchangeModesExtension")
			length := uint8(extension.data[0])
			keModes := []PSKKeyExchangeMode{}
			for i := 0; i < int(length); i++ {
				keMode := PSKKeyExchangeMode(extension.data[1+i])
				keModes = append(keModes, PSKKeyExchangeMode(keMode))
				fmt.Printf("    PSKKeyExchangeMode: %s (%x)\n", PSKKeyExchangeModeName[PSKKeyExchangeMode(keMode)], keMode)
			}
			extensionMap[PSKKeyExchangeModesExtensionType] = PSKKeyExchangeModesExtension{
				length:  length,
				keModes: keModes,
			}
		case EncryptThenMacExtensionType:
			// https://tex2e.github.io/rfc-translater/html/rfc7366.html
			fmt.Println("- EncryptThenMacExtension")
		case SessionTicketExtensionType:
			fmt.Println("- SessionTicketExtension")
		default:
			fmt.Printf("- Extension data: %x\n", extension)
			extensionMap[extension.extensionType] = extension.data
		}
	}
	return extensionMap
}

func NewTLSCipherMessageText(key, iv []byte, plaintext TLSInnerPlainText, sequenceNumber uint64) (*TLSRecord, error) {
	encryptedRecord, err := encryptTLSInnerPlaintext(key, iv, plaintext.Bytes(), sequenceNumber)
	if err != nil {
		return nil, err
	}
	return &TLSRecord{
		contentType:         ApplicationDataRecord,
		legacyRecordVersion: TLS12,
		length:              uint16(len(encryptedRecord)),
		fragment:            encryptedRecord,
	}, nil
}

func (t TLSRecord) Bytes() []byte {
	return append([]byte{
		byte(uint8(t.contentType)),
		byte(uint8(t.legacyRecordVersion >> 8)),
		byte(uint8(t.legacyRecordVersion)),
		byte(uint8(t.length >> 8)),
		byte(uint8(t.length)),
	}, t.fragment...)
}

func (s *Secrets) handshakeTrafficKeys(clientHello []byte, serverHello []byte, keyLength int, ivLength int) (*TrafficSecrets, error) {
	clientHandshakeTrafficSecret, err := DeriveSecret(s.hash, s.handshakeSecret, "c hs traffic", [][]byte{clientHello, serverHello})
	if err != nil {
		return nil, err
	}
	fmt.Printf("Client Handshake Traffic Secret: %x\n", clientHandshakeTrafficSecret)

	serverHandshakeTrafficSecret, err := DeriveSecret(s.hash, s.handshakeSecret, "s hs traffic", [][]byte{clientHello, serverHello})
	if err != nil {
		return nil, err
	}
	fmt.Printf("Server Handshake Traffic Secret: %x\n", serverHandshakeTrafficSecret)

	serverWriteKey, err := HKDFExpandLabel(s.hash, serverHandshakeTrafficSecret, "key", []byte{}, keyLength)
	if err != nil {
		return nil, err
	}
	serverWriteIV, err := HKDFExpandLabel(s.hash, serverHandshakeTrafficSecret, "iv", []byte{}, ivLength)
	if err != nil {
		return nil, err
	}
	clientWriteKey, err := HKDFExpandLabel(s.hash, clientHandshakeTrafficSecret, "key", []byte{}, keyLength)
	if err != nil {
		return nil, err
	}
	clientWriteIV, err := HKDFExpandLabel(s.hash, clientHandshakeTrafficSecret, "iv", []byte{}, ivLength)
	if err != nil {
		return nil, err
	}
	return &TrafficSecrets{
		clientHandshakeTrafficSecret:   clientHandshakeTrafficSecret,
		serverHandshakeTrafficSecret:   serverHandshakeTrafficSecret,
		clientApplicationTrafficSecret: nil,
		serverApplicationTrafficSecret: nil,
		serverWriteKey:                 serverWriteKey,
		serverWriteIV:                  serverWriteIV,
		clientWriteKey:                 clientWriteKey,
		clientWriteIV:                  clientWriteIV,
	}, nil
}

func (s *Secrets) applicationTrafficKeys(
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
	clientApplicationTrafficSecret, err := DeriveSecret(s.hash, s.masterSecret, "c ap traffic", messages)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Client Application Traffic Secret: %x\n", clientApplicationTrafficSecret)

	serverApplicationTrafficSecret, err := DeriveSecret(s.hash, s.masterSecret, "s ap traffic", messages)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Server Application Traffic Secret: %x\n", serverApplicationTrafficSecret)

	serverWriteKey, err := HKDFExpandLabel(s.hash, serverApplicationTrafficSecret, "key", []byte{}, keyLength)
	if err != nil {
		return nil, err
	}
	serverWriteIV, err := HKDFExpandLabel(s.hash, serverApplicationTrafficSecret, "iv", []byte{}, ivLength)
	if err != nil {
		return nil, err
	}
	clientWriteKey, err := HKDFExpandLabel(s.hash, clientApplicationTrafficSecret, "key", []byte{}, keyLength)
	if err != nil {
		return nil, err
	}
	clientWriteIV, err := HKDFExpandLabel(s.hash, clientApplicationTrafficSecret, "iv", []byte{}, ivLength)
	if err != nil {
		return nil, err
	}
	return &ApplicationTrafficSecrets{
		clientApplicationTrafficSecret: clientApplicationTrafficSecret,
		serverApplicationTrafficSecret: serverApplicationTrafficSecret,
		clientWriteKey:                 clientWriteKey,
		clientWriteIV:                  clientWriteIV,
		serverWriteKey:                 serverWriteKey,
		serverWriteIV:                  serverWriteIV,
	}, nil
}

func generateSecrets(hash func() hash.Hash, curve ecdh.Curve, clientPublicKeyBytes []byte, serverPrivateKey *ecdh.PrivateKey) (*Secrets, error) {
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
		hash:            hash,
		sharedSecret:    sharedSecret,
		earlySecret:     earlySecret,
		handshakeSecret: handshakeSecret,
		masterSecret:    masterSecret,
	}, nil
}

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

func encryptTLSInnerPlaintext(key, iv []byte, tlsInnerPlainText []byte, sequenceNumber uint64) ([]byte, error) {
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

func decryptTLSInnerPlaintext(key, iv []byte, encryptedTLSInnerPlainText []byte, sequenceNumber uint64, tlsHeader []byte) ([]byte, error) {
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

func signCertificate(priv *ecdsa.PrivateKey, handshakeMessages ...[]byte) ([]byte, error) {
	signatureTarget := bytes.Repeat([]byte{0x20}, 64)
	signatureTarget = append(signatureTarget, []byte("TLS 1.3, server CertificateVerify")...)
	signatureTarget = append(signatureTarget, 0x00) // separator
	signatureTarget = append(signatureTarget, TranscriptHash(sha256.New, handshakeMessages)...)

	hashed := sha256.Sum256(signatureTarget)
	signature, err := ecdsa.SignASN1(rand.Reader, priv, hashed[:])
	if err != nil {
		return nil, err
	}
	return signature, err
}

func NewServerHello(publicKey *ecdh.PublicKey, namedGroup NamedGroup, cipherSuite CipherSuite, sessionID []byte) (ServerHelloMessage, error) {
	randomData := make([]byte, 32)
	_, err := rand.Read(randomData)
	if err != nil {
		return ServerHelloMessage{}, err
	}

	publicKeyBytes := publicKey.Bytes()
	keyShareExtension := KeyShareExtension{
		length: 2 + 2 + uint16(len(publicKeyBytes)),
		clientShares: []KeyShareEntry{
			{
				group:           namedGroup,
				length:          uint16(len(publicKeyBytes)),
				keyExchangeData: publicKeyBytes,
			},
		},
	}

	return ServerHelloMessage{
		legacyVersion:     TLS12,
		randomBytes:       [32]byte(randomData),
		sessionID:         sessionID,
		cipherSuite:       cipherSuite,
		compressionMethod: 0x00,
		extensions: []Extension{
			{
				extensionType: SupportedVersionsExtensionType,
				length:        2,
				data:          []byte{byte(TLS13 >> 8), byte(TLS13 & 0xff)}, // 0x0304
			},
			{
				extensionType: KeyShareExtensionType,
				length:        keyShareExtension.length,
				data:          keyShareExtension.Bytes(),
			},
		},
	}, nil
}

func newFinishedMessage(hash func() hash.Hash, baseKey []byte, handshakeMessages ...[]byte) (FinishedMessage, error) {
	finishedKey, err := HKDFExpandLabel(hash, baseKey, "finished", []byte{}, hash().Size())
	if err != nil {
		return FinishedMessage{}, err
	}
	h := hmac.New(hash, finishedKey)
	h.Write(TranscriptHash(hash, handshakeMessages))
	return FinishedMessage{
		verifyData: h.Sum(nil),
	}, nil
}
