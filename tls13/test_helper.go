package tls13

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
)

func MustDecode(s string) []byte {
	bytes, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("MustDecode: decoding failed: %v", err))
	}
	return bytes
}

type FixedReader struct{}

func (fr *FixedReader) Read(b []byte) (n int, err error) {
	fixedStream := MustDecode("5275b57fa2e70b42f1f8d34fe388553522284a4746d07e1d0dd10190a6efe793")
	for i := range b {
		b[i] = fixedStream[i%len(fixedStream)]
	}
	return len(b), nil
}

// mockConn simulates net.Conn interface for testing.
type MockConn struct {
	net.Conn
	readBuffer bytes.Buffer
	writeCalls [][]byte
}

func (mc *MockConn) Read(b []byte) (n int, err error) {
	return mc.readBuffer.Read(b)
}

func (mc *MockConn) Write(b []byte) (n int, err error) {
	mc.writeCalls = append(mc.writeCalls, b)
	return
}

func (mc *MockConn) WriteCalls() [][]byte {
	return mc.writeCalls
}

var TestTLSContext = &TLSContext{
	Secrets: Secrets{
		Hash:            sha256.New,
		SharedSecret:    MustDecode("a1ae2074ecbee8242f94e1c00270d5ef18ff33e6b90e68c126a36c0e4af56c0a"),
		EarlySecret:     MustDecode("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"),
		HandshakeSecret: MustDecode("5e2fa8c452e2fd2bd95fa2c3de79e9dab1f74832cc56e572c0fcf6d356efe068"),
		MasterSecret:    MustDecode("c94e1355910e1e2e394eb34087681dd9f1d5037266f2b3ca715837902471fde3"),
	},
	HandshakeTrafficSecrets: HandshakeTrafficSecrets{
		ClientHandshakeTrafficSecret: MustDecode("6346f10b90c5f17ee16b0fbec3f050e742aabdf66e0f094e003093ff1b583a5e"),
		ServerHandshakeTrafficSecret: MustDecode("7e67f9df2aa1e9aa135fb7b6f3194befd08804e9a970462c7b8f67063331594c"),
		ServerWriteKey:               MustDecode("bd45cc665845090bfd5e41c5cb7741d3"),
		ServerWriteIV:                MustDecode("a5a474a93677923142c18305"),
		ClientWriteKey:               MustDecode("cf75ba0334ed12f6bf03b8ed0a9fad65"),
		ClientWriteIV:                MustDecode("91caeb9e3b14ac0d70fa5337"),
	},
	ApplicationTrafficSecrets: ApplicationTrafficSecrets{
		ClientApplicationTrafficSecret: MustDecode("76fd411a87c780a155ad9502bdcc82d267056ad322abc7bef55ce4d201b1cf98"),
		ServerApplicationTrafficSecret: MustDecode("14ddc2d4fd9762182ff77614efe34659fe4e1be6a8ba4fc4a4ee9d0cc4855495"),
		ServerWriteKey:                 MustDecode("c3c61ef8e670af2058cfa343066b2800"),
		ServerWriteIV:                  MustDecode("784980c4e57292c027ea95be"),
		ClientWriteKey:                 MustDecode("5722165ad0c81832de4f791f9b5d42b7"),
		ClientWriteIV:                  MustDecode("4b7fbbf5b3b718da4064dd4c"),
	},
	/*
		Legacy version: TLS 1.0 (301)
		Record length: 178

		Received TLS Handshake message (16)
		Handshake Type: ClientHello (1)
		Handshake message length: 174
		Legacy version: TLS 1.2 (303)
		Random: 9a73c24e48b9f8664367a21d32c496522662cc97dc1c3421ba84dac15a4b8aa5
		LegacySessionIDLength: 32
		LegacySessionID: 2aae6f5e1c56bb7d6dfa528943fffb412f7a915bc5ff4dd6e666ccde5d7090e1
		CipherSuites
		  CipherSuite: TLS_AES_256_GCM_SHA384 (1302)
		  CipherSuite: TLS_CHACHA20_POLY1305_SHA256 (1303)
		  CipherSuite: TLS_AES_128_GCM_SHA256 (1301)
		LegacyCompressionMethodLength: 1
		LegacyCompressionMethod: 00

		Extensions
		  SupportedPointFormatsExtension (b)
		    ECPointFormat: uncompressed (0)
		    ECPointFormat: ansiX962_compressed_prime (1)
		    ECPointFormat: ansiX962_compressed_char2 (2)
		  SupportedGroupsExtension (a)
		    Named Group: x25519 (1d)
		    Named Group: secp256r1 (17)
		  SessionTicketExtension
		  EncryptThenMacExtension (16)
		  ExtendedMasterSecretExtension (17)
		  SignatureAlgorithmsExtension (d)
		    Signature algorithm: ed25519 (807)
		    Signature algorithm: ecdsa_secp256r1_sha256 (403)
		  SupportedVersionsExtension (2b)
		    Version: TLS 1.3 (304)
		  PSKKeyExchangeModesExtension (2d)
		    PSKKeyExchangeMode: psk_dhe_ke (1)
		  KeyShareExtension (33)
		    Group: x25519 (1d)
		    Length: 32
		    KeyExchangeData: 4651cd20d664ed8fffc0b66937393b7ac05756a14158b383ab2bd0c9517f533c
	*/
	HandshakeClientHello: MustDecode("010000ae03039a73c24e48b9f8664367a21d32c496522662cc97dc1c3421ba84dac15a4b8aa5202aae6f5e1c56bb7d6dfa528943fffb412f7a915bc5ff4dd6e666ccde5d7090e100061302130313010100005f000b000403000102000a00060004001d0017002300000016000000170000000d0006000408070403002b0003020304002d00020101003300260024001d00204651cd20d664ed8fffc0b66937393b7ac05756a14158b383ab2bd0c9517f533c"),
	/*
		Selected curve: x25519 (1d)
		ECDH Server Private key: 5275b57fa2e70b42f1f8d34fe388553522284a4746d07e1d0dd10190a6efe793
		ECDH Server Public  key: 43fe9cb0fe774fdc70ebf8ba85a0853317643e583c0f1f25683f95445e85d878
	*/
	HandshakeServerHello: MustDecode("160303007a020000760303f8d1c73551b26bfa8cdff0788b2ebd56e41c1e998e814708be82ca27ed1dd5f7202aae6f5e1c56bb7d6dfa528943fffb412f7a915bc5ff4dd6e666ccde5d7090e1130100002e002b0002030400330024001d002043fe9cb0fe774fdc70ebf8ba85a0853317643e583c0f1f25683f95445e85d878"),
	/*
		EncryptedExtensions: 0000
		EncryptedExtensions Length: 2
	*/
	HandshakeEncryptedExtensions: MustDecode("0000"),
	/*
		Certificate: 0000023400022f3082022b308201d1a00302010202142c0d84a354e424a6fcbbb6c29acf4cda0ea229bc300a06082a8648ce3d040302306b310b3009060355040613024a50310e300c06035504080c05546f6b796f310e300c06035504070c05546f6b796f31173015060355040a0c0e4d794f7267616e697a6174696f6e310f300d060355040b0c064d79556e69743112301006035504030c096c6f63616c686f7374301e170d3234303330333032313630335a170d3235303330333032313630335a306b310b3009060355040613024a50310e300c06035504080c05546f6b796f310e300c06035504070c05546f6b796f31173015060355040a0c0e4d794f7267616e697a6174696f6e310f300d060355040b0c064d79556e69743112301006035504030c096c6f63616c686f73743059301306072a8648ce3d020106082a8648ce3d030107034200044cc45d61f9f6089905d84ed3fc949e60c1adab37bf9a5b68c236e97f2da68e6f974cb737a905bf70edee44c00e824c5cf3cf259a1ba2054d30ffd5f520517088a3533051301d0603551d0e0416041498d15af7dc532bedb6cebbb1a5fd77d004f57e96301f0603551d2304183016801498d15af7dc532bedb6cebbb1a5fd77d004f57e96300f0603551d130101ff040530030101ff300a06082a8648ce3d0403020348003045022100f0ece2961dc9299c01983ac7abe2a67d2e9cffa63b0c7beeb49de8dee61800780220178f4e1f3d47fe062a7f53760cb88d276eb8e38af36e2d83ade0304253d9e4a10000
		Certificate Length: 568
	*/
	HandshakeCertificate: MustDecode("0000023400022f3082022b308201d1a00302010202142c0d84a354e424a6fcbbb6c29acf4cda0ea229bc300a06082a8648ce3d040302306b310b3009060355040613024a50310e300c06035504080c05546f6b796f310e300c06035504070c05546f6b796f31173015060355040a0c0e4d794f7267616e697a6174696f6e310f300d060355040b0c064d79556e69743112301006035504030c096c6f63616c686f7374301e170d3234303330333032313630335a170d3235303330333032313630335a306b310b3009060355040613024a50310e300c06035504080c05546f6b796f310e300c06035504070c05546f6b796f31173015060355040a0c0e4d794f7267616e697a6174696f6e310f300d060355040b0c064d79556e69743112301006035504030c096c6f63616c686f73743059301306072a8648ce3d020106082a8648ce3d030107034200044cc45d61f9f6089905d84ed3fc949e60c1adab37bf9a5b68c236e97f2da68e6f974cb737a905bf70edee44c00e824c5cf3cf259a1ba2054d30ffd5f520517088a3533051301d0603551d0e0416041498d15af7dc532bedb6cebbb1a5fd77d004f57e96301f0603551d2304183016801498d15af7dc532bedb6cebbb1a5fd77d004f57e96300f0603551d130101ff040530030101ff300a06082a8648ce3d0403020348003045022100f0ece2961dc9299c01983ac7abe2a67d2e9cffa63b0c7beeb49de8dee61800780220178f4e1f3d47fe062a7f53760cb88d276eb8e38af36e2d83ade0304253d9e4a10000"),
	/*
		Signature: 304402201658b117a439cf26968a3fa0f6bbb4a9b8e65af9361f7a834aaeb2de2a7a7cb402205e88f6a899b261c3427ea40949160e138371e6dc5f508555f165c386114e3f01
		Signature length: 70
		Signature algorithm: ecdsa_secp256r1_sha256
		CertificateVerify: 04030046304402201658b117a439cf26968a3fa0f6bbb4a9b8e65af9361f7a834aaeb2de2a7a7cb402205e88f6a899b261c3427ea40949160e138371e6dc5f508555f165c386114e3f01
		CertificateVerify Length: 74
	*/
	HandshakeCertificateVerify: MustDecode("04030046304402201658b117a439cf26968a3fa0f6bbb4a9b8e65af9361f7a834aaeb2de2a7a7cb402205e88f6a899b261c3427ea40949160e138371e6dc5f508555f165c386114e3f01"),
	/*
		Finished: cb744a742062cd321617add0500166c8c00bb1a7f8d0129d3ac1908ab8f51d7b
		Finished Length: 32
	*/
	ServerFinished: MustDecode("cb744a742062cd321617add0500166c8c00bb1a7f8d0129d3ac1908ab8f51d7b"),
}

var AppData = "c7dccc7e39873f7588b0553de6777460ef4be40218820357d44332f81b4fccbc3b4378d3e031f833543d603d9a4e92635d9a06756b"
