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

// mockConn simulates net.Conn interface for testing.
type MockConn struct {
	net.Conn
	readBuffer  bytes.Buffer
	writeBuffer bytes.Buffer
}

func (mc *MockConn) Read(b []byte) (n int, err error) {
	return mc.readBuffer.Read(b)
}

func (mc *MockConn) Write(b []byte) (n int, err error) {
	return mc.writeBuffer.Write(b)
}

var TestTLSContext = &TLSContext{
	Secrets: Secrets{
		Hash:            sha256.New,
		SharedSecret:    MustDecode("37d9e861c7aec3180b42a48813a6c307382b28326daee713300fec3c975ec24f"),
		EarlySecret:     MustDecode("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"),
		HandshakeSecret: MustDecode("215760a4deba82a0eb3c5683f5f8e41e71d5aa736a0a17df44d868168230fdc2"),
		MasterSecret:    MustDecode("d10990ea95a0178a36bfbae22729b5160445229d2e16312345abd8ebf5f7e2d2"),
	},
	TrafficSecrets: HandshakeTrafficSecrets{
		ClientHandshakeTrafficSecret: MustDecode("63a6425eba762c4d003500f615bffe6de372dc0be75756043e22e676d1541038"),
		ServerHandshakeTrafficSecret: MustDecode("1484c068784568ac29423ffc7bc31ab89a2b7c71dffb9fb20b62856f65cc9c10"),
		ServerWriteKey:               MustDecode("28a768daea8644687b912e1b3feda860"),
		ServerWriteIV:                MustDecode("d6c469be94d9605b2d49ff95"),
		ClientWriteKey:               MustDecode("450630f037b6778ec6f10a273f9aa70b"),
		ClientWriteIV:                MustDecode("079fac89677fb9ea91551997"),
	},
	ApplicationTrafficSecrets: ApplicationTrafficSecrets{
		ClientApplicationTrafficSecret: MustDecode("4d4bada40fbe94cda4ecdfc6120ee96a05b6b29ae2195f43cc2a198df3b747e4"),
		ServerApplicationTrafficSecret: MustDecode("ed9dbf00a4b1082ab7de5d1c02d287986024c82f89a13db2532d26b296e1ae55"),
		ServerWriteKey:                 MustDecode("44b4c6493fe4f2250578257378fb40d1"),
		ServerWriteIV:                  MustDecode("27a6a94a47337dd3ecbd1840"),
		ClientWriteKey:                 MustDecode("be1f995b5b4fb39d1132d595295e90a7"),
		ClientWriteIV:                  MustDecode("11b2cc16a0440f08b90b0538"),
	},
	HandshakeClientHello:         MustDecode("010000ae03034eb4265bd56bf0ac494162561aa121c23bd0fb0b65d3ebaa71dce62bfa488b3c20a1bbf8dfd458bab6df9d99a1b0076c41de7265cff6ec6a153252b84140eb05d600061302130313010100005f000b000403000102000a00060004001d0017002300000016000000170000000d0006000408070403002b0003020304002d00020101003300260024001d0020a3ebb24c8d3e398976d9443a06daccaefd51767f140485c74dd8e0ba6eed1673"),
	HandshakeServerHello:         MustDecode("160303007a020000760303fea8f7d6240458f4461796a2bf6ba9fca3bc95b3a42d224f38309c070604b5d320a1bbf8dfd458bab6df9d99a1b0076c41de7265cff6ec6a153252b84140eb05d6130100002e002b0002030400330024001d0020a5298ba9e1f9c693a91dd4dc69d98669c2eb78e4a4d4a0e6dd15804017a3431d"),
	HandshakeEncryptedExtensions: MustDecode("1703030017cab409f940ab51e875899daa275e6bbdf590eba0527835"),
	HandshakeCertificate:         MustDecode("0000023400022f3082022b308201d1a00302010202142c0d84a354e424a6fcbbb6c29acf4cda0ea229bc300a06082a8648ce3d040302306b310b3009060355040613024a50310e300c06035504080c05546f6b796f310e300c06035504070c05546f6b796f31173015060355040a0c0e4d794f7267616e697a6174696f6e310f300d060355040b0c064d79556e69743112301006035504030c096c6f63616c686f7374301e170d3234303330333032313630335a170d3235303330333032313630335a306b310b3009060355040613024a50310e300c06035504080c05546f6b796f310e300c06035504070c05546f6b796f31173015060355040a0c0e4d794f7267616e697a6174696f6e310f300d060355040b0c064d79556e69743112301006035504030c096c6f63616c686f73743059301306072a8648ce3d020106082a8648ce3d030107034200044cc45d61f9f6089905d84ed3fc949e60c1adab37bf9a5b68c236e97f2da68e6f974cb737a905bf70edee44c00e824c5cf3cf259a1ba2054d30ffd5f520517088a3533051301d0603551d0e0416041498d15af7dc532bedb6cebbb1a5fd77d004f57e96301f0603551d2304183016801498d15af7dc532bedb6cebbb1a5fd77d004f57e96300f0603551d130101ff040530030101ff300a06082a8648ce3d0403020348003045022100f0ece2961dc9299c01983ac7abe2a67d2e9cffa63b0c7beeb49de8dee61800780220178f4e1f3d47fe062a7f53760cb88d276eb8e38af36e2d83ade0304253d9e4a10000"),
	HandshakeCertificateVerify:   MustDecode("0403004730450221008ec1182ccb0515057ef8466ff191ffc5f44b7833f6460155905eff876ad8d01c022066f5dd0493d5fe26ea35115cd49974116484484be8a764d936b48a847032cba6"),
	ServerFinished:               MustDecode("77e32186b7bb3eb846440ce51efb2ebd4b30676743a1fe62b5c8b4d8db7ba594"),
}

var AppData = "c7dccc7e39873f7588b0553de6777460ef4be40218820357d44332f81b4fccbc3b4378d3e031f833543d603d9a4e92635d9a06756b"
