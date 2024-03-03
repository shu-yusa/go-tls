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
		SharedSecret:    MustDecode("84547ccc951b8463bd19e3b43fb917ea085bdab53d86cf789039262a52c2571a"),
		EarlySecret:     MustDecode("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"),
		HandshakeSecret: MustDecode("0eb67f9bc70b713d4d2f06b0485cadb0110e444b6bf4e8211d65815a117e73d1"),
		MasterSecret:    MustDecode("d1f3f24db619e509fead5b327a2aa3de329b0179d51f75c0bbd2ab8eae30adef"),
	},
	TrafficSecrets: HandshakeTrafficSecrets{
		ClientHandshakeTrafficSecret: MustDecode("2dd54ea21937d22ba3e62441a9220f6fc47a7cec4bf8ddf5bf136c640e3fe99d"),
		ServerHandshakeTrafficSecret: MustDecode("338e51631255743005854fe629a9342d61f81f70d61f32a0226989259cba47c9"),
		ServerWriteKey:               MustDecode("d5d344810a4b11ab92368221a4007c16"),
		ServerWriteIV:                MustDecode("7f4bf54be5428b34d7afc719"),
		ClientWriteKey:               MustDecode("ff9f63964e2176fd30878d6a3debce49"),
		ClientWriteIV:                MustDecode("1fe240cc6c5271dfdd3abec1"),
	},
	ApplicationTrafficSecrets: ApplicationTrafficSecrets{
		ClientApplicationTrafficSecret: MustDecode("2fb5535fbb08b8390db10669088572a4c66773fccab20208055f7dff10577895"),
		ServerApplicationTrafficSecret: MustDecode("afd0f7c94379336c93764c010e9076454dca79628c829ae70581b7f060a82e9d"),
		ServerWriteKey:                 MustDecode("4331d9730843b7f30f54b373a501be40"),
		ServerWriteIV:                  MustDecode("608ee951d7c102890a8ca827"),
		ClientWriteKey:                 MustDecode("18f5248a8739ba395de3390027504062"),
		ClientWriteIV:                  MustDecode("d0adff51e86efa8d68248c90"),
	},
	HandshakeClientHello: MustDecode("010000cc0303e3d8e3d035e072cc92ad27fe9894fb4e3347de42c8948e8981cc00f4a30f6bef20e98b044b8da60b0bddc605c9b10bfe9a49600ae0d99b4834b11231d3cab8ceb600061302130313010100007d000b000403000102000a00060004001d0017002300000016000000170000000d0024002204030503060308070808081a081b081c0809080a080b080408050806040105010601002b0003020304002d00020101003300260024001d00201cb41c6a028a11eac1c5a18b4fb481b55fa68d52b55dd2934d7eb43d502bc92f"),
	HandshakeServerHello: MustDecode("020000760303a96a59e3b6eeb8a4c552fec7668154927d9ba8bc97dc54403103226594ae00f620523093b10bec1a1e776fd5c3e902c6090a31e3e3e119bf96899a767f96645fd3130100002e002b0002030400330024001d00208389cfcf51140d4d9caf771dd561aa4dc738f422af2bc39e384ef9185bc4df71"),
	HandshakeCertificate: MustDecode("0000023400022f3082022b308201d1a00302010202141201645ef6823f4840c193bbb2c471d8fd10b0c8300a06082a8648ce3d040302306b310b3009060355040613024a50310e300c06035504080c05546f6b796f310e300c06035504070c05546f6b796f31173015060355040a0c0e4d794f7267616e697a6174696f6e310f300d060355040b0c064d79556e69743112301006035504030c096c6f63616c686f7374301e170d3234303232363134343633385a170d3235303232353134343633385a306b310b3009060355040613024a50310e300c06035504080c05546f6b796f310e300c06035504070c05546f6b796f31173015060355040a0c0e4d794f7267616e697a6174696f6e310f300d060355040b0c064d79556e69743112301006035504030c096c6f63616c686f73743059301306072a8648ce3d020106082a8648ce3d0301070342000467ec6f356ccce9daee9663d382fae0187a6e46165700f3a08702f50fb8384bc614adb82502b676cfd072e403f96762c14e42ef4a0dd802d0b65db0e916b6fd79a3533051301d0603551d0e0416041449349cd96432009a5d6b1169c5323b8c7ef3a5b3301f0603551d2304183016801449349cd96432009a5d6b1169c5323b8c7ef3a5b3300f0603551d130101ff040530030101ff300a06082a8648ce3d040302034800304502206e84a3bb255a93e9ceb511fbd76a5cb031b61fcbcbf35e6920f54c188421ec11022100ec66226beece88f1b733594e358bddac08e0b9e0d411a611cf0ec6eb36dba4730000"),
}
