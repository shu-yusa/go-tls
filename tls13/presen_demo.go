package tls13

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"log"
	"net"

	"golang.org/x/crypto/hkdf"
)

func TLSServer() {
	listener, _ := net.Listen("tcp", ":443")
	for {
		conn, _ := listener.Accept()
		go func(conn net.Conn) {
			// Read TLS record header
			tlsHeaderBuffer := make([]byte, 5)
			conn.Read(tlsHeaderBuffer)
			length := binary.BigEndian.Uint16(tlsHeaderBuffer[3:5])

			// Read TLS record payload
			payloadBuffer := make([]byte, length)
			io.ReadFull(conn, payloadBuffer)

			tlsRecord := &TLSRecord{
				ContentType:         ContentType(tlsHeaderBuffer[0]),
				LegacyRecordVersion: ProtocolVersion(binary.BigEndian.Uint16(tlsHeaderBuffer[1:3])),
				Length:              length,
				Fragment:            payloadBuffer,
			}
			// Handle TLS record
			switch tlsRecord.ContentType {
			case HandshakeRecord:
				msgType := HandshakeType(tlsRecord.Fragment[0])
				// extract 3 bytes
				handshakeLength :=
					(uint32(tlsRecord.Fragment[1]) << 16) |
						(uint32(tlsRecord.Fragment[2]) << 8) |
						uint32(tlsRecord.Fragment[3])
				switch msgType {
				case ClientHello: // 0x01
					clientHello := NewClientHello(tlsRecord.Fragment[4 : 4+handshakeLength])
					extensions := clientHello.ParseExtensions(&log.Logger{})
					keyShareExtension := extensions[KeyShareExtensionType].(KeyShareExtension)
					clientECDHPublicKey := keyShareExtension.ClientShares[0].KeyExchangeData // NamedGroup: x25519

					ecdhServerPrivateKey, _ := ecdh.P256().GenerateKey(rand.Reader)
					ecdhServerPublicKey := ecdhServerPrivateKey.PublicKey()
					randomData := make([]byte, 32)
					rand.Read(randomData)
					serverKeyShareExtension := KeyShareExtension{
						Length: 4 + uint16(len(ecdhServerPublicKey.Bytes())), // 4 bytes for NamedGroup, and Length
						ClientShares: []KeyShareEntry{
							{
								Group:           x25519,
								Length:          uint16(len(ecdhServerPublicKey.Bytes())),
								KeyExchangeData: ecdhServerPublicKey.Bytes(),
							},
						},
					}
					serverHello := ServerHelloMessage{
						LegacyVersion:     TLS12,
						RandomBytes:       [32]byte(randomData),
						SessionID:         clientHello.LegacySessionID,
						CipherSuite:       TLS_AES_128_GCM_SHA256,
						CompressionMethod: 0x00, // No compression
						Extensions: []Extension{
							{
								ExtensionType: SupportedVersionsExtensionType,
								Length:        2,
								Data:          []byte{byte(TLS13 >> 8), byte(TLS13 & 0xff)}, // 0x0304
							},
							{
								ExtensionType: KeyShareExtensionType,
								Length:        serverKeyShareExtension.Length,
								Data:          serverKeyShareExtension.Bytes(),
							},
						},
					}
					// Shared secret (Pre-master Secret)
					clientPublicKey, _ := ecdh.P256().NewPublicKey(keyShareExtension.ClientShares[0].KeyExchangeData)
					sharedSecret, _ := ecdhServerPrivateKey.ECDH(clientPublicKey)

					// Early Secret
					hash := sha256.New
					zero32 := make([]byte, hash().Size())
					earlySecret := hkdf.Extract(hash, zero32, zero32)

					secretState, _ := DeriveSecret(hash, earlySecret, "derived", [][]byte{})
					handshakeSecret := hkdf.Extract(hash, sharedSecret, secretState)

					secretState, _ = DeriveSecret(hash, handshakeSecret, "derived", [][]byte{})
					masterSecret := hkdf.Extract(hash, zero32, secretState)
					secrets := Secrets{
						Hash:            hash,
						SharedSecret:    sharedSecret,
						EarlySecret:     earlySecret,
						HandshakeSecret: handshakeSecret,
						MasterSecret:    masterSecret,
					}
				}
			}
		}(conn)
	}
}
