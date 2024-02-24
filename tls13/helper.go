package tls13

import (
	"hash"

	"golang.org/x/crypto/hkdf"
)

func TranscriptHash(hash func() hash.Hash, messages [][]byte) []byte {
	h := hash()
	for _, message := range messages {
		h.Write(message)
	}
	return h.Sum(nil)
}

func HKDFExpandLabel(hash func() hash.Hash, secret []byte, label string, content []byte, length int) ([]byte, error) {
	hkdflabel := HKDFLabel{
		Length:  uint16(length),
		Label:   "tls13 " + label,
		Context: content,
	}

	hkdfExpand := hkdf.Expand(hash, secret, hkdflabel.Bytes())
	derivedSecret := make([]byte, length)
	_, err := hkdfExpand.Read(derivedSecret)
	if err != nil {
		return nil, err
	}
	return derivedSecret, nil
}

func DeriveSecret(hash func() hash.Hash, secret []byte, label string, messages [][]byte) ([]byte, error) {
	return HKDFExpandLabel(hash, secret, label, TranscriptHash(hash, messages), hash().Size())
}
