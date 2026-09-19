package tls13

import (
	"crypto/hkdf"
	"hash"
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

	return hkdf.Expand(hash, secret, string(hkdflabel.Bytes()), length)
}

func DeriveSecret(hash func() hash.Hash, secret []byte, label string, messages [][]byte) ([]byte, error) {
	return HKDFExpandLabel(hash, secret, label, TranscriptHash(hash, messages), hash().Size())
}

func RemoveZeroPaddingFromTail(data []byte) []byte {
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] != 0 {
			return data[:i+1]
		}
	}
	return nil
}
