package paseto

import (
	"testing"
)

func TestPAE(t *testing.T) {
	testCases := []struct {
		pieces [][]byte
		want   string
	}{
		{
			pieces: nil,
			want:   "\x00\x00\x00\x00\x00\x00\x00\x00",
		},
		{
			pieces: [][]byte{},
			want:   "\x00\x00\x00\x00\x00\x00\x00\x00",
		},
		{
			pieces: [][]byte{nil},
			want:   "\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		},
		{
			pieces: [][]byte{[]byte("test")},
			want:   "\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00test",
		},
	}

	for _, tc := range testCases {
		res := pae(tc.pieces...)
		have := string(res)

		if have != tc.want {
			t.Errorf("\nhave: %v\nwant: %v", have, tc.want)
		}
	}
}

func BenchmarkPAE(b *testing.B) {
	var nonce [32]byte
	var encryptedPayload [256]byte
	var footerBytes []byte

	pieces := [][]byte{
		[]byte(v1LocHeader),
		nonce[:],
		encryptedPayload[:],
		footerBytes,
	}

	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		res := pae(pieces...)
		if len(res) == 0 {
			b.Fatal()
		}
	}
}
