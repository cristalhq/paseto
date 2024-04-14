package paseto

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestV1Loc_Encrypt(t *testing.T) {
	testCases := loadGoldenFile("testdata/v1.json")

	for _, tc := range testCases.Tests {
		if tc.Key == "" || !strings.HasPrefix(tc.Token, v1locHeader) {
			continue
		}

		t.Run(tc.Name, func(t *testing.T) {
			key := must(hex.DecodeString(tc.Key))
			payload := mustJSON(tc.Payload)
			footer := mustJSON(tc.Footer)
			nonce := must(hex.DecodeString(tc.Nonce))

			token, err := V1Encrypt(key, payload, footer, nonce)
			mustOk(t, err)
			mustEqual(t, token, tc.Token)
		})
	}
}

func TestV1Loc_Decrypt(t *testing.T) {
	testCases := loadGoldenFile("testdata/v1.json")

	for _, tc := range testCases.Tests {
		if tc.Key == "" || !strings.HasPrefix(tc.Token, v1locHeader) {
			continue
		}

		t.Run(tc.Name, func(t *testing.T) {
			key := must(hex.DecodeString(tc.Key))
			var payload, footer any

			err := V1Decrypt(tc.Token, key, payload, footer)
			mustOk(t, err)
		})
	}
}
