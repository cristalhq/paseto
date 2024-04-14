package paseto

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestV2Loc_Encrypt(t *testing.T) {
	testCases := loadGoldenFile("testdata/v2.json")

	for _, tc := range testCases.Tests {
		if tc.Key == "" || !strings.HasPrefix(tc.Token, v2locHeader) {
			continue
		}

		t.Run(tc.Name, func(t *testing.T) {
			key := mustHex(tc.Key)
			payload := mustJSON(tc.Payload)
			footer := mustJSON(tc.Footer)
			nonce := mustHex(tc.Nonce)

			token, err := V2Encrypt(key, payload, footer, nonce)
			if err != nil {
				t.Fatal(err)
			}
			mustEqual(t, token, tc.Token)
		})
	}
}

func TestV2Loc_Decrypt(t *testing.T) {
	testCases := loadGoldenFile("testdata/v2.json")

	for _, tc := range testCases.Tests {
		if tc.Key == "" || !strings.HasPrefix(tc.Token, v2locHeader) {
			continue
		}

		t.Run(tc.Name, func(t *testing.T) {
			key := must(hex.DecodeString(tc.Key))
			var payload, footer any

			err := V2Decrypt(tc.Token, key, payload, footer)
			mustOk(t, err)
		})
	}
}
