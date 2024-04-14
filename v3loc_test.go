package paseto

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestV3Loc_Encrypt(t *testing.T) {
	t.Skip()
	testCases := loadGoldenFile("testdata/v3.json")

	for _, tc := range testCases.Tests {
		if tc.Key == "" || !strings.HasPrefix(tc.Token, v3locHeader) {
			continue
		}

		t.Run(tc.Name, func(t *testing.T) {
			key := mustHex(tc.Key)
			payload := mustJSON(tc.Payload)
			footer := mustJSON(tc.Footer)
			imp := tc.ImplicitAssertion
			nonce := mustHex(tc.Nonce)

			token, err := V3Encrypt(key, payload, footer, imp, nonce)
			if err != nil {
				t.Fatal(err)
			}
			mustEqual(t, token, tc.Token)
		})
	}
}

func TestV3Loc_Decrypt(t *testing.T) {
	t.Skip()
	testCases := loadGoldenFile("testdata/v3.json")

	for _, tc := range testCases.Tests {
		if tc.Key == "" || !strings.HasPrefix(tc.Token, v3locHeader) {
			continue
		}

		t.Run(tc.Name, func(t *testing.T) {
			imp := tc.ImplicitAssertion
			key := must(hex.DecodeString(tc.Key))
			var payload, footer any

			err := V3Decrypt(tc.Token, key, payload, footer, imp)
			mustOk(t, err)
		})
	}
}
