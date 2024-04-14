package paseto

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestV4Loc_Encrypt(t *testing.T) {
	testCases := loadGoldenFile("testdata/v4.json")

	for _, tc := range testCases.Tests {
		if tc.Key == "" || !strings.HasPrefix(tc.Token, v4locHeader) {
			continue
		}
		if strings.HasPrefix(tc.Name, "4-F-") {
			continue
		}

		t.Run(tc.Name, func(t *testing.T) {
			key := mustHex(tc.Key)
			payload := tc.Payload
			footer := tc.Footer
			imp := tc.ImplicitAssertion
			nonce := mustHex(tc.Nonce)

			token, err := V4Encrypt(key, payload, footer, imp, nonce)
			if tc.ExpectFail {
				mustFail(t, err)
			} else {
				mustOk(t, err)
				mustEqual(t, token, tc.Token)
			}
		})
	}
}

func TestV4Loc_Decrypt(t *testing.T) {
	testCases := loadGoldenFile("testdata/v4.json")

	for _, tc := range testCases.Tests {
		if tc.Key == "" || !strings.HasPrefix(tc.Token, v4locHeader) {
			continue
		}
		// TODO: (probably) should fail.
		if tc.Name == "4-F-4" {
			continue
		}

		t.Run(tc.Name, func(t *testing.T) {
			key := must(hex.DecodeString(tc.Key))
			var payload, footer string

			err := V4Decrypt(tc.Token, key, &payload, &footer, tc.ImplicitAssertion)
			if tc.ExpectFail {
				mustFail(t, err)
			} else {
				mustOk(t, err)
				mustEqual(t, payload, tc.Payload)
				mustEqual(t, footer, tc.Footer)
			}
		})
	}
}
