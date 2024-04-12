package paseto

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

type GoldenCases struct {
	Tests []GoldenCase `json:"tests"`
}

type GoldenCase struct {
	Name              string `json:"name"`
	ExpectFail        bool   `json:"expect-fail"`
	Nonce             string `json:"nonce"`
	Key               string `json:"key"`
	PublicKey         string `json:"public-key"`
	SecretKey         string `json:"secret-key"`
	SecretKeySeed     string `json:"secret-key-seed"`
	SecretKeyPem      string `json:"secret-key-pem"`
	PublicKeyPem      string `json:"public-key-pem"`
	Token             string `json:"token"`
	Payload           string `json:"payload"`
	Footer            string `json:"footer"`
	ImplicitAssertion string `json:"implicit-assertion"`
}

func loadGoldenFile(filename string) GoldenCases {
	f, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	var tc GoldenCases
	if err := json.NewDecoder(f).Decode(&tc); err != nil {
		panic(err)
	}
	return tc
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func mustHex(raw string) []byte {
	return must(hex.DecodeString(raw))
}

func mustJSON(raw string) any {
	if len(raw) == 0 || string(raw) == "" {
		return nil
	}
	var dst any
	if err := json.Unmarshal([]byte(raw), &dst); err != nil {
		return string(raw)
	}
	return dst
}

func mustOk(tb testing.TB, err error) {
	tb.Helper()
	if err != nil {
		tb.Fatal(err)
	}
}

func mustFail(tb testing.TB, err error) {
	tb.Helper()
	if err == nil {
		tb.Fatal()
	}
}

func mustEqual[T any](tb testing.TB, have, want T) {
	tb.Helper()
	if !reflect.DeepEqual(have, want) {
		tb.Fatalf("\nhave: %+v\nwant: %+v\n", have, want)
	}
}
