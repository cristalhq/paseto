package paseto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

func pae(pieces ...[]byte) []byte {
	size := 8
	for i := range pieces {
		size += 8 + len(pieces[i])
	}

	buf := make([]byte, size)
	binary.LittleEndian.PutUint64(buf, uint64(len(pieces)))

	idx := 8
	for i := range pieces {
		binary.LittleEndian.PutUint64(buf[idx:], uint64(len(pieces[i])))
		idx += 8

		copy(buf[idx:], pieces[i])
		idx += len(pieces[i])
	}
	return buf
}

func toBytes(x any) ([]byte, error) {
	switch v := x.(type) {
	case nil:
		return nil, nil
	case string:
		return []byte(v), nil
	case []byte:
		return v, nil
	default:
		return json.Marshal(v)
	}
}

func fromBytes(data []byte, x any) error {
	switch f := x.(type) {
	case *string:
		*f = string(data)
	case *[]byte:
		*f = append(*f, data...)
	default:
		if err := json.Unmarshal(data, x); err != nil {
			return fmt.Errorf("%w: %v", ErrDataUnmarshal, err)
		}
	}
	return nil
}

func splitToken(token, header string) ([]byte, []byte, error) {
	if !strings.HasPrefix(token, header) {
		return nil, nil, ErrIncorrectTokenHeader
	}

	parts := bytes.Split([]byte(token[len(header):]), []byte("."))

	var rawPayload, rawFooter []byte
	switch len(parts) {
	case 1:
		rawPayload = parts[0]
	case 2:
		rawPayload = parts[0]
		rawFooter = parts[1]
	default:
		return nil, nil, ErrIncorrectTokenFormat
	}

	payload := make([]byte, b64DecodedLen(len(rawPayload)))
	if _, err := b64Decode(payload, rawPayload); err != nil {
		return nil, nil, fmt.Errorf("decode payload: %w", err)
	}

	var footer []byte
	if rawFooter != nil {
		footer = make([]byte, b64DecodedLen(len(rawFooter)))
		if _, err := b64Decode(footer, rawFooter); err != nil {
			return nil, nil, fmt.Errorf("decode footer: %w", err)
		}
	}
	return payload, footer, nil
}

func buildToken(header, body, footer []byte) string {
	size := len(header) + b64EncodedLen(len(body))
	if len(footer) > 0 {
		size += 1 + b64EncodedLen(len(footer))
	}

	token := make([]byte, size)
	offset := 0
	offset += copy(token[offset:], header)

	b64Encode(token[offset:], body)
	offset += b64EncodedLen(len(body))

	if len(footer) > 0 {
		offset += copy(token[offset:], ".")
		b64Encode(token[offset:], footer)
	}
	return string(token)
}

func doHMACSHA384(key, b []byte) []byte {
	h := hmac.New(sha512.New384, key)
	h.Write(b)
	return h.Sum(nil)
}

func doBLAKE2b(size int, key, b []byte) []byte {
	h, err := blake2b.New(size, key)
	if err != nil {
		panic(err)
	}
	h.Write(b)
	return h.Sum(nil)
}

func doAES256CTR(key, nonce, m []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	dst := make([]byte, len(m))
	ciph := cipher.NewCTR(block, nonce)
	ciph.XORKeyStream(dst, m)
	return dst
}

func doCHACHA20(key, nonce, m []byte) []byte {
	ciph, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		panic(err)
	}

	dst := make([]byte, len(m))
	ciph.XORKeyStream(dst, m)
	return dst
}

func doOpenCHACHA(key, nonce, c, a []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		panic(err)
	}
	return aead.Open(nil, nonce, c, a)
}

func doSealCHACHA(key, nonce, m, a []byte) []byte {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		panic(err)
	}
	return aead.Seal(nil, nonce, m, a)
}

func doHKDF(key, salt, info []byte) io.Reader {
	return hkdf.New(sha512.New384, key, salt, info)
}

func b64Decode(dst, src []byte) (n int, err error) {
	return base64.RawURLEncoding.Decode(dst, src)
}

func b64DecodedLen(n int) int {
	return base64.RawURLEncoding.DecodedLen(n)
}

func b64Encode(dst, src []byte) {
	base64.RawURLEncoding.Encode(dst, src)
}

func b64EncodedLen(n int) int {
	return base64.RawURLEncoding.EncodedLen(n)
}

func constTimeEq(x, y int32) bool {
	return subtle.ConstantTimeEq(x, y) == 1
}
