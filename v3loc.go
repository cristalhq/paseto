package paseto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/hkdf"
)

const (
	v3locHeader = "v3.local."
	v3locNonce  = 32
	v3locKey    = 32
	v3locMac    = 48
	v3locKDF    = 48
)

func V3Encrypt(key []byte, payload, footer any, implicit string, randBytes []byte) (string, error) {
	payloadBytes, err := toBytes(payload)
	if err != nil {
		return "", fmt.Errorf("encode payload: %w", err)
	}

	footerBytes, err := toBytes(footer)
	if err != nil {
		return "", fmt.Errorf("encode footer: %w", err)
	}

	// step 0.
	m := payloadBytes
	k := key
	f := footerBytes
	i := []byte(implicit)

	// step 1.
	if subtle.ConstantTimeEq(int32(len(k)), v3locKey) != 1 {
		return "", errors.New("bad key")
	}

	// step 2.
	h := []byte(v3locHeader)

	// step 3.
	n := randBytes
	if n == nil {
		n = make([]byte, v3locNonce)
		if _, err := io.ReadFull(rand.Reader, n); err != nil {
			return "", fmt.Errorf("read from crypto/rand.Reader: %w", err)
		}
	}

	// step 4.
	ek, n2, ak, err := v3locSplitKey(key, n)
	if err != nil {
		return "", fmt.Errorf("create enc and auth keys: %w", err)
	}

	// step 5.
	block, err := aes.NewCipher(ek)
	if err != nil {
		return "", fmt.Errorf("create aes cipher: %w", err)
	}
	c := make([]byte, len(m))
	ciph := cipher.NewCTR(block, n2)
	ciph.XORKeyStream(c, m)

	// step 6.
	preAuth := pae(h, n, c, f, i)

	// step 7.
	hasher := hmac.New(sha512.New384, ak)
	hasher.Write(preAuth)
	t := hasher.Sum(nil)

	// step 7.
	body := make([]byte, 0, len(n)+len(c)+len(t))
	body = append(body, n...)
	body = append(body, c...)
	body = append(body, t...)

	return buildToken(h, body, f), nil
}

func V3Decrypt(token string, key []byte, payload, footer any, implicit string) error {
	// step 0.
	m := token
	k := key
	i := []byte(implicit)

	// step 1.
	if subtle.ConstantTimeEq(int32(len(k)), v3locKey) != 1 {
		return errors.New("bad key")
	}

	// step 2.
	// TODO: ?

	// step 3.
	if !strings.HasPrefix(token, v3locHeader) {
		return ErrIncorrectTokenFormat
	}
	h := []byte(v3locHeader)

	// step 4.
	body, footerBytes, err := splitToken(m, v3locHeader)
	if err != nil {
		return fmt.Errorf("decode token: %w", err)
	}
	if len(body) < v3locNonce {
		return ErrIncorrectTokenFormat
	}
	n, c, t, f := body[:v3locNonce], body[v3locNonce:len(body)-32], body[len(body)-32:], footerBytes

	// step 5.
	ek, n2, ak, err := v3locSplitKey(key, n)
	if err != nil {
		return fmt.Errorf("create enc and auth keys: %w", err)
	}

	// step 6.
	preAuth := pae(h, n, c, f, i)

	// step 7.
	hasher := hmac.New(sha512.New384, ak)
	hasher.Write(preAuth)
	t2 := hasher.Sum(nil)

	// step 8.
	if !hmac.Equal(t, t2) {
		return ErrInvalidTokenAuth
	}

	// step 9.
	block, err := aes.NewCipher(ek)
	if err != nil {
		return fmt.Errorf("create aes cipher: %w", err)
	}

	p := make([]byte, len(c))
	ciph := cipher.NewCTR(block, n2)
	ciph.XORKeyStream(p, c)

	// step 7.
	if payload != nil {
		if err := fromBytes(p, payload); err != nil {
			return fmt.Errorf("decode payload: %w", err)
		}
	}

	if footer != nil {
		if err := fromBytes(f, footer); err != nil {
			return fmt.Errorf("decode footer: %w", err)
		}
	}
	return nil
}

func v3locSplitKey(key, n []byte) (ek, ak, n2 []byte, err error) {
	eKDF := hkdf.New(sha512.New384, key, nil, append([]byte("paseto-encryption-key"), n...))
	aKDF := hkdf.New(sha512.New384, key, nil, append([]byte("paseto-auth-key-for-aead"), n...))

	tmp := make([]byte, v3locKDF)
	if _, err := io.ReadFull(eKDF, tmp); err != nil {
		return nil, nil, nil, fmt.Errorf("unable to generate encryption key from seed: %w", err)
	}

	ek, n2 = tmp[:v3locKey], tmp[v3locKey:]

	ak = make([]byte, v3locKDF)
	if _, err := io.ReadFull(aKDF, ak); err != nil {
		return nil, nil, nil, fmt.Errorf("unable to generate authentication key from seed: %w", err)
	}
	return ek, n2, ak, nil
}
