package paseto

import (
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	v1locHeader = "v1.local."
	v1locKey    = 32
	v1locNonce  = 32
	v1locNonceH = v1locNonce / 2
	v1locMac    = 48 // const for crypto.SHA384.Size()
)

func V1Encrypt(key []byte, payload, footer any, randBytes []byte) (string, error) {
	payloadBytes, err := toBytes(payload)
	if err != nil {
		return "", fmt.Errorf("encode payload: %w", err)
	}

	footerBytes, err := toBytes(footer)
	if err != nil {
		return "", fmt.Errorf("encode footer: %w", err)
	}

	m := payloadBytes
	k := key
	f := footerBytes

	// step 1.
	if !constTimeEq(int32(len(k)), v1locKey) {
		return "", errors.New("bad key")
	}

	// step 2.
	h := []byte(v1locHeader)

	// step 3.
	b := randBytes
	if b == nil {
		b = make([]byte, v1locNonce)
		if _, err := io.ReadFull(rand.Reader, b); err != nil {
			return "", fmt.Errorf("read from crypto/rand.Reader: %w", err)
		}
	}

	// step 4.
	n := doHMACSHA384(b, m)[:v1locNonce]

	// step 5.
	ek, ak, err := v1locSplitKey(k, n[:v1locNonceH])
	if err != nil {
		return "", fmt.Errorf("create enc and auth keys: %w", err)
	}

	// step 6.
	c := doAES256CTR(ek, n[v1locNonceH:], m)

	// step 7.
	preAuth := pae(h, n, c, f)

	// step 8.
	t := doHMACSHA384(ak, preAuth)

	// step 9.
	body := make([]byte, 0, len(n)+len(c)+len(t))
	body = append(body, n...)
	body = append(body, c...)
	body = append(body, t...)

	return buildToken(h, body, f), nil
}

func V1Decrypt(token string, key []byte, payload, footer any) error {
	// step 0.
	k := key

	// step 1.
	if !constTimeEq(int32(len(k)), v1locKey) {
		return errors.New("bad key")
	}

	// step 2.
	// TODO: ?

	// step 3.
	if !strings.HasPrefix(token, v1locHeader) {
		return ErrIncorrectTokenFormat
	}
	h := []byte(v1locHeader)

	// step 4.
	data, footerBytes, err := splitToken(token, v1locHeader)
	if err != nil {
		return fmt.Errorf("decode token: %w", err)
	}
	if len(data) < v1locNonce+v1locMac {
		return ErrIncorrectTokenFormat
	}
	f := footerBytes

	pivot := len(data) - v1locMac
	n := data[:v1locNonce]
	c, t := data[v1locNonce:pivot], data[pivot:]

	// step 5.
	ek, ak, err := v1locSplitKey(k, n[:v1locNonceH])
	if err != nil {
		return fmt.Errorf("create enc and auth keys: %w", err)
	}

	// step 6.
	preAuth := pae(h, n, c, f)

	// step 7.
	t2 := doHMACSHA384(ak, preAuth)

	// step 8.
	if !hmac.Equal(t2, t) {
		return ErrInvalidTokenAuth
	}

	// step 9.
	p := doAES256CTR(ek, n[v1locNonceH:], c)

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

func v1locSplitKey(key, salt []byte) ([]byte, []byte, error) {
	er := doHKDF(key, salt, []byte("paseto-encryption-key"))
	ar := doHKDF(key, salt, []byte("paseto-auth-key-for-aead"))

	ek := make([]byte, 32)
	ak := make([]byte, 32)

	if _, err := io.ReadFull(er, ek); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(ar, ak); err != nil {
		return nil, nil, err
	}
	return ek, ak, nil
}
