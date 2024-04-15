package paseto

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	v2locHeader = "v2.local."
	v2locKey    = 32
	v2locNonce  = chacha20poly1305.NonceSizeX
)

func V2Encrypt(key []byte, payload, footer any, randBytes []byte) (string, error) {
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

	// step 1.
	if !constTimeEq(int32(len(k)), v2locKey) {
		return "", errors.New("bad key")
	}

	// step 2.
	h := []byte(v2locHeader)

	// step 3.
	b := randBytes
	if b == nil {
		b = make([]byte, v2locNonce)
		if _, err := io.ReadFull(rand.Reader, b); err != nil {
			return "", fmt.Errorf("read from crypto/rand.Reader: %w", err)
		}
	}

	// step 4.
	n := doBLAKE2b(v2locNonce, b, m)

	// step 5.
	preAuth := pae(h, n, f)

	// step 6.
	c := doSealCHACHA(k, n, m, preAuth)

	// step 7.
	body := make([]byte, 0, len(n)+len(c))
	body = append(body, n...)
	body = append(body, c...)

	return buildToken(h, body, f), nil
}

func V2Decrypt(token string, key []byte, payload, footer any) error {
	// step 0.
	m := token
	k := key

	// step 1.
	if !constTimeEq(int32(len(k)), v2locKey) {
		return errors.New("bad key")
	}

	// step 2.
	// TODO: ?

	// step 3.
	h := []byte(v2locHeader)

	// step 4.
	body, footerBytes, err := splitToken(m, v2locHeader)
	if err != nil {
		return fmt.Errorf("decode token: %w", err)
	}
	if len(body) < v2locNonce {
		return ErrIncorrectTokenFormat
	}
	n, c, f := body[:v2locNonce], body[v2locNonce:], footerBytes

	// step 5.
	preAuth := pae(h, n, f)

	// step 6.
	p, err := doOpenCHACHA(k, n, c, preAuth)
	if err != nil {
		return ErrInvalidTokenAuth
	}

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
