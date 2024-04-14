package paseto

import (
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20"
)

const (
	v4locHeader = "v4.local."
	v4locKey    = 32
	v4locNonce  = 32
	v4locMac    = 32
	v4locKDF    = 32
)

func V4Encrypt(key []byte, payload, footer any, implicit string, randBytes []byte) (string, error) {
	payloadBytes, err := toBytes(payload)
	if err != nil {
		return "", fmt.Errorf("encode payload: %w", err)
	}

	footerBytes, err := toBytes(footer)
	if err != nil {
		return "", fmt.Errorf("encode footer: %w", err)
	}

	if randBytes == nil {
		randBytes = make([]byte, v4locNonce)
		if _, err := io.ReadFull(rand.Reader, randBytes); err != nil {
			return "", fmt.Errorf("read from crypto/rand.Reader: %w", err)
		}
	}

	// step 0.
	m := payloadBytes
	k := key
	f := footerBytes
	i := []byte(implicit)

	// step 1.
	if !constTimeEq(int32(len(k)), v4locKey) {
		return "", errors.New("bad key")
	}

	// step 2.
	h := []byte(v4locHeader)

	// step 3.
	n := randBytes
	if n == nil {
		n = make([]byte, v4locNonce)
		if _, err := io.ReadFull(rand.Reader, n); err != nil {
			return "", fmt.Errorf("read from crypto/rand.Reader: %w", err)
		}
	}

	// step 4.
	ek, n2, ak, err := v4locSplitKey(key, n)
	if err != nil {
		return "", fmt.Errorf("create enc and auth keys: %w", err)
	}

	// step 5.
	c := make([]byte, len(m))

	ciph, err := chacha20.NewUnauthenticatedCipher(ek, n2)
	if err != nil {
		return "", fmt.Errorf("create chacha20 cipher: %w", err)
	}
	ciph.XORKeyStream(c, m)

	// step 6.
	preAuth := pae(h, n, c, f, i)

	// step 7.
	mac, err := blake2b.New(v4locMac, ak)
	if err != nil {
		return "", fmt.Errorf("unable to in initialize MAC kdf: %w", err)
	}
	mac.Write(preAuth)
	t := mac.Sum(nil)

	// step 8.
	body := make([]byte, 0, len(n)+len(c)+len(t))
	body = append(body, n...)
	body = append(body, c...)
	body = append(body, t...)

	return buildToken(h, body, f), nil
}

func V4Decrypt(token string, key []byte, payload, footer any, implicit string) error {
	// step 0.
	k := key
	i := []byte(implicit)

	// step 1.
	// step 2.

	// step 3.
	if !strings.HasPrefix(token, v4locHeader) {
		return ErrIncorrectTokenFormat
	}
	h := []byte(v4locHeader)

	// step 4.
	body, footerBytes, err := splitToken(token, v4locHeader)
	if err != nil {
		return fmt.Errorf("decode token: %w", err)
	}
	if len(body) < v4locNonce+v4locMac {
		return ErrIncorrectTokenFormat
	}
	f := footerBytes
	n := body[:v4locNonce]
	c := body[v4locNonce : len(body)-v4locMac]
	t := body[v4locNonce+len(c):]

	// step 5.
	ek, n2, ak, err := v4locSplitKey(k, n)
	if err != nil {
		return fmt.Errorf("create enc and auth keys: %w", err)
	}

	// step 6.
	preAuth := pae(h, n, c, f, i)

	// step 7.
	hasher, err := blake2b.New(v4locMac, ak)
	if err != nil {
		return fmt.Errorf("create blake2b hash: %w", err)
	}
	hasher.Write(preAuth)
	t2 := hasher.Sum(nil)

	// step 8.
	if !hmac.Equal(t, t2) {
		return ErrInvalidTokenAuth
	}

	// step 9.
	ciph, err := chacha20.NewUnauthenticatedCipher(ek, n2)
	if err != nil {
		return fmt.Errorf("create chacha20 cipher: %w", err)
	}

	p := make([]byte, len(c))
	ciph.XORKeyStream(p, c)

	// step 10.
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

func v4locSplitKey(key, n []byte) (ek, n2, ak []byte, err error) {
	encKDF, err := blake2b.New(56, key)
	if err != nil {
		return nil, nil, nil, err
	}

	encKDF.Write([]byte("paseto-encryption-key"))
	encKDF.Write(n)
	tmp := encKDF.Sum(nil)
	ek, n2 = tmp[:v4locKDF], tmp[v4locKDF:]

	authKDF, err := blake2b.New(32, key)
	if err != nil {
		return nil, nil, nil, err
	}

	authKDF.Write([]byte("paseto-auth-key-for-aead"))
	authKDF.Write(n)
	ak = authKDF.Sum(nil)

	return ek, n2, ak, nil
}
