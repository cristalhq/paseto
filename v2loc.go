package paseto

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	v2LocHeader = "v2.local."
	v2NonceSize = chacha20poly1305.NonceSizeX
)

func V2Encrypt(key []byte, payload, footer any, randBytes []byte) (string, error) {
	if randBytes == nil {
		randBytes = make([]byte, v2NonceSize)
		if _, err := io.ReadFull(rand.Reader, randBytes); err != nil {
			return "", fmt.Errorf("read from crypto/rand.Reader: %w", err)
		}
	}

	payloadBytes, err := toBytes(payload)
	if err != nil {
		return "", fmt.Errorf("encode payload: %w", err)
	}

	footerBytes, err := toBytes(footer)
	if err != nil {
		return "", fmt.Errorf("encode footer: %w", err)
	}

	hash, err := blake2b.New(v2NonceSize, randBytes)
	if err != nil {
		return "", fmt.Errorf("create blake2b hash: %w", err)
	}
	if _, err := hash.Write(payloadBytes); err != nil {
		return "", fmt.Errorf("hash payload: %w", err)
	}
	nonce := hash.Sum(nil)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", fmt.Errorf("create chacha20poly1305 cipher: %w", err)
	}

	preAuth := pae([]byte(v2LocHeader), nonce, footerBytes)

	encryptedPayload := aead.Seal(
		payloadBytes[:0],
		nonce,
		payloadBytes,
		preAuth,
	)
	body := append(nonce, encryptedPayload...)

	return buildToken(v2LocHeader, body, footerBytes), nil
}

func V2Decrypt(token string, key []byte, payload, footer any) error {
	body, footerBytes, err := splitToken(token, v2LocHeader)
	if err != nil {
		return fmt.Errorf("decode token: %w", err)
	}
	if len(body) < v2NonceSize {
		return ErrIncorrectTokenFormat
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("create chacha20poly1305 cipher: %w", err)
	}

	nonce, encryptedPayload := body[:v2NonceSize], body[v2NonceSize:]
	preAuth := pae([]byte(v2LocHeader), nonce, footerBytes)

	decryptedPayload, err := aead.Open(
		encryptedPayload[:0],
		nonce,
		encryptedPayload,
		preAuth,
	)
	if err != nil {
		return ErrInvalidTokenAuth
	}

	if payload != nil {
		if err := fromBytes(decryptedPayload, payload); err != nil {
			return fmt.Errorf("decode payload: %w", err)
		}
	}

	if footer != nil {
		if err := fromBytes(footerBytes, footer); err != nil {
			return fmt.Errorf("decode footer: %w", err)
		}
	}
	return nil
}
