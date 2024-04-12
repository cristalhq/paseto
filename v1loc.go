package paseto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	v1LocNonceSize = 32
	v1LocNonceHalf = v1LocNonceSize / 2
	v1LocMacSize   = 48 // const for crypty.SHA384.Size()
	v1LocHeader    = "v1.local."
)

func V1Encrypt(key []byte, payload, footer any, randBytes []byte) (string, error) {
	if randBytes == nil {
		randBytes = make([]byte, v1LocNonceSize)
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

	macN := hmac.New(sha512.New384, randBytes)
	if _, err := macN.Write(payloadBytes); err != nil {
		return "", fmt.Errorf("hash payload: %w", err)
	}
	nonce := macN.Sum(nil)[:v1LocNonceSize]

	encKey, authKey, err := v1locSplitKey(key, nonce[:v1LocNonceHalf])
	if err != nil {
		return "", fmt.Errorf("create enc and auth keys: %w", err)
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return "", fmt.Errorf("create aes cipher: %w", err)
	}

	encryptedPayload := make([]byte, len(payloadBytes))
	cipher.NewCTR(block, nonce[v1LocNonceHalf:]).
		XORKeyStream(encryptedPayload, payloadBytes)

	h := hmac.New(sha512.New384, authKey)
	if _, err := h.Write(pae([]byte(v1LocHeader), nonce, encryptedPayload, footerBytes)); err != nil {
		return "", fmt.Errorf("create signature: %w", err)
	}
	mac := h.Sum(nil)

	body := make([]byte, 0, len(nonce)+len(encryptedPayload)+len(mac))
	body = append(body, nonce...)
	body = append(body, encryptedPayload...)
	body = append(body, mac...)

	return buildToken(v1LocHeader, body, footerBytes), nil
}

func V1Decrypt(token string, key []byte, payload, footer any) error {
	data, footerBytes, err := splitToken(token, v1LocHeader)
	if err != nil {
		return fmt.Errorf("decode token: %w", err)
	}
	if len(data) < v1LocNonceSize+v1LocMacSize {
		return ErrIncorrectTokenFormat
	}

	pivot := len(data) - v1LocMacSize
	nonce := data[:v1LocNonceSize]
	encryptedPayload, mac := data[v1LocNonceSize:pivot], data[pivot:]

	encKey, authKey, err := v1locSplitKey(key, nonce[:v1LocNonceHalf])
	if err != nil {
		return fmt.Errorf("create enc and auth keys: %w", err)
	}

	body := pae([]byte(v1LocHeader), nonce, encryptedPayload, footerBytes)
	h := hmac.New(sha512.New384, authKey)
	if _, err := h.Write(body); err != nil {
		return fmt.Errorf("create signature: %w", err)
	}

	if !hmac.Equal(h.Sum(nil), mac) {
		return fmt.Errorf("token signature: %w", ErrInvalidTokenAuth)
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return fmt.Errorf("create aes cipher: %w", err)
	}

	decryptedPayload := make([]byte, len(encryptedPayload))
	cipher.NewCTR(block, nonce[v1LocNonceHalf:]).
		XORKeyStream(decryptedPayload, encryptedPayload)

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

func v1locSplitKey(key, salt []byte) ([]byte, []byte, error) {
	eReader := hkdf.New(sha512.New384, key, salt, []byte("paseto-encryption-key"))
	aReader := hkdf.New(sha512.New384, key, salt, []byte("paseto-auth-key-for-aead"))

	encKey := make([]byte, 32)
	authKey := make([]byte, 32)

	if _, err := io.ReadFull(eReader, encKey); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(aReader, authKey); err != nil {
		return nil, nil, err
	}
	return encKey, authKey, nil
}
