package paseto

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
)

func pae(pieces ...[]byte) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, int64(len(pieces)))

	for _, p := range pieces {
		binary.Write(&buf, binary.LittleEndian, int64(len(p)))
		buf.Write(p)
	}
	return buf.Bytes()
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
			return fmt.Errorf("%v: %w", err, ErrDataUnmarshal)
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

func buildToken(header string, body, footer []byte) string {
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
