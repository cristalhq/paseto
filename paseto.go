package paseto

import "encoding/json"

type Token struct {
	typ    TokenType
	raw    []byte
	dot1   int
	dot2   int
	claims json.RawMessage
	footer json.RawMessage
}

func (t Token) Type() TokenType {
	return t.typ
}

func (t *Token) String() string {
	return string(t.raw)
}

func (t *Token) Bytes() []byte {
	return t.raw
}

// HeaderPart returns token header part.
func (t *Token) HeaderPart() []byte {
	return t.raw[:t.dot1]
}

// ClaimsPart returns token claims part.
func (t *Token) ClaimsPart() []byte {
	return t.raw[t.dot1+1 : t.dot2]
}

// PayloadPart returns token payload part.
func (t *Token) PayloadPart() []byte {
	return t.raw[:t.dot2]
}

// SignaturePart returns token signature part.
func (t *Token) SignaturePart() []byte {
	return t.raw[t.dot2+1:]
}

// Claims returns token's claims.
func (t *Token) Claims() json.RawMessage {
	return t.claims
}

// DecodeClaims into a given parameter.
func (t *Token) DecodeClaims(dst any) error {
	return json.Unmarshal(t.claims, dst)
}

// Footer returns token's footer.
func (t *Token) Footer() json.RawMessage {
	return t.footer
}

// DecodeFooter into a given parameter.
func (t *Token) DecodeFooter(dst any) error {
	return json.Unmarshal(t.footer, dst)
}

// unexported method to check that token was created via Parse func.
func (t *Token) isValid() bool {
	return t != nil && len(t.raw) > 0
}

type TokenType uint

const (
	TokenUnknown  TokenType = 0
	TokenV1Local  TokenType = 1
	TokenV1Public TokenType = 2
	TokenV2Local  TokenType = 3
	TokenV2Public TokenType = 4
	TokenV3Local  TokenType = 5
	TokenV3Public TokenType = 6
	TokenV4Local  TokenType = 7
	TokenV4Public TokenType = 8
)
