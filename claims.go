package paseto

type RegisteredClaims struct {
	ID        string       `json:"jti,omitempty"`
	Audience  string       `json:"aud,omitempty"`
	Issuer    string       `json:"iss,omitempty"`
	Subject   string       `json:"sub,omitempty"`
	ExpiresAt *NumericDate `json:"exp,omitempty"`
	IssuedAt  *NumericDate `json:"iat,omitempty"`
	NotBefore *NumericDate `json:"nbf,omitempty"`
}
