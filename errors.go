package paseto

import "errors"

var (
	ErrDataUnmarshal        = errors.New("can't unmarshal token data to the given type of value")
	ErrInvalidTokenAuth     = errors.New("invalid token authentication")
	ErrIncorrectTokenFormat = errors.New("incorrect token format")
	ErrIncorrectTokenHeader = errors.New("incorrect token header")
)
