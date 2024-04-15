package paseto

import (
	"encoding/json"
	"math"
	"strconv"
	"time"
)

type NumericDate struct {
	time.Time
}

func NewNumericDate(t time.Time) *NumericDate {
	return &NumericDate{t}
}

func (t NumericDate) MarshalJSON() ([]byte, error) {
	if t.IsZero() {
		return []byte("null"), nil
	}
	return []byte(strconv.FormatInt(t.Unix(), 10)), nil
}

func (t *NumericDate) UnmarshalJSON(data []byte) error {
	var value json.Number
	if err := json.Unmarshal(data, &value); err != nil {
		return ErrDateInvalidFormat
	}
	f, err := value.Float64()
	if err != nil {
		return ErrDateInvalidFormat
	}
	sec, dec := math.Modf(f)
	ts := time.Unix(int64(sec), int64(dec*1e9))
	*t = NumericDate{ts}
	return nil
}
