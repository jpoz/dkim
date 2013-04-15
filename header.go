package dkim

import (
	"fmt"
	"regexp"
	"strings"
)

type Header struct {
	RawKey   string
	RawValue string
}

func ParseHeader(headerLine string) (*Header, error) {
	c := strings.SplitN(headerLine, ":", 2)
	if len(c) == 2 {
		return &Header{c[0], c[1]}, nil
	}
	return nil, fmt.Errorf("could not parse header; malformed")
}

func (h *Header) Key() string {
	return strings.TrimSpace(h.RawKey)
}

func (h *Header) Value() string {
	return strings.TrimSpace(h.RawValue)
}

func (h *Header) RelaxedKey() string {
	return strings.ToLower(h.Key())
}

func (h *Header) RelaxedValue() string {
	return strings.TrimSpace(regexp.MustCompile(`\s+`).ReplaceAllString(h.RawValue, " "))
}

func (h *Header) Canonical(relaxed bool) string {
	if relaxed {
		return h.RelaxedKey() + ":" + h.RelaxedValue()
	}
	return h.RawKey + ":" + h.RawValue
}
