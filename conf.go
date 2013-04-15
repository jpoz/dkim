package dkim

import (
	"crypto"
	_ "crypto/sha256"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Conf map[string]string

const (
	VersionKey          = "v"
	AlgorithmKey        = "a"
	DomainKey           = "d"
	SelectorKey         = "s"
	CanonicalizationKey = "c"
	QueryMethodKey      = "q"
	BodyLengthKey       = "l"
	TimestampKey        = "t"
	ExpireKey           = "x"
	FieldsKey           = "h"
	BodyHashKey         = "bh"
	SignatureDataKey    = "b"
	AUIDKey             = "i"
	CopiedFieldsKey     = "z"
)

type Algorithm string

const (
	AlgorithmSHA256 = "rsa-sha256"
)

type Canonicalization uint

const (
	SimpleCanonicalization = iota
	RelaxedCanonicalization
)

func NewConf(domain string, selector string) (Conf, error) {
	if domain == "" {
		return nil, fmt.Errorf("domain invalid")
	}
	if selector == "" {
		return nil, fmt.Errorf("selector invalid")
	}
	return Conf{
		VersionKey:          "1",
		AlgorithmKey:        AlgorithmSHA256,
		DomainKey:           domain,
		SelectorKey:         selector,
		CanonicalizationKey: "relaxed/simple",
		QueryMethodKey:      "dns/txt",
		TimestampKey:        strconv.FormatInt(time.Now().Unix(), 10),
		FieldsKey:           "",
		BodyHashKey:         "",
		SignatureDataKey:    "",
	}, nil
}

func (c Conf) IsValid() bool {
	minRequired := []string{
		VersionKey,
		AlgorithmKey,
		DomainKey,
		SelectorKey,
		CanonicalizationKey,
		QueryMethodKey,
		TimestampKey,
	}
	for _, v := range minRequired {
		if _, ok := c[v]; !ok {
			return false
		}
	}
	return true
}

func (c Conf) Algorithm() Algorithm {
	a := c[AlgorithmKey]
	if a != "" {
		return Algorithm(a)
	}
	return AlgorithmSHA256
}

func (c Conf) Hash() crypto.Hash {
	a := c.Algorithm()
	if a == AlgorithmSHA256 {
		return crypto.SHA256
	}
	panic("algorithm not implemented")
}

func (c Conf) HeaderCanonicalization() Canonicalization {
	can := strings.ToLower(c[CanonicalizationKey])
	if strings.HasPrefix(can, "relaxed") {
		return RelaxedCanonicalization
	}
	return SimpleCanonicalization
}

func (c Conf) BodyCanonicalization() Canonicalization {
	can := strings.ToLower(c[CanonicalizationKey])
	if strings.HasSuffix(can, "/relaxed") {
		return RelaxedCanonicalization
	}
	return SimpleCanonicalization
}

func (c Conf) Join() string {
	keyOrder := []string{
		VersionKey,
		AlgorithmKey,
		CanonicalizationKey,
		DomainKey,
		QueryMethodKey,
		SelectorKey,
		TimestampKey,
		BodyHashKey,
		FieldsKey,
		CopiedFieldsKey,
		AUIDKey,
		BodyLengthKey,
		SignatureDataKey,
	}
	pairs := make([]string, 0, len(keyOrder))
	for _, k := range keyOrder {
		v, ok := c[k]
		if ok {
			pairs = append(pairs, k+"="+v)
		}
	}
	return strings.Join(pairs, "; ")
}
