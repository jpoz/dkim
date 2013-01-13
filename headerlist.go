package dkim

import (
	"fmt"
	"regexp"
	"strings"
)

type HeaderList []*Header

func ParseHeaderList(header string) (HeaderList, error) {
	lines := strings.Split(header, "\r\n")
	list := make(HeaderList, 0, len(lines))
	lastHeader := -1
	continuedRx := regexp.MustCompile(`^[ \t]`)
	for _, v := range lines {
		if continuedRx.MatchString(v) && lastHeader >= 0 {
			list[lastHeader].RawValue += "\r\n" + v
		} else {
			h, err := ParseHeader(v)
			if err == nil {
				lastHeader = len(list)
				list = append(list, h)
			}
		}
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("could not read header lines")
	}
	return list, nil
}

func (l HeaderList) Get(key string) (*Header, bool) {
	for _, v := range l {
		if strings.ToLower(v.Key()) == strings.ToLower(key) {
			return v, true
		}
	}
	return nil, false
}

func (l HeaderList) Fields() string {
	a := make([]string, 0, len(l))
	for _, v := range l {
		k := v.Key()
		if strings.ToLower(k) != strings.ToLower(SignatureHeaderKey) {
			a = append(a, k)
		}
	}
	return strings.Join(a, ":")
}

func (l HeaderList) Canonical(c Canonicalization) string {
	a := make([]string, 0, len(l))
	for _, v := range l {
		a = append(a, v.Canonical(c))
	}
	return strings.Join(a, "\r\n") + "\r\n"
}
