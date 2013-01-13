package dkim

import (
	"fmt"
	"strings"
)

func ReadEML(eml string) (header string, body string, err error) {
	c := strings.SplitN(eml, "\r\n\r\n", 2)
	if len(c) == 2 {
		return c[0], c[1], nil
	}
	return "", "", fmt.Errorf("could not read header block")
}
