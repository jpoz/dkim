package dkim

import (
	"bytes"
	"fmt"
	"net/mail"
)

func splitEML(eml []byte) (header, body []byte, err error) {
	r := bytes.NewReader(eml)
	msg, err := mail.ReadMessage(r)
	if err != nil {
		return header, body, err
	}

	header_buf := bytes.NewBuffer([]byte{})
	for k, v := range msg.Header {
		s := fmt.Sprintf("%s: %s\n", k, v[0])
		header_buf.Write([]byte(s))
	}

	body_buf := new(bytes.Buffer)
	body_buf.ReadFrom(msg.Body)

	return header_buf.Bytes(), body_buf.Bytes(), nil
}
