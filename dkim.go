package dkim

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"regexp"
	"strings"
)

const (
	SignatureHeaderKey = "DKIM-Signature"
)

var StdSignableHeaders = []string{
	"Cc",
	"Content-Type",
	"Date",
	"From",
	"Reply-To",
	"Subject",
	"To",
	SignatureHeaderKey,
}

type DKIM struct {
	emlData         string
	signableHeaders []string
	conf            Conf
	privateKey      *rsa.PrivateKey
}

func New(emlData string, conf Conf, keyPEM []byte) (*DKIM, error) {
	if emlData == "" {
		return nil, fmt.Errorf("invalid eml data")
	}
	if !conf.IsValid() {
		return nil, fmt.Errorf("invalid dkim configuration")
	}
	if keyPEM == nil {
		return nil, fmt.Errorf("invalid key PEM data")
	}
	dkim := &DKIM{
		emlData:         emlData,
		signableHeaders: StdSignableHeaders,
		conf:            conf,
	}
	der, _ := pem.Decode(keyPEM)
	key, err := x509.ParsePKCS1PrivateKey(der.Bytes)
	if err != nil {
		return nil, err
	}
	dkim.privateKey = key

	return dkim, nil
}

func (d *DKIM) canonicalBody() string {
	_, b, _ := ReadEML(d.emlData)
	if d.conf.BodyCanonicalization() == RelaxedCanonicalization {
		if b == "" {
			return ""
		}
		// Reduce WSP sequences to single WSP
		rx := regexp.MustCompile(`[ \t]+`)
		b = rx.ReplaceAllString(b, " ")

		// Ignore all whitespace at end of lines.
		// Implementations MUST NOT remove the CRLF
		// at the end of the line
		rx2 := regexp.MustCompile(` \r\n`)
		b = rx2.ReplaceAllString(b, "\r\n")
	} else {
		if b == "" {
			return "\r\n"
		}
	}

	// Ignore all empty lines at the end of the message body
	rx3 := regexp.MustCompile(`[ \r\n]*\z`)
	b = rx3.ReplaceAllString(b, "")

	return b + "\r\n"
}

func (d *DKIM) canonicalBodyHash() []byte {
	b := d.canonicalBody()
	digest := d.conf.Hash().New()
	digest.Write([]byte(b))

	return digest.Sum(nil)
}

func (d *DKIM) signableHeaderBlock() string {
	header, _, _ := ReadEML(d.emlData)
	headerList, _ := ParseHeaderList(header)

	signableHeaderList := make(HeaderList, 0, len(headerList)+1)
	for _, k := range d.signableHeaders {
		h, ok := headerList.Get(k)
		if ok {
			signableHeaderList = append(signableHeaderList, h)
		}
	}

	d.conf[BodyHashKey] = base64.StdEncoding.EncodeToString(d.canonicalBodyHash())
	d.conf[FieldsKey] = signableHeaderList.Fields()

	signableHeaderList = append(signableHeaderList, &Header{
		SignatureHeaderKey,
		d.conf.Join(),
	})

	// According to RFC6376 http://tools.ietf.org/html/rfc6376#section-3.7
	// the DKIM header must be inserted without a trailing <CRLF>.
	// That's why we have to trim the space from the canonical header.
	return strings.TrimSpace(signableHeaderList.Canonical(d.conf.HeaderCanonicalization()))
}

func (d *DKIM) signature() (string, error) {
	if d.privateKey == nil {
		return "", fmt.Errorf("no private key loaded")
	}
	block := d.signableHeaderBlock()
	hash := d.conf.Hash()
	digest := hash.New()
	digest.Write([]byte(block))

	sig, err := rsa.SignPKCS1v15(rand.Reader, d.privateKey, hash, digest.Sum(nil))
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(sig), nil
}

func (d *DKIM) SignedEML() (string, error) {
	sig, err := d.signature()
	if err != nil {
		return "", err
	}
	d.conf[SignatureDataKey] = sig
	header, body, err := ReadEML(d.emlData)
	if err != nil {
		return "", err
	}
	headerList, _ := ParseHeaderList(header)

	// Append the signature header. Keep in mind these are raw values,
	// so we add a <SP> character before the key-value list
	headerList = append(headerList, &Header{SignatureHeaderKey, " " + d.conf.Join()})
	header = headerList.Canonical(SimpleCanonicalization)

	return strings.Join([]string{header, body}, "\r\n"), nil
}
