package dkim2

import (
	"bytes"
	"io"
	"net/mail"
	"net/textproto"
)

type VersionedMessage struct {
	Revision int
	Header   map[string][]string
	Body     []byte
}

// ToMessage converts a VersionedMessage to a mail.Message
func (m VersionedMessage) ToMessage() mail.Message {
	hdr := mail.Header{}
	for h, v := range m.Header {
		hdr[textproto.CanonicalMIMEHeaderKey(h)] = v
	}
	return mail.Message{
		Header: hdr,
	}
}

// MessageHistory returns all the previous versions of a message
func MessageHistory(r io.Reader) ([]VersionedMessage, error) {
	ret := []VersionedMessage{}
	msg, err := mail.ReadMessage(r)
	if err != nil {
		return nil, err
	}

	_, miHeaders, err := parseD2Headers(msg.Header)
	if err != nil {
		return nil, err
	}

	body, err := io.ReadAll(msg.Body)
	if err != nil {
		return nil, err
	}
	headers := NormalizedHeaders(msg.Header)
	for len(miHeaders) > 0 {
		m := miHeaders[len(miHeaders)-1].Revision
		ret = append(ret, VersionedMessage{
			Revision: m,
			Header:   headers,
			Body:     body,
		})
		recipe := miHeaders[len(miHeaders)-1].Recipes
		if recipe != nil {
			headers, err = recipe.Header(headers)
			if err != nil {
				return nil, err
			}
			var buff bytes.Buffer
			err = recipe.Body(bytes.NewBuffer(body), &buff)
			if err != nil {
				return nil, err
			}
			body = buff.Bytes()
		}
		miHeaders = miHeaders[:len(miHeaders)-1]
	}
	//ret = append(ret, VersionedMessage{
	//	Revision: 0,
	//	Header:   headers,
	//	Body:     body,
	//})
	return ret, nil
}
