package client

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
)

type Request struct {
	method string
	url    *url.URL
	body   []byte
}

func (c *Client) NewRequest(method, requestPath string) *Request {
	addr := c.address

	return &Request{
		method: method,
		url: &url.URL{
			Scheme: addr.Scheme,
			User:   addr.User,
			Host:   addr.Host,
			Path:   path.Join(addr.Path, requestPath),
		},
	}
}

func (r *Request) SetJSONBody(val interface{}) error {
	buf, err := json.Marshal(val)
	if err != nil {
		return err
	}

	r.body = buf
	return nil
}

func (r *Request) toHttpReq() (*http.Request, error) {
	return http.NewRequest(r.method, r.url.String(), ioutil.NopCloser(bytes.NewReader(r.body)))
}
