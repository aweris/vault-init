package client

import (
	"net/http"
	"net/url"
	"time"
)

// Config is used to configure the creation of the client.
type Config struct {
	// Address is the address of the Vault server. This should be a complete
	// URL such as "http://vault.example.com".
	Address string

	// HTTPClient is the HTTP client to use.
	HTTPClient *http.Client

	// Timeout is for setting custom timeout parameter in the HTTPClient
	Timeout time.Duration
}

// Client is a simple http client wrapper.
type Client struct {
	address *url.URL
	config  *Config
}

func NewClient(cfg *Config) (*Client, error) {
	if cfg == nil {
		cfg = &Config{}
	}

	if cfg.Address == "" {
		cfg.Address = "https://127.0.0.1:8200"
	}

	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}

	if cfg.Timeout == 0 {
		cfg.Timeout = 60 * time.Second //nolint:gomnd
	}

	u, err := url.Parse(cfg.Address)
	if err != nil {
		return nil, err
	}

	return &Client{
		address: u,
		config:  cfg,
	}, nil
}

func (c *Client) Do(req *Request) (*Response, error) {
	httpReq, err := req.toHTTPReq()
	if err != nil {
		return nil, err
	}

	//nolint: bodyclose
	res, err := c.config.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, err
	}

	return &Response{res}, nil
}
