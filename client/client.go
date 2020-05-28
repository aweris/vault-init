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

	// HttpClient is the HTTP client to use.
	HttpClient *http.Client

	// Timeout is for setting custom timeout parameter in the HttpClient
	Timeout time.Duration
}

// Client is a simple http client wrapper
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

	if cfg.HttpClient == nil {
		cfg.HttpClient = http.DefaultClient
	}

	if cfg.Timeout == 0 {
		cfg.Timeout = time.Second * 60
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
	httpReq, err := req.toHttpReq()
	if err != nil {
		return nil, err
	}

	res, err := c.config.HttpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}

	return &Response{res}, nil
}
