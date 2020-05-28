package vault

import (
	"github.com/aweris/vault-init/client"
	"github.com/pkg/errors"
)

var (
	ErrFailedToInit   = errors.New("failed to initialize vault")
	ErrFailedToUnseal = errors.New("failed to unseal vault")
)

// API is a wrapper interface for vault init operations.
type API interface {
	// Returns status of the vault
	Status() (StatusCode, error)

	// Initialize the vault
	Init(initReq *InitRequest) (*InitResponse, error)

	// Unseals the vault
	Unseal(unsealReq *UnsealRequest) (*UnsealResponse, error)
}

type vault struct {
	client *client.Client
}

func NewVaultAPI(client *client.Client) API {
	return &vault{client: client}
}
