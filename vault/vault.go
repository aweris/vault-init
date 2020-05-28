package vault

import (
	"github.com/aweris/vault-init/client"
)

// API is a wrapper interface for vault init operations
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
