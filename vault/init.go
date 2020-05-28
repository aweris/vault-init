package vault

import (
	"fmt"
	"net/http"
)

type InitRequest struct {
	SecretShares      int `json:"secret_shares"`
	SecretThreshold   int `json:"secret_threshold"`
	StoredShares      int `json:"stored_shares"`
	RecoveryShares    int `json:"recovery_shares"`
	RecoveryThreshold int `json:"recovery_threshold"`
}

// InitResponse holds a Vault init response.
type InitResponse struct {
	Keys       []string `json:"keys"`
	KeysBase64 []string `json:"keys_base64"`
	RootToken  string   `json:"root_token"`
}

func (v *vault) Init(initReq *InitRequest) (*InitResponse, error) {
	req := v.client.NewRequest("PUT", "/v1/sys/init")

	if err := req.SetJSONBody(initReq); err != nil {
		return nil, err
	}

	res, err := v.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("init failed with status code: %v", res.StatusCode)
	}

	var ir InitResponse

	if err := res.DecodeJSON(&ir); err != nil {
		return nil, err
	}

	return &ir, nil
}
