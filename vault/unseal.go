package vault

import (
	"net/http"

	"github.com/pkg/errors"
)

// UnsealRequest holds a Vault unseal request.
type UnsealRequest struct {
	Key   string `json:"key"`
	Reset bool   `json:"reset"`
}

// UnsealResponse holds a Vault unseal response.
type UnsealResponse struct {
	Sealed   bool `json:"sealed"`
	T        int  `json:"t"`
	N        int  `json:"n"`
	Progress int  `json:"progress"`
}

func (v *vault) Unseal(unsealReq *UnsealRequest) (*UnsealResponse, error) {
	req := v.client.NewRequest("PUT", "/v1/sys/unseal")

	if err := req.SetJSONBody(unsealReq); err != nil {
		return nil, err
	}

	res, err := v.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, errors.Wrapf(ErrFailedToUnseal, "status code: %d", res.StatusCode)
	}

	var ur UnsealResponse

	if err := res.DecodeJSON(&ur); err != nil {
		return nil, err
	}

	return &ur, nil
}
