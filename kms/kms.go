package kms

import (
	"context"
	"encoding/base64"
	"encoding/json"

	"google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/option"
)

type Service interface {
	Encrypt(key string, val interface{}) ([]byte, error)
	Decrypt(key string, data []byte, out interface{}) error
}

type kms struct {
	ks *cloudkms.Service
}

func NewService(ctx context.Context, userAgent string) (Service, error) {
	ks, err := cloudkms.NewService(ctx, option.WithScopes(cloudkms.CloudkmsScope))
	if err != nil {
		return nil, err
	}

	ks.UserAgent = userAgent

	return &kms{ks: ks}, nil
}

func (k kms) Encrypt(key string, val interface{}) ([]byte, error) {
	data, err := json.Marshal(val)
	if err != nil {
		return nil, err
	}

	req := &cloudkms.EncryptRequest{
		Plaintext: base64.StdEncoding.EncodeToString(data),
	}

	res, err := k.ks.Projects.Locations.KeyRings.CryptoKeys.Encrypt(key, req).Do()
	if err != nil {
		return nil, err
	}

	return []byte(res.Ciphertext), nil
}

func (k kms) Decrypt(key string, data []byte, out interface{}) error {
	req := &cloudkms.DecryptRequest{
		Ciphertext: string(data),
	}

	res, err := k.ks.Projects.Locations.KeyRings.CryptoKeys.Decrypt(key, req).Do()
	if err != nil {
		return err
	}

	decodedData, err := base64.StdEncoding.DecodeString(res.Plaintext)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(decodedData, &out); err != nil {
		return err
	}

	return nil
}
