package manager

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/aweris/vault-init/client"
	"github.com/aweris/vault-init/kms"
	"github.com/aweris/vault-init/storage"
	"github.com/aweris/vault-init/vault"
)

const (
	// file names
	rootTokenEnc  = "root-token.enc" /* #nosec */
	unsealKeysEnc = "unseal-keys.json.enc"
)

type Config struct {
	// Enables debug logs
	Verbose bool

	// Disable TLS validation when connecting. Setting to true is highly discouraged.
	VaultInsecureSkipVerify bool

	// Use Vault 1.0 native auto-unsealing directly. You must set the seal configuration in Vault's configuration.
	VaultAutoUnseal bool

	// The number of human shares to create.
	VaultSecretShares int

	// The number of human shares required to unseal.
	VaultSecretThreshold int

	// Number of shares to store on KMS. Only applies to Vault 1.0 native auto-unseal.
	VaultStoredShares int

	// Number of recovery shares to generate. Only applies to Vault 1.0 native auto-unseal.
	VaultRecoveryShares int

	// Number of recovery shares needed to unseal. Only applies to Vault 1.0 native auto-unseal.
	VaultRecoveryThreshold int

	// Address of the vault service
	VaultAddress string

	// Path to a PEM-encoded CA certificate file on the local disk.
	VaultCACert string

	// The time duration between Vault health checks. Set this to a negative number to unseal once and exit.
	CheckInterval time.Duration

	// The Google Cloud Storage Bucket where the vault master key and root token is stored.
	GcsBucketName string

	// The Google Cloud KMS key ID used to encrypt and decrypt the vault master key and root token.
	KmsKeyID string

	// User Agent info used by clients
	UserAgent string
}

type Manager struct {
	va vault.API
	ks kms.Service
	ss storage.Service

	cfg *Config
}

func NewManager(ctx context.Context, cfg *Config) (man *Manager, err error) {
	man = &Manager{
		cfg: cfg,
	}

	man.ks, err = kms.NewService(ctx, cfg.UserAgent)
	if err != nil {
		return nil, err
	}

	man.ss, err = storage.NewStorage(ctx, cfg.UserAgent, cfg.GcsBucketName)
	if err != nil {
		return nil, err
	}

	// #nosec
	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.VaultInsecureSkipVerify,
	}

	if cfg.VaultCACert != "" {
		// Load CA cert
		caCert, err := ioutil.ReadFile(cfg.VaultCACert)
		if err != nil {
			return nil, err
		}

		caCertPool := x509.NewCertPool()

		caCertPool.AppendCertsFromPEM(caCert)

		// Setup HTTPS client
		tlsConfig.RootCAs = caCertPool
	}

	vc, err := client.NewClient(
		&client.Config{
			Address: cfg.VaultAddress,
			HTTPClient: &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: tlsConfig,
				},
			},
		},
	)

	if err != nil {
		return nil, err
	}

	man.va = vault.NewVaultAPI(vc)

	return man, nil
}

func (m *Manager) Start(ctx context.Context) error {
	for {
		status, err := m.va.Status()
		if err != nil {
			log.Println(err)
		}

		switch status {
		case vault.StatusNotInit:
			log.Println("Vault is not initialized.")
			log.Println("Initializing...")

			err := m.initialize(ctx)
			if err != nil {
				log.Println(err)
				break
			}

			if !m.cfg.VaultAutoUnseal {
				log.Println("Unsealing...")

				err := m.unseal(ctx)
				if err != nil {
					log.Println(err)
					break
				}
			}

		case vault.StatusSealed:
			log.Println("Vault is sealed.")

			if !m.cfg.VaultAutoUnseal {
				log.Println("Unsealing...")

				err := m.unseal(ctx)
				if err != nil {
					log.Println(err)
					break
				}
			}
		case vault.StatusActive, vault.StatusStandBy:
			if m.cfg.Verbose {
				log.Printf("Vault status: %s", status)
			}
		default:
			log.Printf("Vault status: %s", status)
		}

		if m.cfg.CheckInterval <= 0 {
			log.Printf("Check interval set to less than 0, exiting.")
			return nil
		}

		if m.cfg.Verbose {
			log.Printf("Next check in %s", m.cfg.CheckInterval)
		}

		<-time.After(m.cfg.CheckInterval)
	}
}

func (m *Manager) initialize(ctx context.Context) error {
	ir, err := m.va.Init(
		&vault.InitRequest{
			SecretShares:      m.cfg.VaultSecretShares,
			SecretThreshold:   m.cfg.VaultSecretThreshold,
			StoredShares:      m.cfg.VaultStoredShares,
			RecoveryShares:    m.cfg.VaultRecoveryShares,
			RecoveryThreshold: m.cfg.VaultRecoveryThreshold,
		},
	)

	if err != nil {
		return err
	}

	log.Println("Encrypting unseal keys and the root token...")

	rt, err := m.ks.Encrypt(m.cfg.KmsKeyID, ir.RootToken)
	if err != nil {
		return err
	}

	// Save the encrypted root token.
	if err := m.ss.Put(ctx, rootTokenEnc, rt); err != nil {
		log.Println(err)
	}

	log.Printf("Root token written to gs://%s/%s", m.cfg.GcsBucketName, rootTokenEnc)

	uk, err := m.ks.Encrypt(m.cfg.KmsKeyID, ir)
	if err != nil {
		return err
	}

	// Save the encrypted root token.
	if err := m.ss.Put(ctx, unsealKeysEnc, uk); err != nil {
		log.Println(err)
	}

	log.Printf("Unseal keys written to gs://%s/%s", m.cfg.GcsBucketName, unsealKeysEnc)

	log.Println("Initialization complete.")

	return nil
}

func (m *Manager) unseal(ctx context.Context) error {
	data, err := m.ss.Get(ctx, unsealKeysEnc)
	if err != nil {
		return err
	}

	var ir vault.InitResponse

	err = m.ks.Decrypt(m.cfg.KmsKeyID, data, &ir)
	if err != nil {
		return err
	}

	for _, key := range ir.KeysBase64 {
		done, err := unsealOne(m.va, key)
		if done {
			return nil
		}

		if err != nil {
			return err
		}
	}

	return nil
}

func unsealOne(va vault.API, key string) (bool, error) {
	resp, err := va.Unseal(
		&vault.UnsealRequest{
			Key: key,
		},
	)
	if err != nil {
		return false, err
	}

	return !resp.Sealed, nil
}
