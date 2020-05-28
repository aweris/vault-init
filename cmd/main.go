// Copyright 2018 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/spf13/pflag"

	"github.com/aweris/vault-init/manager"
)

var (
	// version flags
	version = "dev"
	//nolint:gochecknoglobals
	commit = "none"
	//nolint:gochecknoglobals
	date = "unknown"
)

//nolint:funlen
func main() {
	var (
		cfg = &manager.Config{
			UserAgent: fmt.Sprintf("vault-init/%s (%s)", version, runtime.Version()),
		}

		showVersion bool
	)

	pflag.BoolVar(
		&cfg.VaultInsecureSkipVerify,
		"vault-skip-verify",
		false,
		"Disable TLS validation when connecting. Setting to true is highly discouraged.",
	)
	pflag.BoolVar(
		&cfg.VaultAutoUnseal,
		"vault-auto-unseal",
		true,
		"Use Vault 1.0 native auto-unsealing directly. You must set the seal configuration in Vault's configuration.",
	)
	pflag.IntVar(
		&cfg.VaultSecretShares,
		"vault-secret-shares",
		5,
		"The number of human shares to create.",
	)
	pflag.IntVar(
		&cfg.VaultSecretThreshold,
		"vault-secret-threshold",
		3,
		"The number of human shares required to unseal.",
	)
	pflag.IntVar(
		&cfg.VaultStoredShares,
		"vault-stored-shares",
		1,
		"Number of shares to store on KMS. Only applies to Vault 1.0 native auto-unseal.",
	)
	pflag.IntVar(
		&cfg.VaultRecoveryShares,
		"vault-recovery-shares",
		1,
		"Number of recovery shares to generate. Only applies to Vault 1.0 native auto-unseal.",
	)
	pflag.IntVar(
		&cfg.VaultRecoveryThreshold,
		"vault-recovery-threshold",
		1,
		" Number of recovery shares needed to unseal. Only applies to Vault 1.0 native auto-unseal.",
	)
	pflag.StringVar(
		&cfg.VaultAddress,
		"vault-addr",
		"https://127.0.0.1:8200",
		"Address of the vault service",
	)
	pflag.StringVar(
		&cfg.VaultCACert,
		"vault-cacert",
		"",
		"Path to a PEM-encoded CA certificate file on the local disk",
	)
	pflag.DurationVar(
		&cfg.CheckInterval,
		"check-interval",
		30*time.Second, //nolint:gomnd
		"The time duration between Vault health checks. Set this to a negative number to unseal once and exit.",
	)
	pflag.StringVar(
		&cfg.GcsBucketName,
		"gcs-bucket-name",
		"",
		"The Google Cloud Storage Bucket where the vault master key and root token is stored.",
	)
	pflag.StringVar(
		&cfg.KmsKeyID,
		"kms-key-id",
		"",
		"The Google Cloud KMS key ID used to encrypt and decrypt the vault master key and root token.",
	)
	pflag.BoolVar(
		&showVersion,
		"version",
		false,
		"Prints version info",
	)

	bindEnv(pflag.Lookup("vault-addr"), "VAULT_ADDR")
	bindEnv(pflag.Lookup("vault-cacert"), "VAULT_CACERT")

	bindEnv(pflag.Lookup("vault-secret-shares"), "VAULT_SECRET_SHARES")
	bindEnv(pflag.Lookup("vault-secret-threshold"), "VAULT_SECRET_THRESHOLD")

	bindEnv(pflag.Lookup("vault-skip-verify"), "VAULT_SKIP_VERIFY")

	bindEnv(pflag.Lookup("vault-auto-unseal"), "VAULT_AUTO_UNSEAL")
	bindEnv(pflag.Lookup("vault-stored-shares"), "VAULT_STORED_SHARES")
	bindEnv(pflag.Lookup("vault-recovery-shares"), "VAULT_RECOVERY_SHARES")
	bindEnv(pflag.Lookup("vault-recovery-threshold"), "VAULT_RECOVERY_THRESHOLD")

	bindEnv(pflag.Lookup("check-interval"), "CHECK_INTERVAL")
	bindEnv(pflag.Lookup("gcs-bucket-name"), "GCS_BUCKET_NAME")
	bindEnv(pflag.Lookup("kms-key-id"), "KMS_KEY_ID")

	pflag.Parse()

	if showVersion {
		fmt.Printf("Version    : %s\n", version)
		fmt.Printf("Git Commit : %s\n", commit)
		fmt.Printf("Build Date : %s\n", date)
		os.Exit(0)
	}

	log.Println("Starting the vault-init service...")

	if cfg.GcsBucketName == "" {
		log.Fatal("missing GCS_BUCKET_NAME")
	}

	if cfg.KmsKeyID == "" {
		log.Fatal("missing KMS_KEY_ID")
	}

	ctx, cancel := context.WithCancel(context.Background())

	m, err := manager.NewManager(ctx, cfg)
	if err != nil {
		log.Fatalln(err)
	}

	// graceful shutdown
	c := make(chan os.Signal, 1)

	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		oscall := <-c

		log.Printf("system call:%+v", oscall)

		cancel()

		os.Exit(0)
	}()

	// start manager
	err = m.Start(ctx)
	if err != nil {
		log.Fatalln(err)
	}
}

func bindEnv(fn *pflag.Flag, env string) {
	if fn == nil || fn.Changed {
		return
	}

	val := os.Getenv(env)

	if len(val) > 0 {
		if err := fn.Value.Set(val); err != nil {
			log.Fatalf("failed to bind env: %v\n", err)
		}
	}
}
