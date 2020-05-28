// Copyright 2018 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/spf13/pflag"

	"github.com/sethvargo/vault-init/client"
	"github.com/sethvargo/vault-init/kms"
	"github.com/sethvargo/vault-init/storage"
	"github.com/sethvargo/vault-init/vault"
)

var (
	// version flags
	version = "dev"
	commit  = "none"
	date    = "unknown"

	vaultAddr     string
	gcsBucketName string

	vaultSecretShares      int
	vaultSecretThreshold   int
	vaultStoredShares      int
	vaultRecoveryShares    int
	vaultRecoveryThreshold int

	kmsKeyId string

	userAgent = fmt.Sprintf("vault-init/1.0.0 (%s)", runtime.Version())

	vaultApi       vault.API
	kmsService     kms.Service
	storageService storage.Service
)

func main() {
	var (
		showVersion bool
	)

	pflag.BoolVar(&showVersion, "version", false, "Prints version info")

	pflag.Parse()

	if showVersion {
		fmt.Printf("Version    : %s\n", version)
		fmt.Printf("Git Commit : %s\n", commit)
		fmt.Printf("Build Date : %s\n", date)
		os.Exit(0)
	}

	log.Println("Starting the vault-init service...")

	//vaultAddr = os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "http://127.0.0.1:8200"
	}

	vaultSecretShares = intFromEnv("VAULT_SECRET_SHARES", 5)
	vaultSecretThreshold = intFromEnv("VAULT_SECRET_THRESHOLD", 3)

	vaultInsecureSkipVerify := boolFromEnv("VAULT_SKIP_VERIFY", false)

	vaultAutoUnseal := boolFromEnv("VAULT_AUTO_UNSEAL", true)

	if vaultAutoUnseal {
		vaultStoredShares = intFromEnv("VAULT_STORED_SHARES", 1)
		vaultRecoveryShares = intFromEnv("VAULT_RECOVERY_SHARES", 1)
		vaultRecoveryThreshold = intFromEnv("VAULT_RECOVERY_THRESHOLD", 1)
	}

	checkInterval := durFromEnv("CHECK_INTERVAL", 10*time.Second)

	gcsBucketName = os.Getenv("GCS_BUCKET_NAME")
	if gcsBucketName == "" {
		log.Fatal("GCS_BUCKET_NAME must be set and not empty")
	}

	kmsKeyId = os.Getenv("KMS_KEY_ID")
	if kmsKeyId == "" {
		log.Fatal("KMS_KEY_ID must be set and not empty")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var err error

	kmsService, err = kms.NewService(ctx, userAgent)
	if err != nil {
		log.Fatalln(err)
	}

	storageService, err = storage.NewStorage(ctx, userAgent, gcsBucketName)
	if err != nil {
		log.Fatalln(err)
	}

	vc, err := client.NewClient(
		&client.Config{
			Address: vaultAddr,
			HttpClient: &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: vaultInsecureSkipVerify,
					},
				},
			},
		},
	)
	if err != nil {
		log.Fatal(err)
	}

	vaultApi = vault.NewVaultAPI(vc)

	// graceful shutdown
	signalCh := make(chan os.Signal, 1)

	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)

	stop := func() {
		log.Printf("Shutting down")
		cancel()
		os.Exit(0)
	}

	for {

		select {
		case <-signalCh:
			stop()
		default:
			// intentional left blank
		}

		status, err := vaultApi.Status()

		if err != nil {
			log.Println(err)
		}

		switch status {
		case vault.StatusNotInit:
			log.Println("Vault is not initialized.")
			log.Println("Initializing...")
			initialize()
			if !vaultAutoUnseal {
				log.Println("Unsealing...")
				unseal()
			}
		case vault.StatusSealed:
			log.Println("Vault is sealed.")
			if !vaultAutoUnseal {
				log.Println("Unsealing...")
				unseal()
			}
		default:
			log.Printf("Vault status: %s", status)
		}

		if checkInterval <= 0 {
			log.Printf("Check interval set to less than 0, exiting.")
			stop()
		}

		log.Printf("Next check in %s", checkInterval)

		select {
		case <-signalCh:
			stop()
		case <-time.After(checkInterval):
		}
	}
}

func initialize() {

	initResponse, err := vaultApi.Init(
		&vault.InitRequest{
			SecretShares:      vaultSecretShares,
			SecretThreshold:   vaultSecretThreshold,
			StoredShares:      vaultStoredShares,
			RecoveryShares:    vaultRecoveryShares,
			RecoveryThreshold: vaultRecoveryThreshold,
		},
	)
	if err != nil {
		log.Println(err)
		return
	}

	log.Println("Encrypting unseal keys and the root token...")

	ctx := context.Background()

	rt, err := kmsService.Encrypt(kmsKeyId, initResponse.RootToken)
	if err != nil {
		log.Println(err)
		return
	}

	// Save the encrypted root token.
	if err := storageService.Put(ctx, "root-token.enc", rt); err != nil {
		log.Println(err)
	}

	log.Printf("Root token written to gs://%s/%s", gcsBucketName, "root-token.enc")

	uk, err := kmsService.Encrypt(kmsKeyId, initResponse)
	if err != nil {
		log.Println(err)
		return
	}

	// Save the encrypted root token.
	if err := storageService.Put(ctx, "unseal-keys.json.enc", uk); err != nil {
		log.Println(err)
	}

	log.Printf("Unseal keys written to gs://%s/%s", gcsBucketName, "unseal-keys.json.enc")

	log.Println("Initialization complete.")
}

func unseal() {
	ctx := context.Background()

	data, err := storageService.Get(ctx, "unseal-keys.json.enc")
	if err != nil {
		log.Println(err)
		return
	}

	var initResponse vault.InitResponse

	err = kmsService.Decrypt(kmsKeyId, data, &initResponse)
	if err != nil {
		log.Println(err)
		return
	}

	for _, key := range initResponse.KeysBase64 {
		done, err := unsealOne(key)
		if done {
			return
		}

		if err != nil {
			log.Println(err)
			return
		}
	}
}

func unsealOne(key string) (bool, error) {
	unsealResponse, err := vaultApi.Unseal(
		&vault.UnsealRequest{
			Key: key,
		},
	)
	if err != nil {
		return false, err
	}

	return !unsealResponse.Sealed, nil
}

func boolFromEnv(env string, def bool) bool {
	val := os.Getenv(env)
	if val == "" {
		return def
	}
	b, err := strconv.ParseBool(val)
	if err != nil {
		log.Fatalf("failed to parse %q: %s", env, err)
	}
	return b
}

func intFromEnv(env string, def int) int {
	val := os.Getenv(env)
	if val == "" {
		return def
	}
	i, err := strconv.Atoi(val)
	if err != nil {
		log.Fatalf("failed to parse %q: %s", env, err)
	}
	return i
}

func durFromEnv(env string, def time.Duration) time.Duration {
	val := os.Getenv(env)
	if val == "" {
		return def
	}
	r := val[len(val)-1]
	if r >= '0' || r <= '9' {
		val = val + "s" // assume seconds
	}
	d, err := time.ParseDuration(val)
	if err != nil {
		log.Fatalf("failed to parse %q: %s", env, err)
	}
	return d
}
