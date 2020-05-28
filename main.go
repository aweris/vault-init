// Copyright 2018 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/option"

	"github.com/spf13/pflag"

	"github.com/sethvargo/vault-init/client"
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

	kmsService *cloudkms.Service
	kmsKeyId   string

	storageClient *storage.Client

	userAgent = fmt.Sprintf("vault-init/1.0.0 (%s)", runtime.Version())

	vaultApi vault.API
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

	vaultAddr = os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "https://127.0.0.1:8200"
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

	kmsCtx, kmsCtxCancel := context.WithCancel(context.Background())
	defer kmsCtxCancel()

	kmsService, err := cloudkms.NewService(kmsCtx, option.WithScopes(cloudkms.CloudkmsScope))
	if err != nil {
		log.Println(err)
		return
	}
	kmsService.UserAgent = userAgent

	storageCtx, storageCtxCancel := context.WithCancel(context.Background())
	defer storageCtxCancel()
	storageClient, err = storage.NewClient(storageCtx,
		option.WithUserAgent(userAgent),
		option.WithScopes(storage.ScopeReadWrite),
	)
	if err != nil {
		log.Fatal(err)
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
		kmsCtxCancel()
		storageCtxCancel()
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

	rootTokenEncryptRequest := &cloudkms.EncryptRequest{
		Plaintext: base64.StdEncoding.EncodeToString([]byte(initResponse.RootToken)),
	}

	rootTokenEncryptResponse, err := kmsService.Projects.Locations.KeyRings.CryptoKeys.Encrypt(kmsKeyId, rootTokenEncryptRequest).Do()
	if err != nil {
		log.Println(err)
		return
	}

	data, err := json.Marshal(initResponse)
	if err != nil {
		log.Println(err)
		return
	}

	unsealKeysEncryptRequest := &cloudkms.EncryptRequest{
		Plaintext: base64.StdEncoding.EncodeToString(data),
	}

	unsealKeysEncryptResponse, err := kmsService.Projects.Locations.KeyRings.CryptoKeys.Encrypt(kmsKeyId, unsealKeysEncryptRequest).Do()
	if err != nil {
		log.Println(err)
		return
	}

	bucket := storageClient.Bucket(gcsBucketName)

	// Save the encrypted unseal keys.
	ctx := context.Background()
	unsealKeysObject := bucket.Object("unseal-keys.json.enc").NewWriter(ctx)
	defer unsealKeysObject.Close()

	_, err = unsealKeysObject.Write([]byte(unsealKeysEncryptResponse.Ciphertext))
	if err != nil {
		log.Println(err)
	}

	log.Printf("Unseal keys written to gs://%s/%s", gcsBucketName, "unseal-keys.json.enc")

	// Save the encrypted root token.
	rootTokenObject := bucket.Object("root-token.enc").NewWriter(ctx)
	defer rootTokenObject.Close()

	_, err = rootTokenObject.Write([]byte(rootTokenEncryptResponse.Ciphertext))
	if err != nil {
		log.Println(err)
	}

	log.Printf("Root token written to gs://%s/%s", gcsBucketName, "root-token.enc")

	log.Println("Initialization complete.")
}

func unseal() {
	bucket := storageClient.Bucket(gcsBucketName)

	ctx := context.Background()
	unsealKeysObject, err := bucket.Object("unseal-keys.json.enc").NewReader(ctx)
	if err != nil {
		log.Println(err)
		return
	}

	defer unsealKeysObject.Close()

	unsealKeysData, err := ioutil.ReadAll(unsealKeysObject)
	if err != nil {
		log.Println(err)
		return
	}

	unsealKeysDecryptRequest := &cloudkms.DecryptRequest{
		Ciphertext: string(unsealKeysData),
	}

	unsealKeysDecryptResponse, err := kmsService.Projects.Locations.KeyRings.CryptoKeys.Decrypt(kmsKeyId, unsealKeysDecryptRequest).Do()
	if err != nil {
		log.Println(err)
		return
	}

	var initResponse vault.InitResponse

	unsealKeysPlaintext, err := base64.StdEncoding.DecodeString(unsealKeysDecryptResponse.Plaintext)
	if err != nil {
		log.Println(err)
		return
	}

	if err := json.Unmarshal(unsealKeysPlaintext, &initResponse); err != nil {
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
