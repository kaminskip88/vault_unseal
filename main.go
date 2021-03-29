package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	consul "github.com/hashicorp/consul/api"
	vault "github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
)

const (
	defaultKeyPath      = "./key.pem"
	defaultConsulSchema = "http"
	defaultKeysKVPath   = "vaultinit/keys"
)

var httpClient = &http.Client{
	Timeout: 10 * time.Second,
}

func main() {
	keyPath := flag.String("rsa", defaultKeyPath, "path to RSA key file")
	vaultAddr := flag.String("vault-addr", os.Getenv("VAULT_ADDR"), "Vault address")
	consulAddr := flag.String("consul-addr", os.Getenv("CONSUL_HTTP_ADDR"), "Consul address")
	consulSchema := flag.String("consul-scheme", defaultConsulSchema, "Consul address scheme")
	keysKVPath := flag.String("kv-path", defaultKeysKVPath, "path to Consul KV key")
	flag.Parse()

	// vault client
	vaultC, err := vault.NewClient(&vault.Config{Address: *vaultAddr, HttpClient: httpClient})
	check(err, "failed to connect to Vault API")

	// check seal status
	sealStat, err := vaultC.Sys().SealStatus()
	check(err, "unable to get seal status")

	// exit if Vault not initialized
	if !sealStat.Initialized {
		log.Info("Vault not initialized, exiting.")
		os.Exit(0)
	}
	// exit if Vault already unsealed
	if !sealStat.Sealed {
		log.Info("Vault already unsealed, exiting.")
		os.Exit(0)
	}

	// consul client
	consulC, err := consul.NewClient(&consul.Config{Address: *consulAddr, Scheme: *consulSchema, HttpClient: httpClient})
	check(err, "failed to connect to Consul API")

	// read key from file
	rsaKeyRaw, err := ioutil.ReadFile(*keyPath)
	check(err, fmt.Sprintf("failed to read file: %s", *keyPath))
	rsaKey := bytesToPrivateKey(rsaKeyRaw)

	// read keys from consul decode and decrypt
	val, _, err := consulC.KV().Get(*keysKVPath, nil)
	check(err, fmt.Sprintf("failed to read Consul Key %s", *keysKVPath))
	vDec, err := base64.StdEncoding.DecodeString(string(val.Value))
	check(err, fmt.Sprintf("failed to decode base64 string: %s", val.Value))
	keysS := decryptWithPrivateKey(vDec, rsaKey)

	// split keys string
	keys := strings.Split(string(keysS), ",")
	// check if we got enough keys to unseal
	if len(keys) < sealStat.T {
		log.Fatalf("Not enough key shards to unseal,  required: %o, provided: %o", sealStat.T, len(keys))
	}
	// unseal
	for _, i := range keys {
		s, err := vaultC.Sys().Unseal(i)
		check(err, "failed to unseal Vault")
		if !s.Sealed {
			log.Info("Vault unsealed")
			os.Exit(0)
		}
	}
	log.Fatal("Used all keys, but vault still sealed =(")
}

// decode string to *rsa.PrivateKey
func bytesToPrivateKey(priv []byte) *rsa.PrivateKey {
	block, _ := pem.Decode(priv)
	var err error
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	check(err, "failed to read RSA key")
	return key
}

// decrypt string with RSA private key
func decryptWithPrivateKey(ciphertext []byte, priv *rsa.PrivateKey) []byte {
	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
	check(err, "failed to decrypt text with RSA key")
	return plaintext
}

// error wrapper
func check(err error, msg string) {
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Fatal(msg)
	}
}
