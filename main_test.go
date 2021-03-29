package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"testing"
)

func TestBytesToPrivateKey(t *testing.T) {
	result := bytesToPrivateKey([]byte(privKey))
	pubBlock, _ := pem.Decode([]byte(pubKey))
	pubKey, _ := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if !result.PublicKey.Equal(pubKey) {
		t.Error("Resulting key not matching cert")
	}
}

func TestDecryptWithPrivateKey(t *testing.T) {
	priv := bytesToPrivateKey([]byte(privKey))
	ub64, _ := base64.StdEncoding.DecodeString(enc)
	fmt.Println(string(ub64))
	result := decryptWithPrivateKey(ub64, priv)
	if string(result) != "hello" {
		t.Errorf("Unencrypted text not matching. expected: 'hello' got: '%s'", result)
	}

}

var enc = "cbzkZbKhOgpFBOVvWC7rQXaAvVPMI3o8Y72eBhTy9bRUC3mwQNu7TSmCOkcjR8az0JlVn0nnBgKbUsCfTdQVwg=="

var privKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBALY2g0/xqZkslBZqtJoi8Z4s/C+nKW+WqwvarjEK8kraWjzUT0nG
fe48WgUcVkZcC+REbopD4j1CvFI/VpyL9lcCAwEAAQJALyuxltKS+0plE+CP3I9L
SY2Pw65ctbyljy4Phja1PtcTmvILT1BAKvF5cgK/Aey7thyE7HJ3xZZc93m9GIhf
UQIhAPGHHeMoeggCCCnPDgDqhmkgF91ifen/SuJSueFVukoDAiEAwSGLO9rerk6u
GgIGtpUGlwtkBMCxxv2gauKZo3md3B0CICErFQek/10qKkTTknC9xEebiKt2YyRH
UtlR0wUG6NZRAiEAv12ngvWKdJkNtkOPt1bPItdskbEF9rDVRVOm/O7C1pkCIQDt
hW+hmUaBoF4SAKxmVsr+pYq2S5yVvppFCGFzMUJlfg==
-----END RSA PRIVATE KEY-----
`

var pubKey = `
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALY2g0/xqZkslBZqtJoi8Z4s/C+nKW+W
qwvarjEK8kraWjzUT0nGfe48WgUcVkZcC+REbopD4j1CvFI/VpyL9lcCAwEAAQ==
-----END PUBLIC KEY-----
`
