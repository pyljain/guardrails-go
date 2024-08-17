package utils

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func SignContent(content string) (string, error) {
	sha := sha256.New()
	sha.Write([]byte(content))
	hash := sha.Sum([]byte{})

	pk, err := os.ReadFile("key.pem")
	if err != nil {
		return "", err
	}

	privateKeyBlock, _ := pem.Decode(pk)
	privateKey, err := x509.ParsePKCS8PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return "", err
	}

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey.(*rsa.PrivateKey), crypto.SHA256, hash[:])
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", signature), nil
}
