package main

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"maps"
	"net/mail"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/template"

	flag "github.com/spf13/pflag"
	"go.turscar.ie/dkim2"
)

const baseMessage = `From: DKIM2 testing <{{ .From }}>
Subject: {{ .Subject }}
Date: Tue, 24 Feb 2026 08:00:00 +0000
To: {{ .To }}

{{ .Body }}
`

const defaultDomain = "dkim2test.turscar.ie"

type Variant struct {
	Name     string
	Template string
	Domain   string
	KeyName  string
	Selector string
	Nonce    string
	Time     int64
	From     string
	To       string

	Whitespace string
	Rotate     int
	CapKey     bool
	CapFrom    bool
	CapTo      bool
}

var baseDomain string
var dir string

func main() {
	var private, public bool
	flag.StringVar(&baseDomain, "domain", defaultDomain, "Domain for publishing keys")
	flag.StringVar(&dir, "dir", "", "Target directory")
	flag.BoolVar(&private, "private", false, "Generate private keys")
	flag.BoolVar(&public, "public", false, "Generate public keys")
	flag.Parse()

	if dir == "" {
		log.Fatal("--dir is required")
	}

	if private {
		generatePrivateKeys(dir)
	}
	if public {
		generatePublicKeys(baseDomain, dir)
	}

	//XXXX mangle
}

func makeSignedMessage(v Variant) []byte {
	tpl, err := template.New("message").Parse(v.Template)
	if err != nil {
		log.Fatal(err)
	}
	var buf bytes.Buffer
	err = tpl.Execute(&buf, struct {
		From    string
		To      string
		Subject string
		Body    string
	}{
		From:    v.From,
		To:      v.To,
		Subject: v.Name,
	})
	if err != nil {
		log.Fatal(err)
	}
	unsignedMessage := buf.Bytes()

	keyFilename := filepath.Join(dir, "keys", v.KeyName+".pem")
	k, err := loadPrivateKey(keyFilename)
	if err != nil {
		log.Fatal(err)
	}
	keys := []dkim2.SigningKey{
		{
			Selector: v.Selector,
			Signer:   k,
		},
	}

	msg, err := mail.ReadMessage(bytes.NewReader(unsignedMessage))
	if err != nil {
		log.Fatal(err)
	}

	headers, err := dkim2.SignMessage(msg, dkim2.SignOptions{
		Nonce:         v.Nonce,
		Timestamp:     v.Time,
		Domain:        v.Domain,
		Keys:          keys,
		MailFrom:      v.From,
		RcptTo:        []string{v.To},
		Modifications: nil,
	})
	var miHeader, d2Header string
	_, _ = miHeader, d2Header
	for _, h := range headers {
		//XXXX pull out the two headers
		_ = h
	}
	if err != nil {
		log.Fatal(err)
	}
	return nil
}

func generatePublicKeys(domain, dir string) {
	dns := map[string]string{}
	for _, keyLength := range []int{512, 1024, 1536, 2048, 4096, 5120} {
		filename := filepath.Join(dir, "keys", fmt.Sprintf("rsa%d.pem", keyLength))
		pk, err := loadPrivateKey(filename)
		if err != nil {
			log.Fatal(err)
		}
		privateKey := pk.(*rsa.PrivateKey)
		pubKey := privateKey.Public()
		der := x509.MarshalPKCS1PublicKey(pubKey.(*rsa.PublicKey))
		txt := fmt.Sprintf("v=DKIM1; k=rsa; p=%s", base64.StdEncoding.EncodeToString(der))
		hostname := fmt.Sprintf("rsa%d._domainkey.%s", keyLength, domain)
		dns[hostname] = txt
		der, err = x509.MarshalPKIXPublicKey(pubKey.(*rsa.PublicKey))
		if err != nil {
			log.Fatal(err)
		}
		txt = fmt.Sprintf("v=DKIM1; k=rsa; p=%s", base64.StdEncoding.EncodeToString(der))
		hostname = fmt.Sprintf("pkix-rsa%d._domainkey.%s", keyLength, domain)
		dns[hostname] = txt
	}
	filename := filepath.Join(dir, "keys", "ed25519.pem")
	pk, err := loadPrivateKey(filename)
	if err != nil {
		log.Fatal(err)
	}
	privateKey := pk.(ed25519.PrivateKey)
	pubKey := privateKey.Public()
	txt := fmt.Sprintf("v=DKIM1; k=rsa; p=%s", base64.StdEncoding.EncodeToString(pubKey.(ed25519.PublicKey)))
	hostname := fmt.Sprintf("ed25519._domainkey.%s", domain)
	dns[hostname] = txt
	f, err := os.Create(filepath.Join(dir, "dns.json"))
	if err != nil {
		log.Fatal(err)
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(f)
	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	err = encoder.Encode(dns)
	if err != nil {
		log.Fatal(err)
	}
	dnsf, err := os.Create(filepath.Join(dir, "dns.txt"))
	if err != nil {
		log.Fatal(err)
	}
	defer func(dnsf *os.File) {
		_ = dnsf.Close()
	}(dnsf)
	for _, k := range slices.Sorted(maps.Keys(dns)) {
		v := dns[k]
		var rec []string
		for len(v) > 200 {
			rec = append(rec, fmt.Sprintf("%q", v[:200]))
			v = v[200:]
		}
		if len(v) > 0 {
			rec = append(rec, fmt.Sprintf("%q", v))
		}
		_, _ = fmt.Fprintf(dnsf, "%s 3600 IN TXT %s\n", k, strings.Join(rec, " "))
	}
}

func loadPrivateKey(filename string) (crypto.Signer, error) {
	keyfile, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read keyfile: %w", err)
	}
	pemBlock, _ := pem.Decode(keyfile)
	if pemBlock != nil && pemBlock.Type == "PRIVATE KEY" {
		key, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key %s: %w", filename, err)
		}

		switch key := key.(type) {
		case *rsa.PrivateKey:
			return key, nil
		case ed25519.PrivateKey:
			return key, nil
		}
	}

	return nil, fmt.Errorf("failed to parse private key")
}

func generatePrivateKeys(dir string) {
	_ = os.Setenv("GODEBUG", os.Getenv("GODEBUG")+",rsa1024min=0")
	_ = os.MkdirAll(filepath.Join(dir, "keys"), 0755)
	for _, keyLength := range []int{512, 1024, 1536, 2048, 4096, 5120} {
		filename := filepath.Join(dir, "keys", fmt.Sprintf("rsa%d.pem", keyLength))
		if _, err := os.Stat(filename); err == nil {
			log.Fatalf("%s already exists; not overwriting", filename)
		}
		privateKey, err := rsa.GenerateKey(nil, keyLength)
		if err != nil {
			log.Fatal(err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			log.Fatal(err)
		}
		f, err := os.Create(filename)
		if err != nil {
			log.Fatal(err)
		}
		err = pem.Encode(f, &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: der,
		})
		if err != nil {
			log.Fatal(err)
		}
		_ = f.Close()
	}
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}
	filename := filepath.Join(dir, "keys", "ed25519.pem")
	if _, err := os.Stat(filename); err == nil {
		log.Fatalf("%s already exists; not overwriting", filename)
	}
	f, err := os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	err = pem.Encode(f, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})
	if err != nil {
		log.Fatal(err)
	}
	_ = f.Close()
}
