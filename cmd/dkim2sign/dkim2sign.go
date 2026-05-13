package main

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/mail"
	"os"
	"regexp"
	"strings"

	flag "github.com/spf13/pflag"

	"go.turscar.ie/dkim2"
)

var version, commit, date, builtBy string

func main() {
	var in, out, domain, selector, nonce, mailFrom, keyfile string
	var rcptTo []string
	var exploded, donotexplode, donotmodify, feedback, fixup bool
	var timestamp int64
	var printVersion bool

	now := dkim2.Now()

	flag.StringVar(&in, "in", "-", "input file")
	flag.StringVar(&out, "out", "-", "output file")
	flag.StringVar(&domain, "domain", "", "domain")
	flag.StringVar(&selector, "selector", "", "selector")
	flag.StringVar(&keyfile, "key", "", "file containing private key")
	flag.StringVar(&mailFrom, "from", "", "mail from")
	flag.StringSliceVar(&rcptTo, "to", []string{}, "rcpt to")
	flag.StringVar(&nonce, "nonce", "", "nonce")
	flag.Int64Var(&timestamp, "timestamp", now, "signing timestamp (epoch seconds)")
	flag.BoolVar(&donotexplode, "donottexplode", false, "set donottexplode flag")
	flag.BoolVar(&donotmodify, "donotmodify", false, "set donotmodify flag")
	flag.BoolVar(&exploded, "exploded", false, "set exploded flag")
	flag.BoolVar(&feedback, "feedback", false, "set feedback flag")
	flag.BoolVar(&fixup, "fixup", true, "fix line endings on input")
	flag.BoolVar(&printVersion, "version", false, "print version")

	flag.Parse()

	if printVersion {
		fmt.Printf("Version: %s\nCommit: %s\nDate: %s\nBuiltBy: %s\nSpec: %s\n", version, commit, date, builtBy, dkim2.Spec)
		os.Exit(0)
	}

	if keyfile == "" {
		log.Fatalf("--key flag is required")
	}
	if domain == "" {
		log.Fatalf("--domain flag is required")
	}
	if selector == "" {
		log.Fatalf("--selector flag is required")
	}

	var inFile io.Reader
	var outFile io.Writer
	switch in {
	case "-", "":
		inFile = os.Stdin
	default:
		inF, err := os.Open(in)
		if err != nil {
			log.Fatal(err)
		}
		defer func(inF *os.File) {
			_ = inF.Close()
		}(inF)
		inFile = inF
	}

	input, err := io.ReadAll(inFile)
	if err != nil {
		log.Fatal(err)
	}
	if fixup {
		input = regexp.MustCompile(`\r?\n`).ReplaceAll(input, []byte("\r\n"))
	}

	privateKey, err := loadPrivateKey(keyfile)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(input)
	message, err := mail.ReadMessage(bytes.NewReader(input))
	if err != nil {
		log.Fatal(fmt.Errorf("error parsing input message: %w", err))
	}

	if mailFrom == "" {
		froms, err := mail.ParseAddressList(message.Header.Get("From"))
		if err != nil {
			log.Printf("Failed to parse mail from address: %s\n", err)
		} else if len(froms) > 0 {
			mailFrom = froms[0].Address
		}
	}

	if len(rcptTo) == 0 {
		tos, err := mail.ParseAddressList(message.Header.Get("To"))
		if err != nil {
			log.Printf("Failed to parse mail from address: %s\n", err)
		} else if len(tos) > 0 {
			for _, to := range tos {
				rcptTo = append(rcptTo, to.Address)
			}
		}
	}

	recipients := make([]string, 0, len(rcptTo))
	for i, rcpt := range rcptTo {
		recipients[i] = wrapAddress(rcpt)
	}
	options := dkim2.SignOptions{
		Nonce:     nonce,
		Timestamp: timestamp,
		Domain:    domain,
		Keys: []dkim2.SigningKey{
			{
				Selector: selector,
				Signer:   privateKey,
			},
		},
		Exploded:     exploded,
		DoNotExplode: donotexplode,
		DoNotModify:  donotmodify,
		Feedback:     feedback,
		ExtraFlags:   nil,
		Signature:    nil,
		MailFrom:     wrapAddress(mailFrom),
		RcptTo:       recipients,
	}

	switch out {
	case "-", "":
		outFile = os.Stdout
	default:
		outF, err := os.Create(out)
		if err != nil {
			log.Fatal(err)
		}
		defer func(outF *os.File) {
			_ = outF.Close()
		}(outF)
		outFile = outF
	}

	err = dkim2.Sign(outFile, bytes.NewReader(input), options)

	if err != nil {
		log.Fatal(err)
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
			return nil, fmt.Errorf("failed to parse private key: %w", err)
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

func wrapAddress(addr string) string {
	if !strings.HasPrefix(addr, "<") {
		addr = "<" + addr
	}
	if !strings.HasSuffix(addr, ">") {
		addr = addr + ">"
	}
	return addr
}
