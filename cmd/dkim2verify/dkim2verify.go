package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"

	flag "github.com/spf13/pflag"
	"go.turscar.ie/dkim2"
)

var version, commit, date, builtBy string

func main() {
	var in, mailFrom, dnsServer, dns string
	var rcptTo []string
	var printVersion bool
	ignoreTimestamp := true

	flag.StringVar(&in, "in", "-", "input file")
	flag.BoolVar(&ignoreTimestamp, "ignore-timestamp", true, "ignore timestamp")
	flag.StringVar(&mailFrom, "from", "", "mail from")
	flag.StringSliceVar(&rcptTo, "to", nil, "rcpt to")
	flag.StringVar(&dns, "txt", "", "public key TXT record")
	flag.StringVar(&dnsServer, "server", "", "dns server")
	flag.BoolVar(&printVersion, "version", false, "print version")

	flag.Parse()

	if printVersion {
		fmt.Printf("Version: %s\nCommit: %s\nDate: %s\nBuiltBy: %s\nSpec: %s\n", version, commit, date, builtBy, dkim2.Spec)
		os.Exit(0)
	}

	var inFile io.Reader
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

	var resolver dkim2.KeyResolver
	if dns != "" {
		resolver = StaticResolver{dns}
	} else {
		var err error
		resolver, err = dkim2.NewDnsResolver(dnsServer)
		if err != nil {
			log.Fatal(err)
		}
	}

	verifyOpts := dkim2.VerifyOptions{
		IgnoreTimestamp: ignoreTimestamp,
		Resolver:        resolver,
		MailFrom:        mailFrom,
		RcptTo:          rcptTo,
	}

	result, _ := dkim2.VerifyAll(context.Background(), inFile, verifyOpts)
	fmt.Printf("Authentication result: %s\n", result.AuthenticationResult())
	if result.Err != nil {
		fmt.Printf("Error: %s\n", errors.Unwrap(result.Err))
	}
}

type StaticResolver struct {
	Txt string
}

func (s StaticResolver) Resolve(_ context.Context, _ string, _ string) ([]string, error) {
	return []string{s.Txt}, nil
}

var _ dkim2.KeyResolver = StaticResolver{}
