package main

import (
	"fmt"
	"io"
	"log"
	"os"

	flag "github.com/spf13/pflag"
	"go.turscar.ie/dkim2"
)

var version, commit, date, builtBy string

func main() {
	targetM := 0
	var in, out string
	var printVersion bool

	flag.IntVar(&targetM, "targetM", 0, "targetM")
	flag.StringVar(&in, "in", "-", "input")
	flag.StringVar(&out, "out", "-", "output")
	flag.BoolVar(&printVersion, "version", false, "print version")

	flag.Parse()

	if printVersion {
		fmt.Printf("Version: %s\nCommit: %s\nDate: %s\nBuiltBy: %s\nSpec: %s\n", version, commit, date, builtBy, dkim2.Spec)
		os.Exit(0)
	}

	var inF io.Reader
	switch in {
	case "", "-":
		inF = os.Stdin
	default:
		f, err := os.Open(in)
		if err != nil {
			log.Fatal(err)
		}
		defer func(f *os.File) {
			err := f.Close()
			if err != nil {
				log.Fatal(err)
			}
		}(f)
		inF = f
	}

	var outF io.Writer
	switch out {
	case "", "-":
		outF = os.Stdout
	default:
		f, err := os.Create(out)
		if err != nil {
			log.Fatal(err)
		}
		defer func(f *os.File) {
			err := f.Close()
			if err != nil {
				log.Fatal(err)
			}
		}(f)
		outF = f
	}
	_, _ = inF, outF
}
