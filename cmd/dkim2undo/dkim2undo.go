package main

import (
	"io"
	"log"
	"os"

	flag "github.com/spf13/pflag"
)

func main() {
	targetM := 0
	var in, out string
	flag.IntVar(&targetM, "targetM", 0, "targetM")
	flag.StringVar(&in, "in", "-", "input")
	flag.StringVar(&out, "out", "-", "output")
	flag.Parse()

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
}
