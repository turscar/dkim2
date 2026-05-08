package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"maps"
	"net/textproto"
	"os"
	"slices"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/jimtsao/go-email/folder"
	"github.com/sergi/go-diff/diffmatchpatch"
	flag "github.com/spf13/pflag"
	"go.turscar.ie/dkim2"
	"go.turscar.ie/theme"
)

var version, commit, date, builtBy string

func main() {
	targetM := 0
	var in, out string
	var printVersion bool
	var all, printJson, printDiff bool
	var revision int

	flag.IntVar(&targetM, "targetM", 0, "targetM")
	flag.StringVar(&in, "in", "-", "input")
	flag.StringVar(&out, "out", "-", "output")
	flag.BoolVar(&printVersion, "version", false, "print version")
	flag.BoolVar(&all, "all", false, "show all versions")
	flag.BoolVar(&printJson, "json", false, "show json output")
	flag.IntVar(&revision, "revision", 0, "print this revision")
	flag.BoolVar(&printDiff, "diff", false, "print diff")
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

	errorColor := lipgloss.NewStyle().Inline(true).Foreground(theme.Red)
	dividerColor := lipgloss.NewStyle().Inline(true).Foreground(theme.BrightWhite)
	titleColor := lipgloss.NewStyle().Inline(true).Foreground(theme.BrightMagenta)

	history, err := dkim2.MessageHistory(inF)
	if err != nil {
		printf(errorColor, "%v\n", err)
		os.Exit(1)
	}

	if revision > 0 {
		history = slices.DeleteFunc(history, func(h dkim2.VersionedMessage) bool {
			return h.Revision != revision
		})
		if len(history) == 0 {
			printf(errorColor, "Revision %d not found\n", revision)
			os.Exit(1)
		}
	}

	if !all {
		history = slices.CompactFunc(history, messageEqual)
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

	if printJson {
		type asString struct {
			Revision int
			Header   map[string][]string
			Body     string
		}
		his := make([]asString, len(history))
		for i, h := range history {
			his[i] = asString{
				Revision: h.Revision,
				Header:   h.Header,
				Body:     string(h.Body),
			}
		}
		enc := json.NewEncoder(outF)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		err := enc.Encode(his)
		if err != nil {
			log.Fatal(err)
		}
		return
	}

	if printDiff {
		texts := make([]string, len(history))
		for i, h := range history {
			texts[i] = foldedHeaders(h.Header) + "\r\n" + string(h.Body)
		}
		for i := 1; i < len(texts); i++ {
			printf(dividerColor, "==== ")
			printf(titleColor, " Message-Instance m=%d", history[i-1].Revision)
			printf(dividerColor, " ====")
			fmt.Println()

			dmp := diffmatchpatch.New()
			diffs := dmp.DiffMain(texts[i], texts[i-1], true)
			fmt.Println(dmp.DiffPrettyText(diffs))
		}
		return
	}

	if revision > 0 {
		// Print just one mail
		_, _ = fmt.Fprintf(outF, "%s\n%s\n", foldedHeaders(history[0].Header), history[0].Body)
		return
	}
	for _, h := range history {
		printf(dividerColor, "==== ")
		printf(titleColor, " Message-Instance m=%d", h.Revision)
		printf(dividerColor, " ====")
		_, _ = fmt.Fprintf(outF, "\n%s\n%s\n", foldedHeaders(h.Header), h.Body)

	}
}

func printf(style lipgloss.Style, format string, a ...interface{}) {
	//fmt.Printf(format, a...)
	s := style.Render(fmt.Sprintf(format, a...))
	_, _ = lipgloss.Print(s)
	//_, _ = lipgloss.Print(style.Render(fmt.Sprintf(format, a...)))
}

func messageEqual(a, b dkim2.VersionedMessage) bool {
	if !maps.EqualFunc(a.Header, b.Header, func(h1, h2 []string) bool {
		return slices.Equal(h1, h2)
	}) {
		return false
	}
	return bytes.Equal(a.Body, b.Body)
}

func foldedHeaders(headers map[string][]string) string {
	var w strings.Builder
	for _, k := range slices.Sorted(maps.Keys(headers)) {
		v := headers[k]
		for _, h := range v {
			w.WriteString(foldedHeader(k, h))
		}
	}
	return w.String()
}

func foldedHeader(name, value string) string {
	var buf bytes.Buffer
	w := folder.New(&buf)
	w.Write(textproto.CanonicalMIMEHeaderKey(name))
	w.Write(": ", 1)
	parts := strings.SplitAfter(value, " ")
	for _, part := range parts {
		w.Write(part, 2)
	}
	w.Close()
	return buf.String()
}
