package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/mail"
	"os"
	"strconv"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"
	flag "github.com/spf13/pflag"
	"go.turscar.ie/dkim2"
	"go.turscar.ie/theme"
)

const hdrMessageInstance = "Message-Instance"
const hdrDKIM2Signature = "Dkim2-Signature"

var version, commit, date, builtBy string

func main() {
	var in string
	var printVersion bool

	flag.StringVar(&in, "in", "-", "input file")
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

	headerName := lipgloss.NewStyle().Inline(true).Foreground(theme.Blue)
	headerValue := lipgloss.NewStyle().Foreground(theme.White)
	errorColor := lipgloss.NewStyle().Foreground(theme.Red)
	msg, err := mail.ReadMessage(inFile)
	if err != nil {
		_, _ = lipgloss.Printf("%s\n", errorColor.Render(err.Error()))
		os.Exit(1)
	}
	for _, d2 := range msg.Header[hdrDKIM2Signature] {
		t := table.New().
			Border(lipgloss.HiddenBorder()).
			Rows([][]string{{
				headerName.Render(hdrDKIM2Signature),
				lipgloss.Wrap(headerValue.Render(d2), 60, " "),
			}}...)
		_, _ = lipgloss.Println(t)
		d, err := dkim2.ParseSignature(d2)
		if err != nil {
			_, _ = lipgloss.Printf("%s\n", errorColor.Render(err.Error()))
			continue
		}
		var rows [][]string
		rows = append(rows, []string{"Sequence:", strconv.Itoa(d.Sequence)})
		rows = append(rows, []string{"M-I Revision:", strconv.Itoa(d.MIRevision)})
		rows = append(rows, []string{"Timestamp:", fmt.Sprintf("%d (%s)", d.Timestamp, time.Unix(d.Timestamp, 0).String())})
		rows = append(rows, []string{"Mail From:", d.MailFrom})
		rows = append(rows, []string{"Rcpt To:", strings.Join(d.RcptTo, "\n")})
		rows = append(rows, []string{"Domain:", d.Domain})
		for i, v := range d.Signatures {
			rows = append(rows, []string{fmt.Sprintf("Selector %d:", i+1), v.Selector})
			rows = append(rows, []string{fmt.Sprintf("Algorithm %d:", i+1), v.Name})
			rows = append(rows, []string{
				fmt.Sprintf("Signature %d:", i+1),
				lipgloss.Wrap(fmt.Sprintf("%x", v.Signature), 60, " "),
			})
		}
		rows = append(rows, []string{"Nonce:", d.Nonce})
		rows = append(rows, []string{"Flags:", strings.Join(d.Flags(), "\n")})
		t = table.New().
			Border(lipgloss.HiddenBorder()).
			Rows(rows...)
		_, _ = lipgloss.Println(t)
	}

	for _, mi := range msg.Header[hdrMessageInstance] {
		t := table.New().
			Border(lipgloss.HiddenBorder()).
			Rows([][]string{{
				headerName.Render(hdrMessageInstance),
				lipgloss.Wrap(headerValue.Render(mi), 60, " "),
			}}...)
		_, _ = lipgloss.Println(t)
		m, err := dkim2.ParseMessageInstance(mi)
		if err != nil {
			_, _ = lipgloss.Printf("%s\n", errorColor.Render(err.Error()))
			continue
		}
		var rows [][]string
		rows = append(rows, []string{"Revision:", strconv.Itoa(m.Revision)})
		for i, hash := range m.Hashes {
			rows = append(rows, []string{
				fmt.Sprintf("Hash %d type:", i+1),
				hash.Name,
			},
				[]string{
					fmt.Sprintf("Hash %d header:", i+1),
					fmt.Sprintf("%x", hash.HeaderHash),
				},
				[]string{
					fmt.Sprintf("Hash %d body:", i+1),
					fmt.Sprintf("%x", hash.BodyHash),
				})
		}
		if m.Recipes != nil {
			var buff bytes.Buffer
			enc := json.NewEncoder(&buff)
			enc.SetIndent("", "  ")
			enc.SetEscapeHTML(false)
			if err := enc.Encode(m.Recipes); err != nil {
				rows = append(rows, []string{"Recipes:", err.Error()})
			} else {
				rows = append(rows, []string{"Recipes:", buff.String()})
			}
		}

		t = table.New().
			Border(lipgloss.HiddenBorder()).
			Rows(rows...)
		_, _ = lipgloss.Println(t)
	}
}
