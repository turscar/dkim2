package dkim2

import (
	"context"
	"os"
	"testing"
)

func TestVerify(t *testing.T) {
	f, err := os.Open("testdata/fc0f946.eml")
	if err != nil {
		t.Fatal(err)
	}
	result, err := VerifyAll(context.Background(), f, VerifyOptions{
		IgnoreTimestamp: false,
		Resolver:        nil,
		MailFrom:        "<c890.82.1f47e4000000343c.5b0565eb792e68857762fdf85d86aa80@email-od.com>",
		RcptTo:          []string{"<glass.plane.money@aboutmy.email>"},
	})
	t.Logf("%#v\n", result)
	if err != nil {
		t.Error(err)
	}
	if result.Err != nil {
		t.Error(result.Err)
	}
}
