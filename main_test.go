package main

import (
	"os"
	"reflect"
	"testing"
)

func TestNormalizeArgs_PreservesFlagValues(t *testing.T) {
	orig := os.Args
	defer func() { os.Args = orig }()

	os.Args = []string{
		"diggo",
		"example.com",
		"--dns-timeout", "3s",
		"--rdap-timeout=6s",
		"--core",
	}

	normalizeArgs()

	want := []string{
		"diggo",
		"--dns-timeout", "3s",
		"--rdap-timeout=6s",
		"--core",
		"example.com",
	}
	if !reflect.DeepEqual(os.Args, want) {
		t.Fatalf("normalizeArgs()\n got=%v\nwant=%v", os.Args, want)
	}
}

func TestNormalizeArgs_LeavesDomainOrderForNoFlags(t *testing.T) {
	orig := os.Args
	defer func() { os.Args = orig }()

	os.Args = []string{"diggo", "example.com"}
	normalizeArgs()

	want := []string{"diggo", "example.com"}
	if !reflect.DeepEqual(os.Args, want) {
		t.Fatalf("normalizeArgs()\n got=%v\nwant=%v", os.Args, want)
	}
}
