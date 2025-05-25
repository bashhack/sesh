package main

import "testing"

func TestExtractServiceNameSimple(t *testing.T) {
	result := extractServiceName([]string{"sesh", "--service=aws"})
	if result != "aws" {
		t.Errorf("extractServiceName failed: got %q, want %q", result, "aws")
	}
}