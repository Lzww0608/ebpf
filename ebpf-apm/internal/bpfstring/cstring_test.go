package bpfstring

import "testing"

func TestCStringStopsAtNUL(t *testing.T) {
	input := []byte{'G', 'E', 'T', 0, 'X'}

	if got := CString(input); got != "GET" {
		t.Fatalf("CString(%v) = %q, want %q", input, got, "GET")
	}
}

func TestCStringUsesWholeSliceWithoutNUL(t *testing.T) {
	input := []byte{'P', 'O', 'S', 'T'}

	if got := CString(input); got != "POST" {
		t.Fatalf("CString(%v) = %q, want %q", input, got, "POST")
	}
}
