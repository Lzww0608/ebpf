package bpfstring

import "testing"

func TestCStringHandlesByteAndInt8Buffers(t *testing.T) {
	byteValue := []byte{'c', 'a', 't', 0, 'x'}
	if got := CString(byteValue); got != "cat" {
		t.Fatalf("CString([]byte) = %q, want cat", got)
	}

	int8Value := []int8{'s', 's', 'h', 0, 'x'}
	if got := CString(int8Value); got != "ssh" {
		t.Fatalf("CString([]int8) = %q, want ssh", got)
	}
}
