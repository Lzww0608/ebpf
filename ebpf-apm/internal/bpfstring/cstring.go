package bpfstring

import "bytes"

func CString(value []byte) string {
	n := bytes.IndexByte(value, 0)
	if n == -1 {
		n = len(value)
	}
	return string(value[:n])
}
