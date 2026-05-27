package bpfstring

type charByte interface {
	~byte | ~int8
}

func CString[T charByte](value []T) string {
	n := len(value)
	for i, b := range value {
		if b == 0 {
			n = i
			break
		}
	}

	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = byte(value[i])
	}

	return string(out)
}
