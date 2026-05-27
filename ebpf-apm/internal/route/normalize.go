package route

import (
	"strings"
	"unicode"
)

func Normalize(path string) string {
	if path == "" {
		return "/"
	}

	parts := strings.Split(path, "/")
	for i, part := range parts {
		if part == "" {
			continue
		}
		if isNumeric(part) {
			parts[i] = "{id}"
			continue
		}
		if looksLikeUUID(part) {
			parts[i] = "{uuid}"
		}
	}

	return strings.Join(parts, "/")
}

func isNumeric(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func looksLikeUUID(value string) bool {
	if len(value) != 36 || strings.Count(value, "-") != 4 {
		return false
	}

	for i, r := range value {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if !isHex(r) {
				return false
			}
		}
	}
	return true
}

func isHex(r rune) bool {
	return (r >= '0' && r <= '9') ||
		(r >= 'a' && r <= 'f') ||
		(r >= 'A' && r <= 'F')
}
