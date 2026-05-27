package route

import "testing"

func TestNormalizeReplacesNumericAndUUIDSegments(t *testing.T) {
	input := "/api/users/123/orders/550e8400-e29b-41d4-a716-446655440000"
	want := "/api/users/{id}/orders/{uuid}"

	if got := Normalize(input); got != want {
		t.Fatalf("Normalize(%q) = %q, want %q", input, got, want)
	}
}

func TestNormalizeKeepsStableSegmentsAndRoot(t *testing.T) {
	tests := map[string]string{
		"":            "/",
		"/":           "/",
		"/api/orders": "/api/orders",
		"/v1/users":   "/v1/users",
	}

	for input, want := range tests {
		if got := Normalize(input); got != want {
			t.Fatalf("Normalize(%q) = %q, want %q", input, got, want)
		}
	}
}
