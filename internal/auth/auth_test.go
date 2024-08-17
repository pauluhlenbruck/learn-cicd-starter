package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	// Test case: No Authorization header
	t.Run("NoAuthHeader", func(t *testing.T) {
		headers := http.Header{}
		_, err := GetAPIKey(headers)
		if err != ErrNoAuthHeaderIncluded {
			t.Errorf("expected error %v, got %v", ErrNoAuthHeaderIncluded, err)
		}
	})

	// Test case: Malformed Authorization header
	t.Run("MalformedAuthHeader", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "Bearer somekey")
		_, err := GetAPIKey(headers)
		if err == nil || err.Error() != "malformed authorization header" {
			t.Errorf("expected error %v, got %v", "malformed authorization header", err)
		}
	})

	// Test case: Valid Authorization header
	t.Run("ValidAuthHeader", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "ApiKey validkey123")
		apiKey, err := GetAPIKey(headers)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if apiKey != "validkey123" {
			t.Errorf("expected API key %v, got %v", "validkey123", apiKey)
		}
	})
}
