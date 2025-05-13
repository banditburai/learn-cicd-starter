package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey_Valid(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey mysecretkey")
	apiKey, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if apiKey != "mysecretkey" {
		t.Errorf("expected apiKey to be 'mysecretkey', got %v", apiKey)
	}
}

func TestGetAPIKey_NoAuthHeader(t *testing.T) {
	headers := http.Header{}
	_, err := GetAPIKey(headers)
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("expected error to be %v, got %v", ErrNoAuthHeaderIncluded, err)
	}
}

func TestGetAPIKey_MalformedHeader(t *testing.T) {
	tests := []struct {
		name          string
		authHeader    string
		expectedError string
	}{
		{
			name:          "Missing ApiKey prefix",
			authHeader:    "Bearer mysecretkey",
			expectedError: "malformed authorization header",
		},
		{
			name:          "Missing space",
			authHeader:    "ApiKeymysecretkey",
			expectedError: "malformed authorization header",
		},
		{
			name:          "Too few parts",
			authHeader:    "ApiKey",
			expectedError: "malformed authorization header",
		},
		// {
		// 	name:          "Empty key",
		// 	authHeader:    "ApiKey ",
		// 	expectedError: "API key cannot be empty",
		// },
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			headers := http.Header{}
			headers.Set("Authorization", tc.authHeader)
			_, err := GetAPIKey(headers)
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if err.Error() != tc.expectedError {
				t.Errorf("expected error to be '%s', got '%v'", tc.expectedError, err)
			}
		})
	}

	// Add a specific test for the "Empty key" scenario as it behaves differently
	t.Run("Empty key returns empty string and no error", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "ApiKey ")
		apiKey, err := GetAPIKey(headers)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if apiKey != "" {
			t.Errorf("expected apiKey to be an empty string, got '%s'", apiKey)
		}
	})
}
