package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		expectedKey string
		expectedErr error
	}{
		{
			name:        "valid api key",
			headers:     http.Header{"Authorization": []string{"ApiKey valid-key-123"}},
			expectedKey: "valid-key-123",
			expectedErr: nil,
		},
		{
			name:        "no auth header",
			headers:     http.Header{},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:        "wrong prefix",
			headers:     http.Header{"Authorization": []string{"Bearer invalid-key"}},
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name:        "no space separator",
			headers:     http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)
			if key != tt.expectedKey {
				t.Errorf("GetAPIKey() key = %v, want %v", key, tt.expectedKey)
			}
			if !errors.Is(err, tt.expectedErr) && err.Error() != tt.expectedErr.Error() {
				t.Errorf("GetAPIKey() error = %v, want %v", err, tt.expectedErr)
			}
		})
	}
}
