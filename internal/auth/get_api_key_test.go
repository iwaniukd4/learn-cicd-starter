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
		wantKey     string
		wantErr     error
	}{
		{
			name:    "brak nagłówka Authorization",
			headers: http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "poprawny nagłówek ApiKey",
			headers: http.Header{
				"Authorization": []string{"ApiKey 12345abcde"},
			},
			wantKey: "12345abcde",
			wantErr: nil,
		},
		{
			name: "kilka części po ApiKey",
			headers: http.Header{
				"Authorization": []string{"ApiKey token123 extra part"},
			},
			wantKey: "token123",
			wantErr: nil,
		},
		{
			name: "nieprawidłowy typ autoryzacji - Bearer",
			headers: http.Header{
				"Authorization": []string{"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"},
			},
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name: "tylko jedno słowo w nagłówku",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name: "pusty nagłówek Authorization",
			headers: http.Header{
				"Authorization": []string{""},
			},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "zła wielkość liter - apikey",
			headers: http.Header{
				"Authorization": []string{"apikey mojklucz"},
			},
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotErr := GetAPIKey(tt.headers)

			// Sprawdzenie klucza
			if gotKey != tt.wantKey {
				t.Errorf("GetAPIKey() key = %v, want %v", gotKey, tt.wantKey)
			}

			// Sprawdzenie błędu
			if tt.wantErr != nil {
				if gotErr == nil {
					t.Errorf("GetAPIKey() expected error: %v, got nil", tt.wantErr)
				} else if gotErr.Error() != tt.wantErr.Error() {
					t.Errorf("GetAPIKey() error = %v, want %v", gotErr, tt.wantErr)
				}
			} else if gotErr != nil {
				t.Errorf("GetAPIKey() unexpected error: %v", gotErr)
			}
		})
	}
}
