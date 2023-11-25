package tokenauth

import (
	"net/http"
	"net/http/httptest"

	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

// MockStorage is a mock implementation of the Storage interface
type MockStorage struct{}

func TestValidateEmbargoToken(t *testing.T) {
	// Mock the storage
	// storage := new(MockStorage)

	// Create a new Echo instance
	e := echo.New()

	tests := []struct {
		name           string
		token          string
		expectedStatus int
	}{
		{
			name:           "No token",
			token:          "",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Invalid token format",
			token:          "invalid_token",
			expectedStatus: http.StatusUnauthorized,
		},
		// Add more test cases here for valid tokens, expired tokens, etc.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new request
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("X-Embargo-Token", tt.token)

			// Create a new response writer
			rec := httptest.NewRecorder()

			// Create a new context
			c := e.NewContext(req, rec)

			// Call the function with the context
			err := ValidateEmbargoToken(func(c echo.Context) error {
				return c.String(http.StatusOK, "test")
			})(c)

			// Assert the status code
			assert.Equal(t, tt.expectedStatus, rec.Code)

			// Assert there was no error
			assert.NoError(t, err)
		})
	}
}
