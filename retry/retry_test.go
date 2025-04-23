package retry_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smithy-security/pkg/retry"
)

type mockTransport struct {
	responses    []*http.Response
	errors       []error
	requestCount int
	requests     []*http.Request
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if m.requests == nil {
		m.requests = make([]*http.Request, 0)
	}
	m.requests = append(m.requests, req)

	if m.requestCount < len(m.responses) {
		resp := m.responses[m.requestCount]
		err := m.errors[m.requestCount]
		m.requestCount++
		return resp, err
	}
	return nil, errors.New("unexpected call to RoundTrip")
}

func TestRoundTripper(t *testing.T) {
	var (
		ctx, cancel  = context.WithTimeout(context.Background(), time.Minute)
		makeResponse = func(statusCode int, body string) *http.Response {
			return &http.Response{
				StatusCode: statusCode,
				Body:       io.NopCloser(bytes.NewBufferString(body)),
			}
		}
		zeroDelayRetry = func(uint) int { return 0 }
	)

	defer cancel()

	for _, tc := range []struct {
		name           string
		responses      []*http.Response
		errors         []error
		maxRetries     uint
		expectedStatus int
		expectedBody   string
		expectError    bool
		errorContains  string
		useContext     bool
		contextTimeout time.Duration
		retryFunc      retry.NextRetryInSeconds
	}{
		{
			name: "success",
			responses: []*http.Response{
				makeResponse(http.StatusOK, "success"),
			},
			errors:         []error{nil},
			maxRetries:     3,
			expectedStatus: http.StatusOK,
			expectedBody:   "success",
			expectError:    false,
		},
		{
			name: "retry success",
			responses: []*http.Response{
				makeResponse(http.StatusTooManyRequests, "rate limited"),
				makeResponse(http.StatusOK, "success after retry"),
			},
			errors:         []error{nil, nil},
			maxRetries:     3,
			expectedStatus: http.StatusOK,
			expectedBody:   "success after retry",
			expectError:    false,
		},
		{
			name: "max retries exceeded",
			responses: []*http.Response{
				makeResponse(http.StatusTooManyRequests, "rate limited 1"),
				makeResponse(http.StatusTooManyRequests, "rate limited 2"),
				makeResponse(http.StatusTooManyRequests, "rate limited 3"),
			},
			errors:         []error{nil, nil, nil},
			maxRetries:     2,
			expectedStatus: http.StatusTooManyRequests,
			expectError:    true,
			errorContains:  "maximum number of retries exceeded",
		},
		{
			name: "non retryable error",
			responses: []*http.Response{
				makeResponse(http.StatusBadRequest, "bad request"),
			},
			errors:         []error{nil},
			maxRetries:     3,
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
			errorContains:  "invalid status code: 400",
		},
		{
			name:          "transport error",
			responses:     []*http.Response{nil},
			errors:        []error{errors.New("network error")},
			maxRetries:    3,
			expectError:   true,
			errorContains: "network error",
		},
		{
			name: "context cancellation",
			responses: []*http.Response{
				makeResponse(http.StatusTooManyRequests, "rate limited"),
			},
			errors:         []error{nil},
			maxRetries:     3,
			expectError:    true,
			errorContains:  "context deadline exceeded",
			useContext:     true,
			contextTimeout: 10 * time.Millisecond,
			retryFunc:      func(uint) int { return 1 },
		},
		{
			name: "multiple retries then success",
			responses: []*http.Response{
				makeResponse(http.StatusTooManyRequests, "rate limited 1"),
				makeResponse(http.StatusServiceUnavailable, "service unavailable"),
				makeResponse(http.StatusOK, "finally succeeded"),
			},
			errors:         []error{nil, nil, nil},
			maxRetries:     3,
			expectedStatus: http.StatusOK,
			expectedBody:   "finally succeeded",
			expectError:    false,
		},
		{
			name: "mix of different retryable errors",
			responses: []*http.Response{
				makeResponse(http.StatusTooManyRequests, "rate limited"),
				makeResponse(http.StatusBadGateway, "bad gateway"),
				makeResponse(http.StatusOK, "success after mixed errors"),
			},
			errors:         []error{nil, nil, nil},
			maxRetries:     3,
			expectedStatus: http.StatusOK,
			expectedBody:   "success after mixed errors",
			expectError:    false,
		},
		{
			name: "custom retry strategy",
			responses: []*http.Response{
				makeResponse(http.StatusTooManyRequests, "rate limited 1"),
				makeResponse(http.StatusTooManyRequests, "rate limited 2"),
				makeResponse(http.StatusOK, "success"),
			},
			errors:         []error{nil, nil, nil},
			maxRetries:     3,
			retryFunc:      func(uint) int { return 0 },
			expectedStatus: http.StatusOK,
			expectedBody:   "success",
			expectError:    false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			baseClient := &http.Client{
				Transport: &mockTransport{
					responses: tc.responses,
					errors:    tc.errors,
				},
			}

			retryFunc := tc.retryFunc
			if retryFunc == nil {
				retryFunc = zeroDelayRetry
			}

			config := retry.Config{
				BaseClient:             baseClient,
				Logger:                 &retry.NoopLogger{},
				MaxRetries:             tc.maxRetries,
				RetryableStatusCodes:   retry.DefaultRetryableStatusCodes,
				AcceptedStatusCodes:    retry.DefaultAcceptedStatusCodes,
				NextRetryInSecondsFunc: retryFunc,
			}

			rt, err := retry.NewRoundTripper(config)
			require.NoError(t, err)

			// Create request with context and timeout
			tcCtx, tcCancel := context.WithTimeout(ctx, 2*time.Second)
			if tc.useContext && tc.contextTimeout > 0 {
				// Override with test-specific timeout for timeout-specific tests
				tcCtx, tcCancel = context.WithTimeout(ctx, tc.contextTimeout)
			}
			defer tcCancel()

			req, err := http.NewRequestWithContext(tcCtx, http.MethodGet, "http://smithy.security", nil)
			require.NoError(t, err)

			resp, err := rt.RoundTrip(req)

			if tc.expectError {
				assert.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}

			if tc.expectedStatus != 0 {
				require.NotNil(t, resp)
				assert.Equal(t, tc.expectedStatus, resp.StatusCode)
			}

			if tc.expectedBody != "" {
				require.NotNil(t, resp)
				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Equal(t, tc.expectedBody, string(body))
			}
		})
	}
}
