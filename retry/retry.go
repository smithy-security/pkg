package retry

import (
	"log/slog"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/go-errors/errors"
	"github.com/smithy-security/pkg/utils"
)

const defaultMaxRetries uint = 5

var (
	defaultRetryableStatusCodes = map[int]struct{}{
		http.StatusTooManyRequests:    {},
		http.StatusRequestTimeout:     {},
		http.StatusGatewayTimeout:     {},
		http.StatusBadGateway:         {},
		http.StatusServiceUnavailable: {},
	}
	defaultAcceptedStatusCodes = map[int]struct{}{
		http.StatusCreated:   {},
		http.StatusAccepted:  {},
		http.StatusNoContent: {},
		http.StatusOK:        {},
	}
)

type (
	// ResponseInfoLogger is allowed to inspect the retryable response and
	// print more info about it that might be useful to the caller for
	// debugging
	ResponseInfoLogger func(res *http.Response, logger Logger)

	// Logger allows to inject a custom logger in the client.
	Logger interface {
		Error(msg string, keysAndValues ...any)
		Info(msg string, keysAndValues ...any)
		Debug(msg string, keysAndValues ...any)
		Warn(msg string, keysAndValues ...any)
	}

	// NextRetryInSeconds allows customising the behaviour for the calculating the next retry.
	NextRetryInSeconds func(currAttempt uint) int

	// Config allows configuring the client.
	Config struct {
		BaseClient *http.Client
		// BaseTransport allows to specify a base http.RoundTripper.
		BaseTransport http.RoundTripper
		// Logger allows to specify a custom logger. *slog.Logger will satisfy this.
		Logger Logger
		// NextRetryInSecondsFunc allows to specify a custom retry function.
		// By default, exponential fibonacci like function is used.
		NextRetryInSecondsFunc NextRetryInSeconds
		// MaxRetries allows to specify the number of max retries before returning a fatal error.
		// 5 is the default.
		MaxRetries uint
		// RetryableStatusCodes allows to specify the retryable status codes.
		// defaultRetryableStatusCodes are the default.
		RetryableStatusCodes map[int]struct{}
		// AcceptedStatusCodes allows to specify the non-retryable status codes.
		// defaultAcceptedStatusCodes are the default.
		AcceptedStatusCodes map[int]struct{}
		// ResponseInfoLoggerFunc when set will be used to check the response
		// returned by the API
		ResponseInfoLoggerFunc ResponseInfoLogger
	}

	retry struct {
		config        Config
		baseTransport http.RoundTripper
	}
)

// Validate validates the client configuration.
func (c Config) Validate() error {
	switch {
	case c.MaxRetries == 0:
		return errors.New("max retries is required")
	case len(c.RetryableStatusCodes) == 0:
		return errors.New("retryable status codes is required")
	case len(c.AcceptedStatusCodes) == 0:
		return errors.New("accepted status codes is required")
	case c.BaseTransport == nil:
		return errors.New("base round tripper is required")
	case c.Logger == nil:
		return errors.New("logger is required")
	case c.NextRetryInSecondsFunc == nil:
		return errors.New("next retry function is required")
	}

	return nil
}

func applyConfig(cfg Config) (Config, error) {
	clonedCfg := cfg
	if cfg.MaxRetries == 0 {
		clonedCfg.MaxRetries = defaultMaxRetries
	}

	if len(clonedCfg.RetryableStatusCodes) == 0 {
		clonedCfg.RetryableStatusCodes = defaultRetryableStatusCodes
	}

	if len(clonedCfg.AcceptedStatusCodes) == 0 {
		clonedCfg.AcceptedStatusCodes = defaultAcceptedStatusCodes
	}

	if clonedCfg.BaseClient == nil {
		clonedCfg.BaseClient = http.DefaultClient
	}

	if clonedCfg.BaseTransport == nil {
		clonedCfg.BaseTransport = http.DefaultTransport
	}

	if clonedCfg.Logger == nil {
		clonedCfg.Logger = &noopLogger{}
	}

	if clonedCfg.NextRetryInSecondsFunc == nil {
		clonedCfg.NextRetryInSecondsFunc = fibNextRetry
	}

	return clonedCfg, clonedCfg.Validate()
}

// NewClient returns a new http.Client with retry behaviour.
func NewClient(config Config) (*http.Client, error) {
	config, err := applyConfig(config)
	if err != nil {
		return nil, errors.Errorf("failed to apply config: %w", err)
	}

	config.BaseClient.Transport = &retry{
		config:        config,
		baseTransport: config.BaseTransport,
	}

	return config.BaseClient, nil
}

// NewRoundTripper returns a new http.RoundTripper with retry behaviour.
func NewRoundTripper(config Config) (http.RoundTripper, error) {
	config, err := applyConfig(config)
	if err != nil {
		return nil, errors.Errorf("failed to apply config: %w", err)
	}

	return &retry{
		config:        config,
		baseTransport: config.BaseTransport,
	}, nil
}

const noRetryHeader = -1

// parseRetryHeader does a best effort parsing of the retry header
func parseRetryHeader(logger Logger, resp *http.Response) int {
	vals, ok := resp.Header["Retry-After"]
	if !ok {
		return noRetryHeader
	}

	logger.Debug("response contains retry after header", slog.String("vals", strings.Join(vals, ",")))
	if len(vals) > 1 {
		logger.Error("retry header has multiple values")
		return noRetryHeader
	}

	retrySeconds, err := strconv.ParseInt(vals[0], 10, 32)
	if err == nil {
		return int(retrySeconds)
	}

	logger.Debug(
		"could not parse `retry after` value into seconds, trying as a date",
		slog.String("err", err.Error()),
	)

	retryAfterTime, err := time.Parse(http.TimeFormat, vals[0])
	if err == nil {
		logger.Debug("parsed successfully time from retry after header")
		return int(time.Until(retryAfterTime).Seconds()) + 1
	}

	logger.Error("could not parse http time in retry header", slog.String("err", err.Error()))
	return noRetryHeader
}

// RoundTrip implements a http transport RoundTripper with retry capabilities.
func (re *retry) RoundTrip(req *http.Request) (*http.Response, error) {
	var (
		logger      = re.config.Logger
		currAttempt uint
		retryableOp = func() (*http.Response, error) {
			resp, err := re.baseTransport.RoundTrip(req)
			switch {
			case err != nil:
				return resp, backoff.Permanent(err)
			case resp == nil:
				return nil, backoff.Permanent(errors.New("invalid nil response"))
			}

			_, isAcceptedStatus := re.config.AcceptedStatusCodes[resp.StatusCode]
			_, isRetryableStatus := re.config.RetryableStatusCodes[resp.StatusCode]

			switch {
			case !isAcceptedStatus && currAttempt >= re.config.MaxRetries:
				return resp, backoff.Permanent(
					errors.Errorf(
						"maximum number of retries exceeded: %d",
						currAttempt,
					),
				)
			case !isAcceptedStatus && isRetryableStatus:
				nextRetryInSeconds := parseRetryHeader(logger, resp)
				if nextRetryInSeconds == noRetryHeader {
					nextRetryInSeconds = re.config.NextRetryInSecondsFunc(currAttempt)
				}

				logger.Debug(
					"retryable status code, retrying",
					slog.Int("retry_in_seconds", nextRetryInSeconds),
					slog.Int("curr_attempt", int(currAttempt)),
					slog.Int("status_code", resp.StatusCode),
				)

				if !utils.IsNil(re.config.ResponseInfoLoggerFunc) {
					re.config.ResponseInfoLoggerFunc(resp, logger)
				}

				currAttempt++

				return resp, backoff.RetryAfter(nextRetryInSeconds)
			case !isAcceptedStatus && !isRetryableStatus:
				bb, err := httputil.DumpResponse(resp, true)
				if err != nil {
					logger.Error(
						"failed to dump response",
						slog.String("error", err.Error()),
					)
				}
				logger.Error(
					"unexpected response",
					slog.Int("status_code", resp.StatusCode),
					slog.String("raw_body", string(bb)),
				)

				return resp, backoff.Permanent(errors.Errorf("invalid status code: %d", resp.StatusCode))
			}

			return resp, nil
		}
	)

	result, err := backoff.Retry(
		req.Context(),
		retryableOp,
	)
	if err != nil {
		return result, errors.Errorf("could not process backoff result: %w", err)
	}

	return result, nil
}

func fibNextRetry(attempt uint) int {
	switch attempt {
	case 0:
		return 0
	case 1:
		return 1
	default:
		return fibNextRetry(attempt-1) + fibNextRetry(attempt-2)
	}
}
