package retry

// NoopLogger is exported for testing.
type NoopLogger = noopLogger

var (
	// DefaultRetryableStatusCodes is exported for testing only.
	DefaultRetryableStatusCodes = defaultRetryableStatusCodes
	// DefaultAcceptedStatusCodes is exported for testing only.
	DefaultAcceptedStatusCodes = defaultAcceptedStatusCodes
)
