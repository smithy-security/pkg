package env_test

import (
	"testing"
	"time"

	"github.com/smithy-security/pkg/env"
)

func TestFromEnvOrDefault(t *testing.T) {
	var (
		testLoader = func(envs map[string]string) env.Loader {
			return func(key string) string {
				return envs[key]
			}
		}
	)

	t.Run("string", func(t *testing.T) {
		const defaultVal = "default"

		loader := testLoader(map[string]string{
			"KNOWN_STRING": "a string",
		})

		for _, tt := range []struct {
			envVar        string
			expectedVal   string
			defaultVal    string
			shouldDefault bool
			expectsError  bool
		}{
			{
				envVar:        "KNOWN_STRING",
				expectedVal:   "a string",
				defaultVal:    defaultVal,
				shouldDefault: false,
				expectsError:  false,
			},
			{
				envVar:        "UNKNOWN_STRING",
				shouldDefault: false,
				expectsError:  true,
			},
			{
				envVar:        "UNKNOWN_STRING",
				defaultVal:    defaultVal,
				shouldDefault: true,
				expectsError:  false,
			},
		} {
			t.Run(tt.envVar, func(t *testing.T) {
				val, err := env.GetOrDefault(
					tt.envVar,
					tt.defaultVal,
					env.WithLoader(loader),
					env.WithDefaultOnError(tt.shouldDefault),
				)
				expectationsChecker(t, val, tt.expectedVal, tt.defaultVal, err, tt.shouldDefault, tt.expectsError)
			})
		}
	})

	t.Run("bool", func(t *testing.T) {
		const defaultVal = true

		loader := testLoader(map[string]string{
			"KNOWN_TRUE_BOOL":  "true",
			"KNOWN_FALSE_BOOL": "false",
		})

		for _, tt := range []struct {
			envVar        string
			expectedVal   bool
			defaultVal    bool
			shouldDefault bool
			expectsError  bool
		}{
			{
				envVar:        "KNOWN_TRUE_BOOL",
				expectedVal:   true,
				shouldDefault: false,
				expectsError:  false,
			},
			{
				envVar:        "KNOWN_FALSE_BOOL",
				expectedVal:   false,
				shouldDefault: false,
				expectsError:  false,
			},
			{
				envVar:        "UNKNOWN_BOOL",
				shouldDefault: false,
				expectsError:  true,
			},
			{
				envVar:        "UNKNOWN_BOOL",
				defaultVal:    defaultVal,
				shouldDefault: true,
				expectsError:  false,
			},
		} {
			t.Run(tt.envVar, func(t *testing.T) {
				val, err := env.GetOrDefault(
					tt.envVar,
					tt.defaultVal,
					env.WithLoader(loader),
					env.WithDefaultOnError(tt.shouldDefault),
				)
				expectationsChecker(t, val, tt.expectedVal, tt.defaultVal, err, tt.shouldDefault, tt.expectsError)
			})
		}
	})

	t.Run("int", func(t *testing.T) {
		const defaultVal = 1234

		loader := testLoader(map[string]string{
			"KNOWN_INT":         "5678",
			"KNOWN_INVALID_INT": "not_an_int",
		})

		for _, tt := range []struct {
			envVar        string
			expectedVal   int
			defaultVal    int
			shouldDefault bool
			expectsError  bool
		}{
			{
				envVar:        "KNOWN_INT",
				expectedVal:   5678,
				shouldDefault: false,
				expectsError:  false,
			},
			{
				envVar:        "KNOWN_INVALID_INT",
				expectedVal:   defaultVal,
				defaultVal:    defaultVal,
				shouldDefault: true,
				expectsError:  false,
			},
			{
				envVar:        "KNOWN_INVALID_INT",
				defaultVal:    defaultVal,
				shouldDefault: false,
				expectsError:  true,
			},
		} {
			t.Run(tt.envVar, func(t *testing.T) {
				val, err := env.GetOrDefault(
					tt.envVar,
					tt.defaultVal,
					env.WithLoader(loader),
					env.WithDefaultOnError(tt.shouldDefault),
				)
				expectationsChecker(t, val, tt.expectedVal, tt.defaultVal, err, tt.shouldDefault, tt.expectsError)
			})
		}
	})

	t.Run("int64", func(t *testing.T) {
		const defaultVal = 1234

		loader := testLoader(map[string]string{
			"KNOWN_INT64":         "5678",
			"KNOWN_INVALID_INT64": "not_an_int64",
		})

		for _, tt := range []struct {
			envVar        string
			expectedVal   int64
			defaultVal    int64
			shouldDefault bool
			expectsError  bool
		}{
			{
				envVar:        "KNOWN_INT64",
				expectedVal:   5678,
				shouldDefault: false,
				expectsError:  false,
			},
			{
				envVar:        "KNOWN_INVALID_INT64",
				expectedVal:   defaultVal,
				defaultVal:    defaultVal,
				shouldDefault: true,
				expectsError:  false,
			},
			{
				envVar:        "KNOWN_INVALID_INT64",
				defaultVal:    defaultVal,
				shouldDefault: false,
				expectsError:  true,
			},
		} {
			t.Run(tt.envVar, func(t *testing.T) {
				val, err := env.GetOrDefault(
					tt.envVar,
					tt.defaultVal,
					env.WithLoader(loader),
					env.WithDefaultOnError(tt.shouldDefault),
				)
				expectationsChecker(t, val, tt.expectedVal, tt.defaultVal, err, tt.shouldDefault, tt.expectsError)
			})
		}
	})

	t.Run("uint", func(t *testing.T) {
		const defaultVal = 1234

		loader := testLoader(map[string]string{
			"KNOWN_UINT":         "5678",
			"KNOWN_INVALID_UINT": "not_a_uint",
		})

		for _, tt := range []struct {
			envVar        string
			expectedVal   uint
			defaultVal    uint
			shouldDefault bool
			expectsError  bool
		}{
			{
				envVar:        "KNOWN_UINT",
				expectedVal:   5678,
				shouldDefault: false,
				expectsError:  false,
			},
			{
				envVar:        "KNOWN_INVALID_UINT",
				expectedVal:   defaultVal,
				defaultVal:    defaultVal,
				shouldDefault: true,
				expectsError:  false,
			},
			{
				envVar:        "KNOWN_INVALID_UINT",
				defaultVal:    defaultVal,
				shouldDefault: false,
				expectsError:  true,
			},
		} {
			t.Run(tt.envVar, func(t *testing.T) {
				val, err := env.GetOrDefault(
					tt.envVar,
					tt.defaultVal,
					env.WithLoader(loader),
					env.WithDefaultOnError(tt.shouldDefault),
				)
				expectationsChecker(t, val, tt.expectedVal, tt.defaultVal, err, tt.shouldDefault, tt.expectsError)
			})
		}
	})

	t.Run("uint64", func(t *testing.T) {
		const defaultVal = 1234

		loader := testLoader(map[string]string{
			"KNOWN_UINT64":         "5678",
			"KNOWN_INVALID_UINT64": "not_a_uint64",
		})

		for _, tt := range []struct {
			envVar        string
			expectedVal   uint
			defaultVal    uint
			shouldDefault bool
			expectsError  bool
		}{
			{
				envVar:        "KNOWN_UINT64",
				expectedVal:   5678,
				shouldDefault: false,
				expectsError:  false,
			},
			{
				envVar:        "KNOWN_INVALID_UINT64",
				expectedVal:   defaultVal,
				defaultVal:    defaultVal,
				shouldDefault: true,
				expectsError:  false,
			},
			{
				envVar:        "KNOWN_INVALID_UINT64",
				defaultVal:    defaultVal,
				shouldDefault: false,
				expectsError:  true,
			},
		} {
			t.Run(tt.envVar, func(t *testing.T) {
				val, err := env.GetOrDefault(
					tt.envVar,
					tt.defaultVal,
					env.WithLoader(loader),
					env.WithDefaultOnError(tt.shouldDefault),
				)
				expectationsChecker(t, val, tt.expectedVal, tt.defaultVal, err, tt.shouldDefault, tt.expectsError)
			})
		}
	})

	t.Run("float64", func(t *testing.T) {
		const defaultVal = 64.4

		loader := testLoader(map[string]string{
			"KNOWN_FLOAT64":         "11.67",
			"KNOWN_INVALID_FLOAT64": "not_a_uint64",
		})

		for _, tt := range []struct {
			envVar        string
			expectedVal   float64
			defaultVal    float64
			shouldDefault bool
			expectsError  bool
		}{
			{
				envVar:        "KNOWN_FLOAT64",
				expectedVal:   11.67,
				shouldDefault: false,
				expectsError:  false,
			},
			{
				envVar:        "KNOWN_INVALID_FLOAT64",
				expectedVal:   defaultVal,
				defaultVal:    defaultVal,
				shouldDefault: true,
				expectsError:  false,
			},
			{
				envVar:        "KNOWN_INVALID_FLOAT64",
				defaultVal:    defaultVal,
				shouldDefault: false,
				expectsError:  true,
			},
		} {
			t.Run(tt.envVar, func(t *testing.T) {
				val, err := env.GetOrDefault(
					tt.envVar,
					tt.defaultVal,
					env.WithLoader(loader),
					env.WithDefaultOnError(tt.shouldDefault),
				)
				expectationsChecker(t, val, tt.expectedVal, tt.defaultVal, err, tt.shouldDefault, tt.expectsError)
			})
		}
	})

	t.Run("time.Duration", func(t *testing.T) {
		const defaultVal = 10 * time.Second

		loader := testLoader(map[string]string{
			"KNOWN_DURATION":         "12s",
			"KNOWN_INVALID_DURATION": "not_a_duration",
		})

		for _, tt := range []struct {
			envVar        string
			expectedVal   time.Duration
			defaultVal    time.Duration
			shouldDefault bool
			expectsError  bool
		}{
			{
				envVar:        "KNOWN_DURATION",
				expectedVal:   12 * time.Second,
				shouldDefault: false,
				expectsError:  false,
			},
			{
				envVar:        "KNOWN_INVALID_DURATION",
				expectedVal:   defaultVal,
				defaultVal:    defaultVal,
				shouldDefault: true,
				expectsError:  false,
			},
			{
				envVar:        "KNOWN_INVALID_DURATION",
				defaultVal:    defaultVal,
				shouldDefault: false,
				expectsError:  true,
			},
		} {
			t.Run(tt.envVar, func(t *testing.T) {
				val, err := env.GetOrDefault(
					tt.envVar,
					tt.defaultVal,
					env.WithLoader(loader),
					env.WithDefaultOnError(tt.shouldDefault),
				)
				expectationsChecker(t, val, tt.expectedVal, tt.defaultVal, err, tt.shouldDefault, tt.expectsError)
			})
		}
	})

	t.Run("time.Time", func(t *testing.T) {
		var (
			defaultVal = time.Date(2024, 3, 10, 11, 0, 0, 0, time.UTC)
			loader     = testLoader(map[string]string{
				"KNOWN_TIME":         "2024-04-10T11:12:00Z",
				"KNOWN_INVALID_TIME": "not_time",
			})
		)

		for _, tt := range []struct {
			envVar        string
			expectedVal   time.Time
			defaultVal    time.Time
			shouldDefault bool
			expectsError  bool
		}{
			{
				envVar:        "KNOWN_TIME",
				expectedVal:   time.Date(2024, 4, 10, 11, 12, 0, 0, time.UTC),
				shouldDefault: false,
				expectsError:  false,
			},
			{
				envVar:        "KNOWN_INVALID_TIME",
				expectedVal:   defaultVal,
				defaultVal:    defaultVal,
				shouldDefault: true,
				expectsError:  false,
			},
			{
				envVar:        "KNOWN_INVALID_TIME",
				defaultVal:    defaultVal,
				shouldDefault: false,
				expectsError:  true,
			},
		} {
			t.Run(tt.envVar, func(t *testing.T) {
				val, err := env.GetOrDefault(
					tt.envVar,
					tt.defaultVal,
					env.WithLoader(loader),
					env.WithDefaultOnError(tt.shouldDefault),
				)
				expectationsChecker(t, val, tt.expectedVal, tt.defaultVal, err, tt.shouldDefault, tt.expectsError)
			})
		}
	})
}

func expectationsChecker(t *testing.T, val, expectedVal, defaultVal any, err error, shouldDefault, expectsError bool) {
	t.Helper()
	switch {
	case shouldDefault:
		if err != nil {
			t.Errorf("unexpected error %v", err)
			break
		}
		if defaultVal != val {
			t.Errorf("expected default value '%s', got '%s'", defaultVal, val)
		}
	case err != nil:
		if !expectsError {
			t.Errorf("unexpected error %v", err)
		}
	case expectedVal != val:
		t.Errorf("expected value '%s', got '%s'", expectedVal, val)
	}
}
