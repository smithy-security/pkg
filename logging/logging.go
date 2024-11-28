package logging

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
)

const ctxLoggerKey = ctxKey("smithy_ctx_logger")

type (
	// Logger exposes an slog.Logger compatible logger contract.
	Logger interface {
		Debug(msg string, keyvals ...any)
		Info(msg string, keyvals ...any)
		Warn(msg string, keyvals ...any)
		Error(msg string, keyvals ...any)
		With(args ...any) Logger
	}

	ctxKey string

	defaultLogger struct {
		logLevel slog.Level
		handler  slog.Handler
		logger   *slog.Logger
	}

	defaultLoggerOption func(*defaultLogger) error
)

// WithContext returns a context with a logger in its values for reusability.
func WithContext(ctx context.Context, logger Logger) context.Context {
	return context.WithValue(ctx, ctxLoggerKey, logger)
}

// FromContext extracts a structured logger from the context for reusability.
func FromContext(ctx context.Context) Logger {
	logger := ctx.Value(ctxLoggerKey)
	if logger == nil {
		l, _ := newDefaultLogger()
		return l
	}
	return logger.(Logger)
}

func (d *defaultLogger) Debug(msg string, keyvals ...any) {
	d.logger.Debug(msg, keyvals...)
}

func (d *defaultLogger) Info(msg string, keyvals ...any) {
	d.logger.Info(msg, keyvals...)
}

func (d *defaultLogger) Warn(msg string, keyvals ...any) {
	d.logger.Warn(msg, keyvals...)
}

func (d *defaultLogger) Error(msg string, keyvals ...any) {
	d.logger.Error(msg, keyvals...)
}

func (d *defaultLogger) With(args ...any) Logger {
	d.logger = d.logger.With(args...)
	return d
}

func DefaultLoggerWithHandler(h slog.Handler) defaultLoggerOption {
	return func(l *defaultLogger) error {
		switch {
		case l == nil:
			return errors.New("invalid nil logger")
		case h == nil:
			return errors.New("invalid nil log handler")
		}
		l.handler = h
		return nil
	}
}

func DefaultLoggerWithLogLevel(logLevel slog.Level) defaultLoggerOption {
	return func(l *defaultLogger) error {
		if l == nil {
			return errors.New("invalid nil logger")
		}
		l.logLevel = logLevel
		return nil
	}
}

func NewDefaultLogger(opts ...defaultLoggerOption) (Logger, error) {
	l, err := newDefaultLogger()
	if err != nil {
		return nil, fmt.Errorf("error creating new default logger: %w", err)
	}

	for _, opt := range opts {
		if err := opt(l); err != nil {
			return nil, fmt.Errorf("error applying default logger options: %w", err)
		}
	}

	return l, nil
}

func newDefaultLogger() (*defaultLogger, error) {
	var (
		logLevel      = slog.LevelError
		loggerHandler = slog.NewJSONHandler(
			os.Stdout,
			&slog.HandlerOptions{
				Level: logLevel,
			},
		)
	)

	return &defaultLogger{
		logLevel: logLevel,
		handler:  loggerHandler,
		logger: slog.New(
			loggerHandler,
		),
	}, nil
}
