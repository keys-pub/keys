package saltpack

import (
	"context"
	pkglog "log"
	"os"
)

var logger = newLogFromEnv()

//var logger = newContextLogFromEnv()

// SetLogger sets logger for the package.
func SetLogger(l Logger) {
	logger = l
}

// // SetContextLogger sets logger for the package.
// func SetContextLogger(l ContextLogger) {
// 	logger = l
// }

// Logger interface used in this package.
type Logger interface {
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Warningf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

// LogLevel ...
type LogLevel int

const (
	// DebugLevel ...
	DebugLevel LogLevel = 3
	// InfoLevel ...
	InfoLevel LogLevel = 2
	// WarnLevel ...
	WarnLevel LogLevel = 1
	// ErrLevel ...
	ErrLevel LogLevel = 0
)

// NewLogger ...
func NewLogger(lev LogLevel) Logger {
	return &defaultLog{Level: lev}
}

func newLogFromEnv() Logger {
	return NewLogger(parseLogLevel(os.Getenv("LOG")))
}

func parseLogLevel(s string) LogLevel {
	switch s {
	case "debug":
		return DebugLevel
	case "info":
		return InfoLevel
	case "warn":
		return WarnLevel
	default:
		return ErrLevel
	}
}

type defaultLog struct {
	Level LogLevel
}

func (l defaultLog) Debugf(format string, args ...interface{}) {
	if l.Level >= 3 {
		pkglog.Printf("[DEBG] "+format+"\n", args...)
	}
}

func (l defaultLog) Infof(format string, args ...interface{}) {
	if l.Level >= 2 {
		pkglog.Printf("[INFO] "+format+"\n", args...)
	}
}

func (l defaultLog) Warningf(format string, args ...interface{}) {
	if l.Level >= 1 {
		pkglog.Printf("[WARN] "+format+"\n", args...)
	}
}

func (l defaultLog) Errorf(format string, args ...interface{}) {
	if l.Level >= 0 {
		pkglog.Printf("[ERR]  "+format+"\n", args...)
	}
}

// ContextLogger interface used in this package with request context.
type ContextLogger interface {
	Debugf(ctx context.Context, format string, args ...interface{})
	Infof(ctx context.Context, format string, args ...interface{})
	Warningf(ctx context.Context, format string, args ...interface{})
	Errorf(ctx context.Context, format string, args ...interface{})
}

// NewContextLogger ...
func NewContextLogger(lev LogLevel) ContextLogger {
	return &defaultContextLog{Level: lev}
}

func newContextLogFromEnv() ContextLogger {
	return NewContextLogger(parseLogLevel(os.Getenv("LOG")))
}

type defaultContextLog struct {
	Level LogLevel
}

func (l defaultContextLog) Debugf(ctx context.Context, format string, args ...interface{}) {
	if l.Level >= 3 {
		pkglog.Printf("[DEBG] "+format+"\n", args...)
	}
}

func (l defaultContextLog) Infof(ctx context.Context, format string, args ...interface{}) {
	if l.Level >= 2 {
		pkglog.Printf("[INFO] "+format+"\n", args...)
	}
}

func (l defaultContextLog) Warningf(ctx context.Context, format string, args ...interface{}) {
	if l.Level >= 1 {
		pkglog.Printf("[WARN] "+format+"\n", args...)
	}
}

func (l defaultContextLog) Errorf(ctx context.Context, format string, args ...interface{}) {
	if l.Level >= 0 {
		pkglog.Printf("[ERR]  "+format+"\n", args...)
	}
}
