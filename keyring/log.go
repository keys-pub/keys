package keyring

import (
	pkglog "log"
	"os"
)

// Logger interface used in this package
type Logger interface {
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Warningf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

type logLevel int

const (
	debugLevel logLevel = 3
	infoLevel  logLevel = 2
	warnLevel  logLevel = 1
	errLevel   logLevel = 0
)

var logger = newLogFromEnv()

func newLog(lev logLevel) Logger {
	return &defaultLog{Level: lev}
}

func newLogFromEnv() Logger {
	return newLog(parseLogLevel(os.Getenv("LOG_LEVEL")))
}

func parseLogLevel(s string) logLevel {
	switch s {
	case "debug":
		return debugLevel
	case "info":
		return infoLevel
	case "warn":
		return warnLevel
	default:
		return errLevel
	}
}

// SetLogger sets package log
func SetLogger(l Logger) {
	logger = l
}

type defaultLog struct {
	Level logLevel
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
	pkglog.Printf("[ERR]  "+format+"\n", args...)
}
