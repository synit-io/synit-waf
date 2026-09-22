package waf

import (
	"github.com/sirupsen/logrus"
	"log"
)

// SyserrWriter is a writer that adds a "SYSERR: " prefix to log messages.
type SyserrWriter struct {
	logger *logrus.Logger
}

// Write implements the io.Writer interface.
func (w *SyserrWriter) Write(p []byte) (n int, err error) {
	w.logger.Error("SYSERR: ", string(p))
	return len(p), nil
}

// NewLogrusStandardLogger creates a new log.Logger that writes to the provided logrus.Logger.
func NewLogrusStandardLogger(l *logrus.Logger) *log.Logger {
	return log.New(&SyserrWriter{l}, "", 0)
}
