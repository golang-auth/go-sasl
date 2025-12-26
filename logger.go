// SPDX-License-Identifier: Apache-2.0

package sasl

type Logger interface {
	Printf(format string, v ...any)
	Println(v ...any)
}

type Loggers struct {
	DebugLogger Logger
	InfoLogger  Logger
	WarnLogger  Logger
	ErrorLogger Logger
}

func (c *Loggers) Debugf(msg string, args ...interface{}) {
	if c.DebugLogger == nil {
		return
	}

	c.DebugLogger.Printf(msg, args...)
}
func (c *Loggers) Infof(msg string, args ...interface{}) {
	if c.InfoLogger == nil {
		return
	}

	c.InfoLogger.Printf(msg, args...)
}
func (c *Loggers) Warnf(msg string, args ...interface{}) {
	if c.WarnLogger == nil {
		return
	}

	c.WarnLogger.Printf(msg, args...)
}
func (c *Loggers) Errorf(msg string, args ...interface{}) {
	if c.ErrorLogger == nil {
		return
	}

	c.ErrorLogger.Printf(msg, args...)
}
