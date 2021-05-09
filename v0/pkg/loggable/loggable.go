package loggable

import "log"

type LoggableOption func(*Loggable) error

type Loggable struct {
	debugLogger *log.Logger
	infoLogger  *log.Logger
	warnLogger  *log.Logger
	errorLogger *log.Logger
}

func (c *Loggable) Debugf(msg string, args ...interface{}) {
	if c.debugLogger == nil {
		return
	}

	c.debugLogger.Printf(msg, args...)
}
func (c *Loggable) Infof(msg string, args ...interface{}) {
	if c.infoLogger == nil {
		return
	}

	c.infoLogger.Printf(msg, args...)
}
func (c *Loggable) Warnf(msg string, args ...interface{}) {
	if c.warnLogger == nil {
		return
	}

	c.warnLogger.Printf(msg, args...)
}
func (c *Loggable) Errorf(msg string, args ...interface{}) {
	if c.errorLogger == nil {
		return
	}

	c.errorLogger.Printf(msg, args...)
}

func WithDebugLogger(l *log.Logger) LoggableOption {
	return func(c *Loggable) error {
		c.debugLogger = l
		return nil
	}
}
func WithInfoLogger(l *log.Logger) LoggableOption {
	return func(c *Loggable) error {
		c.infoLogger = l
		return nil
	}
}
func WithWarnLogger(l *log.Logger) LoggableOption {
	return func(c *Loggable) error {
		c.warnLogger = l
		return nil
	}
}
func WithErrorLogger(l *log.Logger) LoggableOption {
	return func(c *Loggable) error {
		c.errorLogger = l
		return nil
	}
}
