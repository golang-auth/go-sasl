// SPDX-License-Identifier: Apache-2.0

package sasl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Local version of testify/assert  with some extensions
type myassert struct {
	*assert.Assertions

	t *testing.T
}

// Fail the test immediately on error
func (a *myassert) NoErrorFatal(err error) {
	a.t.Helper()
	a.NoError(err)
	if err != nil {
		a.t.Logf("Stopping test %s due to fatal error", a.t.Name())
		a.t.FailNow()
	}
}

func NewAssert(t *testing.T) *myassert {
	a := assert.New(t)
	return &myassert{a, t}
}

func resetRegistry() {
	registry.Lock()
	defer registry.Unlock()
	registry.mechs = nil
}

// testLogger wraps testing.T to implement the Logger interface
type testLogger struct {
	t *testing.T
}

func (l *testLogger) Printf(format string, v ...any) {
	l.t.Helper()
	l.t.Logf(format, v...)
}

func (l *testLogger) Println(v ...any) {
	l.t.Helper()
	l.t.Log(v...)
}

// NewTestLoggers returns a Loggers struct configured to use t.Log for all log levels
func NewTestLoggers(t *testing.T) Loggers {
	t.Helper()
	logger := &testLogger{t: t}
	return Loggers{
		DebugLogger: logger,
		InfoLogger:  logger,
		WarnLogger:  logger,
		ErrorLogger: logger,
	}
}
