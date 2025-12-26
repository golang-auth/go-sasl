// SPDX-License-Identifier: Apache-2.0

package sasl

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// mockLogger is a mock implementation of Logger that records calls
type mockLogger struct {
	printfCalls  []printfCall
	printlnCalls [][]interface{}
}

type printfCall struct {
	format string
	args   []interface{}
}

func (m *mockLogger) Printf(format string, v ...interface{}) {
	m.printfCalls = append(m.printfCalls, printfCall{format: format, args: v})
}

func (m *mockLogger) Println(v ...interface{}) {
	m.printlnCalls = append(m.printlnCalls, v)
}

func (m *mockLogger) reset() {
	m.printfCalls = nil
	m.printlnCalls = nil
}

func TestLoggers_Debugf_WithLogger(t *testing.T) {
	mock := &mockLogger{}
	loggers := Loggers{DebugLogger: mock}

	loggers.Debugf("test message %s", "value")

	assert.Len(t, mock.printfCalls, 1)
	assert.Equal(t, "test message %s", mock.printfCalls[0].format)
	assert.Equal(t, []interface{}{"value"}, mock.printfCalls[0].args)
}

func TestLoggers_Debugf_WithoutLogger(t *testing.T) {
	loggers := Loggers{DebugLogger: nil}

	// Should not panic
	loggers.Debugf("test message %s", "value")
}

func TestLoggers_Infof_WithLogger(t *testing.T) {
	mock := &mockLogger{}
	loggers := Loggers{InfoLogger: mock}

	loggers.Infof("info message %d", 42)

	assert.Len(t, mock.printfCalls, 1)
	assert.Equal(t, "info message %d", mock.printfCalls[0].format)
	assert.Equal(t, []interface{}{42}, mock.printfCalls[0].args)
}

func TestLoggers_Infof_WithoutLogger(t *testing.T) {
	loggers := Loggers{InfoLogger: nil}

	// Should not panic
	loggers.Infof("info message %d", 42)
}

func TestLoggers_Warnf_WithLogger(t *testing.T) {
	mock := &mockLogger{}
	loggers := Loggers{WarnLogger: mock}

	loggers.Warnf("warning: %s", "something")

	assert.Len(t, mock.printfCalls, 1)
	assert.Equal(t, "warning: %s", mock.printfCalls[0].format)
	assert.Equal(t, []interface{}{"something"}, mock.printfCalls[0].args)
}

func TestLoggers_Warnf_WithoutLogger(t *testing.T) {
	loggers := Loggers{WarnLogger: nil}

	// Should not panic
	loggers.Warnf("warning: %s", "something")
}

func TestLoggers_Errorf_WithLogger(t *testing.T) {
	mock := &mockLogger{}
	loggers := Loggers{ErrorLogger: mock}

	loggers.Errorf("error: %v", fmt.Errorf("test error"))

	assert.Len(t, mock.printfCalls, 1)
	assert.Equal(t, "error: %v", mock.printfCalls[0].format)
	assert.Len(t, mock.printfCalls[0].args, 1)
	assert.Error(t, mock.printfCalls[0].args[0].(error))
}

func TestLoggers_Errorf_WithoutLogger(t *testing.T) {
	loggers := Loggers{ErrorLogger: nil}

	// Should not panic
	loggers.Errorf("error: %v", fmt.Errorf("test error"))
}

func TestLoggers_MultipleCalls(t *testing.T) {
	debugMock := &mockLogger{}
	infoMock := &mockLogger{}
	warnMock := &mockLogger{}
	errorMock := &mockLogger{}

	loggers := Loggers{
		DebugLogger: debugMock,
		InfoLogger:  infoMock,
		WarnLogger:  warnMock,
		ErrorLogger: errorMock,
	}

	loggers.Debugf("debug %s", "1")
	loggers.Infof("info %s", "2")
	loggers.Warnf("warn %s", "3")
	loggers.Errorf("error %s", "4")

	assert.Len(t, debugMock.printfCalls, 1)
	assert.Equal(t, "debug %s", debugMock.printfCalls[0].format)

	assert.Len(t, infoMock.printfCalls, 1)
	assert.Equal(t, "info %s", infoMock.printfCalls[0].format)

	assert.Len(t, warnMock.printfCalls, 1)
	assert.Equal(t, "warn %s", warnMock.printfCalls[0].format)

	assert.Len(t, errorMock.printfCalls, 1)
	assert.Equal(t, "error %s", errorMock.printfCalls[0].format)
}

func TestLoggers_Isolation(t *testing.T) {
	// Test that calling one logger method doesn't affect others
	debugMock := &mockLogger{}
	infoMock := &mockLogger{}

	loggers := Loggers{
		DebugLogger: debugMock,
		InfoLogger:  infoMock,
	}

	loggers.Debugf("debug message")
	loggers.Infof("info message")

	// Debug logger should only have debug call
	assert.Len(t, debugMock.printfCalls, 1)
	assert.Equal(t, "debug message", debugMock.printfCalls[0].format)
	assert.Len(t, debugMock.printfCalls[0].args, 0)

	// Info logger should only have info call
	assert.Len(t, infoMock.printfCalls, 1)
	assert.Equal(t, "info message", infoMock.printfCalls[0].format)
	assert.Len(t, infoMock.printfCalls[0].args, 0)
}

func TestLoggers_WithMultipleArgs(t *testing.T) {
	mock := &mockLogger{}
	loggers := Loggers{InfoLogger: mock}

	loggers.Infof("format: %s %d %v", "string", 123, true)

	assert.Len(t, mock.printfCalls, 1)
	assert.Equal(t, "format: %s %d %v", mock.printfCalls[0].format)
	assert.Equal(t, []interface{}{"string", 123, true}, mock.printfCalls[0].args)
}

func TestLoggers_WithNoArgs(t *testing.T) {
	mock := &mockLogger{}
	loggers := Loggers{InfoLogger: mock}

	loggers.Infof("simple message")

	assert.Len(t, mock.printfCalls, 1)
	assert.Equal(t, "simple message", mock.printfCalls[0].format)
	assert.Len(t, mock.printfCalls[0].args, 0)
}

func TestLoggers_AllNil(t *testing.T) {
	loggers := Loggers{}

	// Should not panic with all loggers nil
	loggers.Debugf("debug")
	loggers.Infof("info")
	loggers.Warnf("warn")
	loggers.Errorf("error")
}
