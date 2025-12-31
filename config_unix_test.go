// SPDX-License-Identifier: Apache-2.0

//go:build unix

package sasl

import (
	"os"
	"testing"
)

func TestGetConfigPathDefault(t *testing.T) {
	a := NewAssert(t)
	paths, err := getConfigPath()
	a.NoErrorFatal(err)
	a.Equal(paths, []string{"/usr/lib/sasl2", "/usr/lib64/sasl2", "/etc/sasl2"})
}

func TestGetConfigPathEnvVar(t *testing.T) {
	a := NewAssert(t)
	os.Setenv("SASL_CONF_PATH", "/etc/foo:/bar")
	paths, err := getConfigPath()
	a.NoErrorFatal(err)
	a.Equal(paths, []string{"/etc/foo", "/bar"})
}
