// SPDX-License-Identifier: Apache-2.0

//go:build unix

package sasl

import (
	"os"
	"path/filepath"
)

// ConfigPath is the search path for SASL configuration files
var ConfigPath = "/usr/lib/sasl2:/usr/lib64/sasl2:/etc/sasl2"

var confPathEnvVar = "SASL_CONF_PATH"

func getConfigPath() ([]string, error) {
	var path string

	if path = os.Getenv(confPathEnvVar); path == "" {
		path = ConfigPath
	}
	return filepath.SplitList(path), nil
}
