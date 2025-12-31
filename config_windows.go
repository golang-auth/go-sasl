// SPDX-License-Identifier: Apache-2.0

//go:build windows

package sasl

import (
	"fmt"
	"path/filepath"

	"golang.org/x/sys/windows/registry"
)

// ConfigPath is the search path for SASL configuration files
var ConfigPath = `C:\Program Files\SASL\sasl2`

var baseRegKey = `SOFTWARE\Project Cyrus\SASL Library`
var baseRegHive registry.Key = registry.LOCAL_MACHINE
var confPathAttr = "ConfDir"

func getConfigPath() ([]string, error) {
	k, err := registry.OpenKey(baseRegHive, baseRegKey, registry.READ)
	if err != nil {
		// If registry key doesn't exist, return default config path
		return filepath.SplitList(ConfigPath), nil
	}
	defer k.Close()

	_, valType, err := k.GetValue(confPathAttr, nil)
	if err != nil {
		return nil, fmt.Errorf("Failed to get value for %s\\%s: %v", baseRegKey, confPathAttr, err)
	}

	paths := []string{}
	switch valType {
	default:
		return nil, fmt.Errorf("bad type %d for registry value %s\\%s", valType, baseRegKey, confPathAttr)
	case registry.SZ, registry.EXPAND_SZ:
		confPath, _, err := k.GetStringValue(confPathAttr)
		if err != nil {
			return nil, fmt.Errorf("Failed to get string value for %s\\%s: %v", baseRegKey, confPathAttr, err)
		}
		paths = append(paths, confPath)
	case registry.MULTI_SZ:
		confPaths, _, err := k.GetStringsValue(confPathAttr)
		if err != nil {
			return nil, fmt.Errorf("Failed to get strings value for %s\\%s: %v", baseRegKey, confPathAttr, err)
		}
		paths = append(paths, confPaths...)
	}

	return paths, nil
}
