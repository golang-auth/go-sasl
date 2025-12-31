// SPDX-License-Identifier: Apache-2.0

package sasl

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var AppName string

func findConfigFile(appname string) string {
	paths, err := getConfigPath()
	if err != nil {
		return ""
	}
	for _, dir := range paths {
		configPath := filepath.Join(dir, appname+".conf")
		if info, err := os.Stat(configPath); err == nil && !info.IsDir() {
			return configPath
		}
	}
	return ""
}

type config struct {
	kv map[string]string
}

var (
	ErrConfigParse = errors.New("config parse error")
	// Match key (alphanumeric, dash, underscore) followed by colon -- then an optional value
	// which is any set of characters followed by optional whitespac
	configLineRE = regexp.MustCompile(`^([a-zA-Z0-9_-]+):(?:\s*(.*?)\s*)?$`)
)

func loadConfigFile(appname string) (*config, error) {
	config := &config{
		kv: make(map[string]string),
	}
	configPath := findConfigFile(appname)
	if configPath == "" {
		return config, nil
	}

	infile, err := os.Open(configPath)
	if err != nil {
		// If file can't be opened, return config with no error (equivalent to SASL_CONTINUE)
		return config, nil
	}
	defer infile.Close()

	scanner := bufio.NewScanner(infile)
	lineno := 0

	for scanner.Scan() {
		lineno++
		line := scanner.Text()

		// Skip leading whitespace
		line = strings.TrimLeft(line, " \t")

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Match key:value pattern
		matches := configLineRE.FindStringSubmatch(line)
		if matches == nil {
			return nil, fmt.Errorf("%w: line %d: missing colon separator", ErrConfigParse, lineno)
		}

		// Extract and lowercase the key
		key := strings.ToLower(matches[1])

		// Extract the value (already trimmed by regex)
		value := matches[2]

		// Check if value is empty
		if value == "" {
			return nil, fmt.Errorf("%w: line %d: empty value", ErrConfigParse, lineno)
		}

		// Store the key-value pair
		config.kv[key] = value
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	return config, nil
}
