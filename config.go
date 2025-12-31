// SPDX-License-Identifier: Apache-2.0

package sasl

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// AppName is the name of the application and is used to locate an
// optional configuration file for the app.  Eg. "imapd".
//
// Top level application code should set this if it wants the library
// to load a Cyrus SASL compatible config file.
//
// The [SetConfigValue] function can be used to augment or override values
// read from the config file or instead of loading a config file.
var AppName string

type kv map[string]string

var config struct {
	once sync.Once
	mu   sync.RWMutex
	kv   kv
}

var (
	// ErrConifgParse denotes an issue parsing application config file
	ErrConfigParse = errors.New("config parse error")

	// Match key (alphanumeric, dash, underscore) followed by colon -- then an optional value
	// which is any set of characters preceeded by and/or followed by optional ignored whitespace
	configLineRE = regexp.MustCompile(`^([a-zA-Z0-9_-]+):(?:\s*(.*?)\s*)?$`)
)

// GetConfigValue retrieves the value of a configuration key, from the config file
// or supplied by the application via [SetConfigValue]
func GetConfigValue(key string) (string, bool) {
	if err := initConfig(); err != nil {
		log.Printf("error initializing config: %s", err)
		return "", false
	}
	config.mu.RLock()
	defer config.mu.RUnlock()

	value, ok := config.kv[key]
	return value, ok
}

// SetConfigValue sets the value of a configuration key for the application
// to use in subsequent calls to [GetConfigValue].  Overrides any value read
// from the optional config file
func SetConfigValue(key, value string) {
	if err := initConfig(); err != nil {
		log.Printf("error initializing config: %s", err)
	}
	config.mu.Lock()
	defer config.mu.Unlock()
	config.kv[key] = value
}

// load an app specific config file once per application execution,
// if the app name is set and a config file can be found for it
func initConfig() error {
	var err error
	config.once.Do(func() {
		config.mu.Lock()
		defer config.mu.Unlock()
		config.kv, err = loadConfigFile(AppName)
		if config.kv == nil {
			config.kv = make(kv)
		}
	})

	return err
}

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

func loadConfigFile(appname string) (kv, error) {
	kv := make(kv)

	// treat missing config file as an empty config
	configPath := findConfigFile(appname)
	if configPath == "" {
		return kv, nil
	}

	infile, err := os.Open(configPath)
	if err != nil {
		log.Printf("error opening config file %s: %s", configPath, err)
		return kv, nil
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
		kv[key] = value
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	return kv, nil
}
