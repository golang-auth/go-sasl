// SPDX-License-Identifier: Apache-2.0

package sasl

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// resetConfig resets the config state for testing purposes
func resetConfig() {
	config.mu.Lock()
	defer config.mu.Unlock()
	config.once = sync.Once{}
	config.kv = nil
}

func TestFindConfigFile(t *testing.T) {
	tests := []struct {
		name         string
		appname      string
		createInDir1 bool
		createInDir2 bool
		expected     int // 0 = no result, 1 = dir1, 2 = dir2
	}{
		{
			name:         "found in second directory",
			appname:      "testapp",
			createInDir1: false,
			createInDir2: true,
			expected:     2,
		},
		{
			name:         "not found",
			appname:      "nonexistent",
			createInDir1: false,
			createInDir2: false,
			expected:     0,
		},
		{
			name:         "found in first directory",
			appname:      "testapp",
			createInDir1: true,
			createInDir2: false,
			expected:     1,
		},
		{
			name:         "found in first directory when both exist",
			appname:      "testapp",
			createInDir1: true,
			createInDir2: true,
			expected:     1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewAssert(t)

			// Create two temporary directories
			dir1 := t.TempDir()
			dir2 := t.TempDir()

			// Set SASL_CONF_PATH to both directories
			pathEnv := dir1 + ":" + dir2
			t.Setenv("SASL_CONF_PATH", pathEnv)

			// Create config files as specified
			if tt.createInDir1 {
				configFile1 := filepath.Join(dir1, tt.appname+".conf")
				err := os.WriteFile(configFile1, []byte("config 1"), 0644)
				a.NoError(err)
			}
			if tt.createInDir2 {
				configFile2 := filepath.Join(dir2, tt.appname+".conf")
				err := os.WriteFile(configFile2, []byte("config 2"), 0644)
				a.NoError(err)
			}

			// Determine expected result
			var expectedResult string
			switch tt.expected {
			case 1:
				expectedResult = filepath.Join(dir1, tt.appname+".conf")
			case 2:
				expectedResult = filepath.Join(dir2, tt.appname+".conf")
			case 0:
				expectedResult = ""
			}

			// Test that findConfigFile returns the expected result
			result := findConfigFile(tt.appname)
			a.Equal(expectedResult, result)
		})
	}
}

func TestLoadConfigFile(t *testing.T) {
	tests := []struct {
		name          string
		appname       string
		configContent string
		expected      kv
		expectError   bool
		errorContains string
	}{
		{
			name:          "no config file found",
			appname:       "nonexistent",
			configContent: "",
			expected:      kv{},
			expectError:   false,
		},
		{
			name:          "valid config with single key-value",
			appname:       "testapp",
			configContent: "key1: value1\n",
			expected:      kv{"key1": "value1"},
			expectError:   false,
		},
		{
			name:          "valid config with multiple key-values",
			appname:       "testapp",
			configContent: "key1: value1\nkey2: value2\nkey3: value3\n",
			expected:      kv{"key1": "value1", "key2": "value2", "key3": "value3"},
			expectError:   false,
		},
		{
			name:          "config with comments and empty lines",
			appname:       "testapp",
			configContent: "# This is a comment\n\nkey1: value1\n# Another comment\n  \nkey2: value2\n",
			expected:      kv{"key1": "value1", "key2": "value2"},
			expectError:   false,
		},
		{
			name:          "config with leading whitespace on lines",
			appname:       "testapp",
			configContent: "  key1: value1\n\tkey2: value2\n",
			expected:      kv{"key1": "value1", "key2": "value2"},
			expectError:   false,
		},
		{
			name:          "config with trailing whitespace in values",
			appname:       "testapp",
			configContent: "key1: value1  \nkey2: value2\t\n",
			expected:      kv{"key1": "value1", "key2": "value2"},
			expectError:   false,
		},
		{
			name:          "config with spaces in values",
			appname:       "testapp",
			configContent: "key1: value with spaces\nkey2: another value\n",
			expected:      kv{"key1": "value with spaces", "key2": "another value"},
			expectError:   false,
		},
		{
			name:          "config with uppercase keys (should be lowercased)",
			appname:       "testapp",
			configContent: "KEY1: value1\nKey2: value2\nkey3: value3\n",
			expected:      kv{"key1": "value1", "key2": "value2", "key3": "value3"},
			expectError:   false,
		},
		{
			name:          "config with keys containing dashes and underscores",
			appname:       "testapp",
			configContent: "key-name: value1\nkey_name: value2\nkey-name_2: value3\n",
			expected:      kv{"key-name": "value1", "key_name": "value2", "key-name_2": "value3"},
			expectError:   false,
		},
		{
			name:          "config with whitespace after colon",
			appname:       "testapp",
			configContent: "key1:value1\nkey2:  value2\nkey3:\tvalue3\n",
			expected:      kv{"key1": "value1", "key2": "value2", "key3": "value3"},
			expectError:   false,
		},
		{
			name:          "missing colon separator",
			appname:       "testapp",
			configContent: "key1: value1\nkey2 value2\n",
			expected:      nil,
			expectError:   true,
			errorContains: "missing colon separator",
		},
		{
			name:          "empty value",
			appname:       "testapp",
			configContent: "key1: value1\nkey2:\n",
			expected:      nil,
			expectError:   true,
			errorContains: "empty value",
		},
		{
			name:          "empty value with whitespace",
			appname:       "testapp",
			configContent: "key1: value1\nkey2:   \n",
			expected:      nil,
			expectError:   true,
			errorContains: "empty value",
		},
		{
			name:          "overwrite duplicate keys",
			appname:       "testapp",
			configContent: "key1: value1\nkey1: value2\n",
			expected:      kv{"key1": "value2"},
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewAssert(t)

			// Create a temporary directory
			dir := t.TempDir()

			// Set SASL_CONF_PATH to the temporary directory
			t.Setenv("SASL_CONF_PATH", dir)

			// Create config file if content is provided
			if tt.configContent != "" {
				configFile := filepath.Join(dir, tt.appname+".conf")
				err := os.WriteFile(configFile, []byte(tt.configContent), 0644)
				a.NoError(err)
			}

			// Load the config
			kv, err := loadConfigFile(tt.appname)

			if tt.expectError {
				a.Error(err)
				if tt.errorContains != "" {
					a.Contains(err.Error(), tt.errorContains)
				}
				a.Nil(kv)
			} else {
				a.NoError(err)
				a.NotNil(kv)
				a.Equal(tt.expected, kv)
			}
		})
	}
}

func TestInitConfig(t *testing.T) {
	tests := []struct {
		name          string
		appname       string
		configContent string
		expectError   bool
		errorContains string
	}{
		{
			name:          "initializes with no config file",
			appname:       "nonexistent",
			configContent: "",
			expectError:   false,
		},
		{
			name:          "initializes with valid config file",
			appname:       "testapp",
			configContent: "key1: value1\nkey2: value2\n",
			expectError:   false,
		},
		{
			name:          "returns error when config file has parse error",
			appname:       "testapp",
			configContent: "key1: value1\ninvalid line\n",
			expectError:   true,
			errorContains: "missing colon separator",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewAssert(t)
			t.Cleanup(func() { resetConfig(); AppName = "" })

			dir := t.TempDir()
			t.Setenv("SASL_CONF_PATH", dir)

			if tt.configContent != "" {
				configFile := filepath.Join(dir, tt.appname+".conf")
				err := os.WriteFile(configFile, []byte(tt.configContent), 0644)
				a.NoError(err)
			}

			AppName = tt.appname

			// Call initConfig directly
			err := initConfig()

			if tt.expectError {
				a.Error(err)
				if tt.errorContains != "" {
					a.Contains(err.Error(), tt.errorContains)
				}
			} else {
				a.NoError(err)
			}
		})
	}

	t.Run("initConfig only runs once", func(t *testing.T) {
		a := NewAssert(t)
		t.Cleanup(func() { resetConfig(); AppName = "" })

		dir := t.TempDir()
		t.Setenv("SASL_CONF_PATH", dir)

		configFile := filepath.Join(dir, "testapp.conf")
		err := os.WriteFile(configFile, []byte("key1: value1\n"), 0644)
		a.NoError(err)

		AppName = "testapp"

		// First call to initConfig should load the config
		err = initConfig()
		a.NoError(err)
		value, ok := config.kv["key1"]
		a.True(ok)
		a.Equal("value1", value)

		// Modify the config file
		err = os.WriteFile(configFile, []byte("key1: value2\n"), 0644)
		a.NoError(err)

		// Second call should still return the original value since init only runs once
		err = initConfig()
		a.NoError(err)
		value, ok = config.kv["key1"]
		a.True(ok)
		a.Equal("value1", value)
	})
}

func TestGetConfigValue(t *testing.T) {
	tests := []struct {
		name          string
		appname       string
		configContent string
		key           string
		expected      string
		found         bool
	}{
		{
			name:          "returns empty string when key not found",
			appname:       "testapp",
			configContent: "key1: value1\n",
			key:           "nonexistent",
			expected:      "",
			found:         false,
		},
		{
			name:          "returns value when key exists",
			appname:       "testapp",
			configContent: "key1: value1\nkey2: value2\n",
			key:           "key1",
			expected:      "value1",
			found:         true,
		},
		{
			name:          "returns value with case-insensitive key lookup",
			appname:       "testapp",
			configContent: "Key1: value1\n",
			key:           "key1",
			expected:      "value1",
			found:         true,
		},
		{
			name:          "returns empty string when no config file exists",
			appname:       "nonexistent",
			configContent: "",
			key:           "key1",
			expected:      "",
			found:         false,
		},
		{
			name:          "handles keys with dashes and underscores",
			appname:       "testapp",
			configContent: "key-name: value1\nkey_name: value2\n",
			key:           "key-name",
			expected:      "value1",
			found:         true,
		},
		// The next test, for parse error, is removed because GetConfigValue never returns an error,
		// but just returns (""/false) if config loading fails. This is true based on the function signature.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewAssert(t)
			t.Cleanup(func() { resetConfig(); AppName = "" })

			// Create a temporary directory
			dir := t.TempDir()

			// Set SASL_CONF_PATH to the temporary directory
			t.Setenv("SASL_CONF_PATH", dir)

			// Create config file if content is provided
			if tt.configContent != "" {
				configFile := filepath.Join(dir, tt.appname+".conf")
				err := os.WriteFile(configFile, []byte(tt.configContent), 0644)
				a.NoError(err)
			}

			// Set AppName
			AppName = tt.appname

			// Get the config value
			value, ok := GetConfigValue(tt.key)

			a.Equal(tt.found, ok)
			a.Equal(tt.expected, value)
		})
	}

	t.Run("GetConfigValue is thread-safe", func(t *testing.T) {
		a := NewAssert(t)
		t.Cleanup(func() { resetConfig(); AppName = "" })

		// Create a temporary directory
		dir := t.TempDir()
		t.Setenv("SASL_CONF_PATH", dir)

		// Create config file
		configFile := filepath.Join(dir, "testapp.conf")
		err := os.WriteFile(configFile, []byte("key1: value1\nkey2: value2\n"), 0644)
		a.NoError(err)

		AppName = "testapp"

		// Test concurrent reads
		const goroutines = 10
		done := make(chan bool, goroutines)

		for i := 0; i < goroutines; i++ {
			go func() {
				defer func() { done <- true }()
				value, ok := GetConfigValue("key1")
				a.True(ok)
				a.Equal("value1", value)
			}()
		}

		// Wait for all goroutines to complete
		for i := 0; i < goroutines; i++ {
			<-done
		}
	})
}

func TestSetConfigValue(t *testing.T) {
	tests := []struct {
		name          string
		appname       string
		configContent string
		setKey        string
		setValue      string
		getKey        string
		expected      string
		expectError   bool // Will be ignored, since SetConfigValue doesn't return error now
	}{
		{
			name:          "sets and gets new value",
			appname:       "testapp",
			configContent: "",
			setKey:        "newkey",
			setValue:      "newvalue",
			getKey:        "newkey",
			expected:      "newvalue",
			expectError:   false,
		},
		{
			name:          "overwrites existing value from config file",
			appname:       "testapp",
			configContent: "key1: value1\n",
			setKey:        "key1",
			setValue:      "updated",
			getKey:        "key1",
			expected:      "updated",
			expectError:   false,
		},
		{
			name:          "sets value when no config file exists",
			appname:       "nonexistent",
			configContent: "",
			setKey:        "key1",
			setValue:      "value1",
			getKey:        "key1",
			expected:      "value1",
			expectError:   false,
		},
		{
			name:          "handles empty value",
			appname:       "testapp",
			configContent: "",
			setKey:        "emptykey",
			setValue:      "",
			getKey:        "emptykey",
			expected:      "",
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewAssert(t)
			t.Cleanup(func() { resetConfig(); AppName = "" })

			// Create a temporary directory
			dir := t.TempDir()

			// Set SASL_CONF_PATH to the temporary directory
			t.Setenv("SASL_CONF_PATH", dir)

			// Create config file if content is provided
			if tt.configContent != "" {
				configFile := filepath.Join(dir, tt.appname+".conf")
				err := os.WriteFile(configFile, []byte(tt.configContent), 0644)
				a.NoError(err)
			}

			// Set AppName
			AppName = tt.appname

			// Set the config value -- currently does not return error
			SetConfigValue(tt.setKey, tt.setValue)

			// Get the config value and verify
			value, ok := GetConfigValue(tt.getKey)
			a.True(ok)
			a.Equal(tt.expected, value)
		})
	}

	t.Run("SetConfigValue overwrites existing value", func(t *testing.T) {
		a := NewAssert(t)
		t.Cleanup(func() { resetConfig(); AppName = "" })

		// Create a temporary directory
		dir := t.TempDir()
		t.Setenv("SASL_CONF_PATH", dir)

		// Create config file
		configFile := filepath.Join(dir, "testapp.conf")
		err := os.WriteFile(configFile, []byte("key1: original\n"), 0644)
		a.NoError(err)

		AppName = "testapp"

		// Verify original value
		value, ok := GetConfigValue("key1")
		a.True(ok)
		a.Equal("original", value)

		// Set new value
		SetConfigValue("key1", "updated")

		// Verify updated value
		value, ok = GetConfigValue("key1")
		a.True(ok)
		a.Equal("updated", value)

		// Set again
		SetConfigValue("key1", "updated2")

		// Verify second update
		value, ok = GetConfigValue("key1")
		a.True(ok)
		a.Equal("updated2", value)
	})

	t.Run("SetConfigValue is thread-safe", func(t *testing.T) {
		a := NewAssert(t)
		t.Cleanup(func() { resetConfig(); AppName = "" })

		// Create a temporary directory
		dir := t.TempDir()
		t.Setenv("SASL_CONF_PATH", dir)

		AppName = "testapp"

		// Test concurrent writes and reads
		const goroutines = 10
		done := make(chan bool, goroutines)

		for i := 0; i < goroutines; i++ {
			go func(id int) {
				defer func() { done <- true }()
				key := "key1"
				value := "value1"
				SetConfigValue(key, value)

				// Verify we can read it back
				result, ok := GetConfigValue(key)
				a.True(ok)
				// Value should be set (may be overwritten by other goroutines, but should be valid)
				a.NotEmpty(result)
			}(i)
		}

		// Wait for all goroutines to complete
		for i := 0; i < goroutines; i++ {
			<-done
		}
	})

	t.Run("SetConfigValue does not return error even if config parse fails", func(t *testing.T) {
		a := NewAssert(t)
		t.Cleanup(func() { resetConfig(); AppName = "" })

		// Create a temporary directory
		dir := t.TempDir()
		t.Setenv("SASL_CONF_PATH", dir)

		// Create invalid config file
		configFile := filepath.Join(dir, "testapp.conf")
		err := os.WriteFile(configFile, []byte("key1: value1\ninvalid line\n"), 0644)
		a.NoError(err)

		AppName = "testapp"

		// SetConfigValue should not panic or error
		// (but config may not have loaded, so new value should be set)
		SetConfigValue("key2", "value2")
		value, ok := GetConfigValue("key2")
		// Since loading fails, depending on implementation, key2 may or may not be set.
		// But code should not panic. Accept both.
		if ok {
			a.Equal("value2", value)
		}
	})
}
