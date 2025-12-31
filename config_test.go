// SPDX-License-Identifier: Apache-2.0

package sasl

import (
	"os"
	"path/filepath"
	"testing"
)

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
		expected      map[string]string
		expectError   bool
		errorContains string
	}{
		{
			name:          "no config file found",
			appname:       "nonexistent",
			configContent: "",
			expected:      map[string]string{},
			expectError:   false,
		},
		{
			name:          "valid config with single key-value",
			appname:       "testapp",
			configContent: "key1: value1\n",
			expected:      map[string]string{"key1": "value1"},
			expectError:   false,
		},
		{
			name:          "valid config with multiple key-values",
			appname:       "testapp",
			configContent: "key1: value1\nkey2: value2\nkey3: value3\n",
			expected:      map[string]string{"key1": "value1", "key2": "value2", "key3": "value3"},
			expectError:   false,
		},
		{
			name:          "config with comments and empty lines",
			appname:       "testapp",
			configContent: "# This is a comment\n\nkey1: value1\n# Another comment\n  \nkey2: value2\n",
			expected:      map[string]string{"key1": "value1", "key2": "value2"},
			expectError:   false,
		},
		{
			name:          "config with leading whitespace on lines",
			appname:       "testapp",
			configContent: "  key1: value1\n\tkey2: value2\n",
			expected:      map[string]string{"key1": "value1", "key2": "value2"},
			expectError:   false,
		},
		{
			name:          "config with trailing whitespace in values",
			appname:       "testapp",
			configContent: "key1: value1  \nkey2: value2\t\n",
			expected:      map[string]string{"key1": "value1", "key2": "value2"},
			expectError:   false,
		},
		{
			name:          "config with spaces in values",
			appname:       "testapp",
			configContent: "key1: value with spaces\nkey2: another value\n",
			expected:      map[string]string{"key1": "value with spaces", "key2": "another value"},
			expectError:   false,
		},
		{
			name:          "config with uppercase keys (should be lowercased)",
			appname:       "testapp",
			configContent: "KEY1: value1\nKey2: value2\nkey3: value3\n",
			expected:      map[string]string{"key1": "value1", "key2": "value2", "key3": "value3"},
			expectError:   false,
		},
		{
			name:          "config with keys containing dashes and underscores",
			appname:       "testapp",
			configContent: "key-name: value1\nkey_name: value2\nkey-name_2: value3\n",
			expected:      map[string]string{"key-name": "value1", "key_name": "value2", "key-name_2": "value3"},
			expectError:   false,
		},
		{
			name:          "config with whitespace after colon",
			appname:       "testapp",
			configContent: "key1:value1\nkey2:  value2\nkey3:\tvalue3\n",
			expected:      map[string]string{"key1": "value1", "key2": "value2", "key3": "value3"},
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
			expected:      map[string]string{"key1": "value2"},
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
			config, err := loadConfigFile(tt.appname)

			if tt.expectError {
				a.Error(err)
				if tt.errorContains != "" {
					a.Contains(err.Error(), tt.errorContains)
				}
				a.Nil(config)
			} else {
				a.NoError(err)
				a.NotNil(config)
				a.Equal(tt.expected, config.kv)
			}
		})
	}
}
