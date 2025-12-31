// SPDX-License-Identifier: Apache-2.0

//go:build windows

package sasl

import (
	"testing"

	"golang.org/x/sys/windows/registry"
)

const testRegKey = `Software\go-sasl-test`

func setupTestRegistryKey(t *testing.T, paths []string) {
	t.Helper()
	a := NewAssert(t)

	// Save original values
	originalBaseRegKey := baseRegKey
	originalBaseRegHive := baseRegHive

	// Override with test values
	baseRegKey = testRegKey
	baseRegHive = registry.CURRENT_USER

	// Restore original values after the test
	t.Cleanup(func() {
		baseRegKey = originalBaseRegKey
		baseRegHive = originalBaseRegHive
	})

	// Create the registry key
	k, _, err := registry.CreateKey(registry.CURRENT_USER, testRegKey, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		t.Fatalf("Failed to create test registry key: %v", err)
	}

	// Set the value based on number of paths
	if len(paths) == 1 {
		// Use REG_SZ for single path
		err = k.SetStringValue(confPathAttr, paths[0])
		a.NoErrorFatal(err)
	} else {
		// Use REG_MULTI_SZ for multiple paths
		err = k.SetStringsValue(confPathAttr, paths)
		a.NoErrorFatal(err)
	}

	// Close the key
	k.Close()

	// Clean up the registry key after the test
	t.Cleanup(func() {
		// Open the key to delete the value
		cleanupKey, err := registry.OpenKey(registry.CURRENT_USER, testRegKey, registry.SET_VALUE)
		if err == nil {
			_ = cleanupKey.DeleteValue(confPathAttr)
			cleanupKey.Close()
		}
		// Delete the key
		_ = registry.DeleteKey(registry.CURRENT_USER, testRegKey)
	})
}

func TestGetConfigPathDefault(t *testing.T) {
	a := NewAssert(t)
	expectedPaths := []string{`C:\Program Files\SASL\sasl2`}

	// Save original values
	originalBaseRegKey := baseRegKey

	// Override with a non-existent test key
	baseRegKey = testRegKey + "-nonexistent"

	// Restore original values after the test
	t.Cleanup(func() {
		baseRegKey = originalBaseRegKey
	})

	paths, err := getConfigPath()
	a.NoErrorFatal(err)
	a.Equal(expectedPaths, paths)
}

func TestGetConfigPathSingle(t *testing.T) {
	a := NewAssert(t)
	expectedPaths := []string{`C:\Program Files\SASL\sasl2`}
	setupTestRegistryKey(t, expectedPaths)

	paths, err := getConfigPath()
	a.NoErrorFatal(err)
	a.Equal(expectedPaths, paths)
}

func TestGetConfigPathMultiple(t *testing.T) {
	a := NewAssert(t)
	expectedPaths := []string{`C:\Program Files\SASL\sasl2`, `C:\Program Files (x86)\SASL\sasl2`}
	setupTestRegistryKey(t, expectedPaths)

	paths, err := getConfigPath()
	a.NoErrorFatal(err)
	a.Equal(expectedPaths, paths)
}
