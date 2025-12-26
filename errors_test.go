// SPDX-License-Identifier: Apache-2.0

package sasl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var sentinelErrors = []error{
	ErrNoMech,
	ErrNotStarted,
	ErrAlreadyEstablished,
	ErrNotEstablished,
}

func TestErrors_Sentinels(t *testing.T) {
	// Basic sanity: exported sentinels should always be non-nil and stable values.
	for _, err := range sentinelErrors {
		assert.Error(t, err)
	}

	// Make sure they remain distinct (helps catch accidental reuse/aliasing).
	for i := 0; i < len(sentinelErrors); i++ {
		for j := i + 1; j < len(sentinelErrors); j++ {
			assert.NotEqual(t, sentinelErrors[i], sentinelErrors[j])
		}
	}
}

func TestErrTooWeak_Error_NoExternalSSF(t *testing.T) {
	err := ErrTooWeak{
		MechSSF:     10,
		ExtSSF:      0,
		RequiredSSF: 56,
	}
	assert.Equal(t, "negotiated SSF (10) is less than required SSF (56)", err.Error())
}

func TestErrTooWeak_Error_WithExternalSSF(t *testing.T) {
	err := ErrTooWeak{
		MechSSF:     10,
		ExtSSF:      20,
		RequiredSSF: 56,
	}
	assert.Equal(t, "negotiated SSF (10) + external SSF (20) is less than required SSF (56)", err.Error())
}
