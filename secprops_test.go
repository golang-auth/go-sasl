// SPDX-License-Identifier: Apache-2.0

package sasl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var knownSecurityFlags = []SecurityFlag{
	SecNoPlainText,
	SecNoActive,
	SecNoDictionary,
	SecForwardSecrecy,
	SecNoAnonymous,
	SecPassCredentials,
	SecMutualAuth,
	SecNonStdCBind,
}

func TestSecurityFlagList_Zero(t *testing.T) {
	assert.Empty(t, SecurityFlagList(0))
}

func TestSecurityFlagList_SingleBit(t *testing.T) {
	assert.Equal(t, []SecurityFlag{SecNoPlainText}, SecurityFlagList(SecNoPlainText))
	assert.Equal(t, []SecurityFlag{SecNonStdCBind}, SecurityFlagList(SecNonStdCBind))
}

func TestSecurityFlagList_MultipleBits_OrderLowToHigh(t *testing.T) {
	f := SecNoActive | SecForwardSecrecy | SecNonStdCBind
	assert.Equal(t, []SecurityFlag{SecNoActive, SecForwardSecrecy, SecNonStdCBind}, SecurityFlagList(f))
}

func TestSecurityFlagList_UnknownBitIncluded(t *testing.T) {
	unknown := SecurityFlag(1 << 12)
	assert.Equal(t, []SecurityFlag{unknown}, SecurityFlagList(unknown))

	combined := SecNoPlainText | unknown | SecNoDictionary
	assert.Equal(t, []SecurityFlag{SecNoPlainText, SecNoDictionary, unknown}, SecurityFlagList(combined))
}

func TestSecurityFlag_String_Zero(t *testing.T) {
	assert.Contains(t, SecurityFlag(0).String(), "no security")
}

func TestSecurityFlag_String_KnownFlags_NonEmptyAndUnique(t *testing.T) {
	seen := map[string]SecurityFlag{}
	for _, f := range knownSecurityFlags {
		s := f.String()
		assert.NotEmpty(t, s)
		if prev, ok := seen[s]; ok {
			t.Fatalf("expected unique security flag stringifications; %v and %v both stringified to %q", prev, f, s)
		}
		seen[s] = f
	}

	// Composite values should also stringify to something non-empty.
	assert.NotEmpty(t, (SecNoActive | SecNoDictionary | SecMutualAuth).String())
}

func TestSecurityFlag_String_UnknownFlag_NonEmpty(t *testing.T) {
	unknown := SecurityFlag(1 << len(knownSecurityFlags))
	assert.Equal(t, "Unknown", unknown.String())
}

func TestSecurityFlagName_KnownAndSpecialCases(t *testing.T) {
	assert.NotEmpty(t, securityFlagName(SecNoPlainText))
	assert.Equal(t, "Maximum security features", securityFlagName(SecMaximum))
}

func TestSecurityProperties_StructWiring(t *testing.T) {
	sp := securityProperties{
		MinSSF:     SSF(10),
		MaxSSF:     SSF(256),
		SecFlags:   SecNoPlainText | SecNoAnonymous,
		MaxBufSize: 4096,
	}

	assert.Equal(t, SSF(10), sp.MinSSF)
	assert.Equal(t, SSF(256), sp.MaxSSF)
	assert.Equal(t, SecNoPlainText|SecNoAnonymous, sp.SecFlags)
	assert.Equal(t, uint32(4096), sp.MaxBufSize)
}
