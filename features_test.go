// SPDX-License-Identifier: Apache-2.0

package sasl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var knownFeatures = []Feature{
	FeatNeedServerFQDN,
	FeatWantClientFirst,
	FeatServerFirst,
	FeatAllowsProxy,
	FeatDontUseUserPassword,
	FeatGSSFraming,
	FeatChannelBindings,
	FeatSupportsHTTP,
}

func TestFeatureList_Zero(t *testing.T) {
	assert.Empty(t, FeatureList(0))
}

func TestFeatureList_SingleBit(t *testing.T) {
	assert.Equal(t, []Feature{FeatNeedServerFQDN}, FeatureList(FeatNeedServerFQDN))
	assert.Equal(t, []Feature{FeatSupportsHTTP}, FeatureList(FeatSupportsHTTP))
}

func TestFeatureList_MultipleBits_OrderLowToHigh(t *testing.T) {
	f := FeatWantClientFirst | FeatAllowsProxy | FeatSupportsHTTP
	assert.Equal(t, []Feature{FeatWantClientFirst, FeatAllowsProxy, FeatSupportsHTTP}, FeatureList(f))
}

func TestFeatureList_UnknownBitIncluded(t *testing.T) {
	unknown := Feature(1 << 12)
	assert.Equal(t, []Feature{unknown}, FeatureList(unknown))

	combined := FeatNeedServerFQDN | unknown | FeatServerFirst
	assert.Equal(t, []Feature{FeatNeedServerFQDN, FeatServerFirst, unknown}, FeatureList(combined))
}

func TestFeature_String_Zero(t *testing.T) {
	assert.Contains(t, Feature(0).String(), "no security features")
}

func TestFeature_String_KnownFeatures_NonEmptyAndUnique(t *testing.T) {
	seen := map[string]Feature{}
	for _, f := range knownFeatures {
		s := f.String()
		assert.NotEmpty(t, s)
		if prev, ok := seen[s]; ok {
			t.Fatalf("expected unique feature stringifications; %v and %v both stringified to %q", prev, f, s)
		}
		seen[s] = f
	}

	// Composite values should also stringify to something non-empty.
	assert.NotEmpty(t, (FeatNeedServerFQDN | FeatAllowsProxy | FeatChannelBindings).String())
}

func TestFeature_String_UnknownFeature_NonEmpty(t *testing.T) {
	unknown := Feature(1 << len(knownFeatures))
	assert.Equal(t, "Unknown", unknown.String())
}
