// SPDX-License-Identifier: Apache-2.0

package sasl

import "strings"

// Features defines the features of a mechanism (RFC 4422 § 5)
// These come from from Cyrys-SASL include/saslplug.h SASL_FEAT_* values
// minus deprecated features.
type Feature int

const (
	// FeatNeedServerFQDN indicates that the mechanism requires the server FQDN
	FeatNeedServerFQDN Feature = 1 << iota

	// FeatWantClientFirstindicated that the mechanism prefers client-send-first
	// if the protocol allows it
	FeatWantClientFirst

	// FeatServerFirst indicates that the mechanism is server-first only.
	// If neither FeatWantClikentFirst or FeatServerFirst is set, the mech handles
	// client-first internally
	FeatServerFirst

	// FeatAllowsProxy indicates that the mechanism allows proxying
	FeatAllowsProxy

	// FeatDontUseUserPassword indicates that the mechanism does not use clear text passwords
	FeatDontUseUserPassword

	// FeatGSSFraming indicates that the mechanism uses GSSAPI framing
	FeatGSSFraming

	// FeatChannelBindings indicates that the mechanism supports channel bindings
	FeatChannelBindings

	// FeatSupportsHTTP indicates that the mechanism can be used for HTTP authentication
	FeatSupportsHTTP
)

// FeatureList returns a slice of individual features derived from the
// composite value f
func FeatureList(f Feature) (fl []Feature) {
	t := Feature(1)
	for i := 0; i < 32; i++ {
		if f&t != 0 {
			fl = append(fl, t)
		}

		t <<= 1
	}

	return
}

// featureName returns a human-readable description of a feature
func featureName(f Feature) string {
	switch f {
	case FeatNeedServerFQDN:
		return "Mechanism requires the server FQDN"
	case FeatWantClientFirst:
		return "Mechanism prefers client-first protocol"
	case FeatServerFirst:
		return "Mechanism requires server-first protocol"
	case FeatAllowsProxy:
		return "Mechanism allows proxying"
	case FeatDontUseUserPassword:
		return "Don't use clear text passwords"
	case FeatGSSFraming:
		return "Mechanism uses GSSAPI framing"
	case FeatChannelBindings:
		return "Mechanism supports channel bindings"
	case FeatSupportsHTTP:
		return "Mechanism supports HTTP authentiation"
	}

	return "Unknown"
}

// String returns a string describing the supported features
func (f Feature) String() string {
	var names []string
	for _, feature := range FeatureList(f) {
		names = append(names, featureName(feature))
	}

	if len(names) == 0 {
		return "(no mecchanism features)"
	}

	return strings.Join(names, ", ")
}
