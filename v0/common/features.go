// Copyright 2021 Jake Scott. All rights reserved.
// Use of this source code is governed by the Apache License
// version 2.0 that can be found in the LICENSE file.
package common

type Feature uint32

const (
	FeatNeedServerFQDN      Feature = 1 << iota // mech requires the server FQDN
	FeatWantClientFirst                         // mech prefers client to send first
	FeatServerFirst                             // mech only supports server-first
	FeatDontUseUserPassword                     // don't use cleartext passwords
	FeatGSSFraming                              // mechanism uses GSS framing
	FeatSupportsHTTP                            // mechanism can be used for HTTP authentication
	FeatChannelBindings                         // mechanism supports channel bindings
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

// FeatureName returns a human-readable description of a context flag value
func FeatureName(f Feature) string {
	switch f {
	case FeatNeedServerFQDN:
		return "Mechanism requires the server FQDN"
	case FeatWantClientFirst:
		return "Mechanism prefers client-first protocol"
	case FeatServerFirst:
		return "Mechanism requires server-first protocol"
	case FeatDontUseUserPassword:
		return "Don't use clear text passwords"
	case FeatGSSFraming:
		return "Mechanism uses GSSAPI framing"
	case FeatSupportsHTTP:
		return "Mechanism supports HTTP authentiation"
	case FeatChannelBindings:
		return "Mechanism supports channel bindings"
	}

	return "Unknown"
}
