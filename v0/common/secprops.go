// Copyright 2021 Jake Scott. All rights reserved.
// Use of this source code is governed by the Apache License
// version 2.0 that can be found in the LICENSE file.
package common

type SecurityFlag uint32

const (
	SecNoPlainText     SecurityFlag = 1 << iota // don't permit mechs susceptible to simple passive attack (eg. PLAIN, LOGIN)
	SecNoActive                                 // protection from active (non-dictionary) attacks
	SecNoDictionary                             // don't permit mechanisms susceptible to passive dictionary attack
	SecForwardSecrecy                           // require forward secrecy between sessions
	SecNoAnonymous                              // don't permit mechanisms that allow anonymous login
	SecPassCredentials                          // require mechanisms that pass client credentials
	SecMutualAuth                               // require mechanisms that provide mutual authentication
)

// FlagList returns a slice of individual flags derived from the
// composite value f
func FlagList(f SecurityFlag) (fl []SecurityFlag) {
	t := SecurityFlag(1)
	for i := 0; i < 32; i++ {
		if f&t != 0 {
			fl = append(fl, t)
		}

		t <<= 1
	}

	return
}

// FlagName returns a human-readable description of a context flag value
func FlagName(f SecurityFlag) string {
	switch f {
	case SecNoPlainText:
		return "No plain text mechanisms"
	case SecNoActive:
		return "Active attack protection"
	case SecNoDictionary:
		return "No mechanisms susceptible to dictionary attacks"
	case SecForwardSecrecy:
		return "Require forward secrecy"
	case SecNoAnonymous:
		return "No anonymous mechanisms"
	case SecPassCredentials:
		return "Require passing of client credentials"
	case SecMutualAuth:
		return "Require mutual authentication"
	}

	return "Unknown"
}
