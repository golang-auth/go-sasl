// SPDX-License-Identifier: Apache-2.0

package sasl

import "strings"

// SecurityFlag defines the saecurity flags an application can specify
// These come from Cyrys-SASL include/sasl.h SASL_SEC_* values
type SecurityFlag int

const (
	// SecNoPlainText indicates that the application does not permit mechs susceptible to simple passive attack (eg. PLAIN, LOGIN)
	SecNoPlainText SecurityFlag = 1 << iota

	// SecNoActive indicates that the application protects from active (non-dictionary) attacks dureing t the authentcation exchange
	// and authenticates the server
	SecNoActive

	// SecNoDictionary indicates that the application does not permit mechanisms susceptible to passive dictionary attack
	SecNoDictionary

	// SecForwardSecrecy indicates that the application requires forward secrecy between sessions
	SecForwardSecrecy

	// SecNoAnonymous indicates that the application does not permit mechanisms that allow anonymous login
	SecNoAnonymous

	// SecPassCredentials indicates that the application requires mechanisms that pass client credentials,
	// and allows mechanisms that can pass credentials to do so
	SecPassCredentials // require mechanisms that pass client credentials

	// SecMutualAuth indicates that the application requires mechanisms that provide mutual authentication
	SecMutualAuth

	// SecNonStdCBind enables channel biundings on mechs that aren't supposed to support them but do so anyway (eg. GSSAPI)
	SecNonStdCBind

	SecMaximum = 0xffff
)

// securityFlagList returns a slice of individual flags derived from the
// composite value f
func SecurityFlagList(f SecurityFlag) (fl []SecurityFlag) {
	t := SecurityFlag(1)
	for i := 0; i < 32; i++ {
		if f&t != 0 {
			fl = append(fl, t)
		}

		t <<= 1
	}

	return
}

// securityFlagName returns a human-readable description of a security flag value
func securityFlagName(f SecurityFlag) string {
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
	case SecNonStdCBind:
		return "Non-standard channel binding"
	case SecMaximum:
		return "Maximum security features"
	}

	return "Unknown"
}

// String returns a string describing the security properties
func (f SecurityFlag) String() string {
	var names []string
	for _, flag := range SecurityFlagList(f) {
		names = append(names, securityFlagName(flag))
	}

	if len(names) == 0 {
		return "(no securityy flags)"
	}

	return strings.Join(names, ", ")
}

// secuityProperties define an application's required security level
type securityProperties struct {

	// MinSSF is the minmum acceptal final level
	MinSSF SSF

	// MaxSSF is the maximum acceptable final level
	MaxSSF SSF

	// SecFlags is the security flags that the application requires
	SecFlags SecurityFlag

	// MaxBufSize is the maximum size of the buffer that the application can receive
	// Zero (0) indicates that a security layer is not supported
	MaxBufSize uint32
}
