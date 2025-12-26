// SPDX-License-Identifier: Apache-2.0

package sasl

import (
	"errors"
	"regexp"
	"slices"
	"sync"
)

var ErrMechNotFound = errors.New("mechsniam not found")

var registry struct {
	sync.RWMutex
	mechs []MechInfo
}

// MechInfo contains information about a SASL mechanism.
type MechInfo struct {
	// Name is the unqique IANA registered name of the mechanism
	Name string // RFC 4422 § 3.1
	// Provider supplies the name of the provider that implements the mechanism.
	Provider string
	// MaxSSF is the maximum security strength factor (SSF) that the mechanism can support
	MaxSSF SSF
	// Features are the features that the mechanism supports
	Features Feature
	// SecFlags are the security flags that the mechanism supports
	SecFlags SecurityFlag
	// HashStrength is the hash strength that the mechanism supports
	HashStrength uint
	// Constructor is a function that can be used to instantiate the mechanism
	Constructor MechConstructor
}

// See RFC 4422 § 3.1
var saslMechRegexp = regexp.MustCompile(`^[A-Z0-9-_]{1,20}$`)

// MechConstructor defines the function signature passed to RegisterMech, used
// by the registration interface to create new instances of a mechanism.
type MechConstructor func(config MechConfig) (Mech, error)

// RegisterMech associates the supplied Mech constructor with the unique
// name for the Mech. If a Mech with name is already registered, the new
// factory function will replace the existing registration.
//
// SASL Mechs must register themselves by calling RegisterMech in their
// init() function. Mechs should document the unique name used in their call
// to RegisterMech which should be registered with the IANA registry at
// https://www.iana.org/assignments/sasl-mechanisms/sasl-mechanisms.xhtml.
//
// Parameters:
//   - info: information about the Mech
//
// The function always succeed or panics if the mech name is invalid.
func RegisterMech(newMech MechInfo) {
	if !saslMechRegexp.Match([]byte(newMech.Name)) {
		panic("Bad mech name: " + newMech.Name)
	}

	registry.Lock()
	defer registry.Unlock()

	// insert the new mech, sorted by relative strength (strongest first)
	insertIndex := len(registry.mechs)
	for i, mech := range registry.mechs {
		if mechCompare(mech, newMech) > 0 {
			// mech is stronger than newMech, so newMech goes after mech
			insertIndex = i + 1
		} else {
			// newMech is stronger than or equal to mech, so insert before mech
			insertIndex = i
			break
		}
	}

	registry.mechs = slices.Insert(registry.mechs, insertIndex, newMech)
}

func newMech(name string, config MechConfig) (p Mech, err error) {
	registry.RLock()
	defer registry.RUnlock()

	mi, err := GetMechInfo(name)
	if err != nil {
		return nil, err
	}

	return mi.Constructor(config)
}

func GetMechInfo(name string) (info *MechInfo, err error) {
	registry.RLock()
	defer registry.RUnlock()

	for _, info := range registry.mechs {
		if info.Name == name {
			return &info, nil
		}
	}

	return nil, ErrMechNotFound
}

// HasMech can be used to find out whether a named
// mechanism is registered or not
func HasMech(name string) bool {
	registry.RLock()
	defer registry.RUnlock()

	_, err := GetMechInfo(name)
	if err != nil {
		return false
	}

	return true
}

func RegisteredMechs() []string {
	registry.RLock()
	defer registry.RUnlock()

	mechs := make([]string, len(registry.mechs))
	for i, mi := range registry.mechs {
		mechs[i] = mi.Name
	}

	return mechs
}

// MechConfig is used to initialize a Mech instance by the SASL glue code
type MechConfig struct {
	Logger             Loggers
	Service            string
	ServerFQDN         string
	ClientFQDN         string
	ExternalProperties ExternalProperties
	SecProps           SecurityFlag
	CBDisposition      channelBindingDisposition
}

type Mech interface {
	Name() string
	IsEstablished() bool
	Step(inToken []byte) (outToken []byte, err error)
	// ContextParams() ContextParams
	// Encode(input []byte) (outToken []byte, err error)
	// Decode(inputToken []byte) (output []byte, err error)
}

func trimMechsToRegistered(mechs []string) []string {
	// trim the mech list to only those that are registered
	var newMechList []string

	for _, name := range mechs {
		if HasMech(name) {
			newMechList = append(newMechList, name)
		}
	}

	return newMechList
}

// mechCompare compares two mechanisms and returns:
//
//	 1 if a should be preferred over b
//	-1 if b should be preferred over a
//	 0 if they are equal
//
// This is a port of Cyrus SASL's mech_compare function.
func mechCompare(a, b MechInfo) int {
	secDiff := a.SecFlags ^ b.SecFlags

	// Check security flags differences, preferring mechanisms with these flags
	for _, flag := range []SecurityFlag{
		SecNoAnonymous,
		SecNoPlainText,
		SecMutualAuth,
		SecNoActive,
		SecNoDictionary,
		SecForwardSecrecy,
	} {
		if secDiff&a.SecFlags&flag != 0 {
			return 1
		}
		if secDiff&b.SecFlags&flag != 0 {
			return -1
		}
	}

	// Check feature flags differences
	featuresDiff := a.Features ^ b.Features
	if featuresDiff&a.Features&FeatChannelBindings != 0 {
		return 1
	}
	if featuresDiff&b.Features&FeatChannelBindings != 0 {
		return -1
	}

	// Compare max_ssf (higher is better)
	if a.MaxSSF > b.MaxSSF {
		return 1
	}
	if a.MaxSSF < b.MaxSSF {
		return -1
	}

	// Compare hash strength (higher is better)
	if a.HashStrength > b.HashStrength {
		return 1
	}
	if a.HashStrength < b.HashStrength {
		return -1
	}

	return 0
}
