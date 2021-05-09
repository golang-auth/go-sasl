// Copyright 2021 Jake Scott. All rights reserved.
// Use of this source code is governed by the Apache License
// version 2.0 that can be found in the LICENSE file.
package registry

import (
	"regexp"

	"github.com/golang-auth/go-sasl/common"
)

// See RFC 4422 § 3.1
var saslMechRegexp = regexp.MustCompile(`^[A-Z0-9-_]{1,20}$`)

type MechFactory func(common.MechConfig) common.Mech

type mech struct {
	factory    MechFactory
	properties common.MechProps
}

var mechs map[string]mech

func init() {
	mechs = make(map[string]mech)
}

// Register should be called by Mech implementations to enable
// a mechanism to be used by clients
func Register(name string, f MechFactory, props common.MechProps) {
	if !saslMechRegexp.Match([]byte(name)) {
		panic("Bad mech name: " + name)
	}

	_, ok := mechs[name]

	// can't register two mechs with the same name
	if ok {
		panic("Cannot have two mechs named " + name)
	}

	mechs[name] = mech{
		factory:    f,
		properties: props,
	}
}

// IsRegistered can be used to find out whether a named
// mechanism is registered or not
func IsRegistered(name string) bool {
	_, ok := mechs[name]

	return ok
}

// NewMech returns a mechanism context by name
func NewMech(name string, cfg common.MechConfig) common.Mech {
	m, ok := mechs[name]

	if ok {
		return m.factory(cfg)
	}

	return nil
}

func Properties(name string) common.MechProps {
	m, ok := mechs[name]

	if ok {
		return m.properties
	}

	return common.MechProps{}
}

// Mechs returns the list of registered mechanism names
func Mechs() (l []string) {
	l = make([]string, 0, len(mechs))

	for name := range mechs {
		l = append(l, name)
	}

	return
}
