// Copyright 2021 Jake Scott. All rights reserved.
// Use of this source code is governed by the Apache License
// version 2.0 that can be found in the LICENSE file.
package registry

import (
	"testing"

	"github.com/golang-auth/go-sasl/common"
	"github.com/stretchr/testify/assert"
)

type dummyMech struct {
	rand int
}

func (m dummyMech) Name() string {
	return "MOCK"
}
func (m dummyMech) MechProperties() common.MechProps {
	return common.MechProps{}
}
func (m dummyMech) IsEstablished() bool {
	return false
}
func (m dummyMech) Step(inToken []byte) (outToken []byte, err error) {
	return nil, nil
}
func (m dummyMech) ContextParams() common.ContextParams {
	return common.ContextParams{}
}
func (m dummyMech) Encode([]byte) ([]byte, error) {
	return nil, nil
}
func (m dummyMech) Decode([]byte) ([]byte, error) {
	return nil, nil
}

func TestRegister(t *testing.T) {
	mf := func(common.MechConfig) common.Mech {
		return dummyMech{rand: 123}
	}
	props := common.MechProps{}

	assert.NotPanics(t, func() { Register("TEST", mf, props) })

	// panics because its already registered
	assert.Panics(t, func() { Register("TEST", mf, props) })

	// panics because the mech name isn't valid (lower case not allowed)
	assert.Panics(t, func() { Register("bad-mech-name", mf, props) })
}

func TestIsRegistered(t *testing.T) {
	mf := func(common.MechConfig) common.Mech {
		return dummyMech{rand: 456}
	}
	props := common.MechProps{}

	assert.NotPanics(t, func() { Register("TEST1", mf, props) })
	assert.True(t, IsRegistered("TEST1"))
	assert.False(t, IsRegistered("NEVER_REGISTERED"))
}

func TestMechs(t *testing.T) {
	// start with empty mech list
	mechs = make(map[string]mech)

	mf := func(common.MechConfig) common.Mech {
		return dummyMech{rand: 789}
	}
	props := common.MechProps{}

	assert.NotPanics(t, func() { Register("TEST2", mf, props) })
	assert.NotPanics(t, func() { Register("TEST3", mf, props) })

	names := Mechs()
	assert.Equal(t, []string{"TEST2", "TEST3"}, names)
}

func TestNewMech(t *testing.T) {
	mf1 := func(common.MechConfig) common.Mech {
		return dummyMech{rand: 98765}
	}
	mf2 := func(common.MechConfig) common.Mech {
		return dummyMech{rand: 54321}
	}
	props := common.MechProps{}

	assert.NotPanics(t, func() { Register("TEST5", mf1, props) })
	assert.NotPanics(t, func() { Register("TEST6", mf2, props) })

	mech1 := NewMech("TEST5", common.MechConfig{})
	mech2 := NewMech("TEST6", common.MechConfig{})
	mech3 := NewMech("no-such-mech", common.MechConfig{})

	assert.NotNil(t, mech1)
	assert.NotNil(t, mech2)
	assert.Nil(t, mech3)

	assert.IsType(t, dummyMech{}, mech1)
	assert.IsType(t, dummyMech{}, mech2)

	testMech1, ok1 := mech1.(dummyMech)
	testMech2, ok2 := mech2.(dummyMech)
	assert.True(t, ok1)
	assert.True(t, ok2)

	assert.Equal(t, 98765, testMech1.rand)
	assert.Equal(t, 54321, testMech2.rand)
}
