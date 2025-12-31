// SPDX-License-Identifier: Apache-2.0

package sasl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type dummyMech struct {
	rand int
}

func (m dummyMech) Name() string {
	return "MOCK"
}

func (m dummyMech) MechProperties() MechInfo {
	return MechInfo{}
}
func (m dummyMech) IsEstablished() bool {
	return false
}

func (m dummyMech) Step(inToken []byte) (outToken []byte, err error) {
	return nil, nil
}

func (m dummyMech) Dispose() {
}

// func (m dummyMech) ContextParams() common.ContextParams {
// 	return common.ContextParams{}
// }
// func (m dummyMech) Encode([]byte) ([]byte, error) {
// 	return nil, nil
// }
// func (m dummyMech) Decode([]byte) ([]byte, error) {
// 	return nil, nil
// }

func TestRegisterMech(t *testing.T) {
	t.Cleanup(func() { resetRegistry() })

	assert.NotPanics(t, func() { RegisterMech(MechInfo{Name: "TEST"}) })

	// panics because the mech name isn't valid (lower case not allowed)
	assert.Panics(t, func() { RegisterMech(MechInfo{Name: "bad-mech-name"}) })
}

func TestRegisterMech_InsertionOrder(t *testing.T) {
	t.Cleanup(func() { resetRegistry() })

	// Register mechanisms in a random order to verify they are sorted correctly
	// Expected order (strongest to weakest):
	// 1. MECH_SEC - has SecNoPlainText (highest priority security flag)
	// 2. MECH_FEAT - has FeatChannelBindings (feature)
	// 3. MECH_SSF_HIGH - has MaxSSF 200
	// 4. MECH_SSF_LOW - has MaxSSF 100
	// 5. MECH_HASH_HIGH - has HashStrength 512
	// 6. MECH_HASH_LOW - has HashStrength 256
	// 7. MECH_BASIC - no special properties

	RegisterMech(MechInfo{
		Name:         "MECH_BASIC",
		MaxSSF:       0,
		Features:     0,
		SecFlags:     0,
		HashStrength: 0,
	})

	RegisterMech(MechInfo{
		Name:         "MECH_SSF_HIGH",
		MaxSSF:       200,
		Features:     0,
		SecFlags:     0,
		HashStrength: 0,
	})

	RegisterMech(MechInfo{
		Name:         "MECH_SEC",
		MaxSSF:       0,
		Features:     0,
		SecFlags:     SecNoPlainText,
		HashStrength: 0,
	})

	RegisterMech(MechInfo{
		Name:         "MECH_HASH_LOW",
		MaxSSF:       0,
		Features:     0,
		SecFlags:     0,
		HashStrength: 256,
	})

	RegisterMech(MechInfo{
		Name:         "MECH_FEAT",
		MaxSSF:       0,
		Features:     FeatChannelBindings,
		SecFlags:     0,
		HashStrength: 0,
	})

	RegisterMech(MechInfo{
		Name:         "MECH_SSF_LOW",
		MaxSSF:       100,
		Features:     0,
		SecFlags:     0,
		HashStrength: 0,
	})

	RegisterMech(MechInfo{
		Name:         "MECH_HASH_HIGH",
		MaxSSF:       0,
		Features:     0,
		SecFlags:     0,
		HashStrength: 512,
	})

	names := RegisteredMechs()
	expectedOrder := []string{
		"MECH_SEC",       // Security flags have highest priority
		"MECH_FEAT",      // Features come after security flags
		"MECH_SSF_HIGH",  // MaxSSF 200 > MaxSSF 100
		"MECH_SSF_LOW",   // MaxSSF 100
		"MECH_HASH_HIGH", // HashStrength 512 > HashStrength 256
		"MECH_HASH_LOW",  // HashStrength 256
		"MECH_BASIC",     // No special properties
	}

	assert.Equal(t, expectedOrder, names, "mechanisms should be sorted by strength (strongest first)")
}

func TestHasMech(t *testing.T) {
	t.Cleanup(func() { resetRegistry() })

	assert.NotPanics(t, func() { RegisterMech(MechInfo{Name: "TEST"}) })
	assert.True(t, HasMech("TEST"))
	assert.False(t, HasMech("NEVER_REGISTERED"))
}

func TestGetRegisteredMechs(t *testing.T) {
	t.Cleanup(func() { resetRegistry() })

	assert.NotPanics(t, func() { RegisterMech(MechInfo{Name: "TEST1"}) })
	assert.NotPanics(t, func() { RegisterMech(MechInfo{Name: "TEST2"}) })

	names := RegisteredMechs()
	assert.ElementsMatch(t, []string{"TEST1", "TEST2"}, names)
}

func TestMechInfo_NotFound(t *testing.T) {
	t.Cleanup(func() { resetRegistry() })

	info, err := GetMechInfo("DOES_NOT_EXIST")
	assert.ErrorIs(t, err, ErrMechNotFound)
	assert.Equal(t, MechInfo{}, info)
}

func TestMechInfo_Found(t *testing.T) {
	t.Cleanup(func() { resetRegistry() })

	want := MechInfo{
		Name:     "MOCK",
		Provider: "unit-test",
		MaxSSF:   123,
		Features: FeatAllowsProxy,
		SecFlags: SecNoPlainText,
		Constructor: func(config MechConfig) (Mech, error) {
			return dummyMech{rand: 7}, nil
		},
	}
	RegisterMech(want)

	got, err := GetMechInfo("MOCK")
	assert.NoError(t, err)
	assert.Equal(t, want.Name, got.Name)
	assert.Equal(t, want.Provider, got.Provider)
	assert.Equal(t, want.MaxSSF, got.MaxSSF)
	assert.Equal(t, want.Features, got.Features)
	assert.Equal(t, want.SecFlags, got.SecFlags)
	assert.NotNil(t, got.Constructor)
}

func TestNewMech_NotFound(t *testing.T) {
	t.Cleanup(func() { resetRegistry() })

	m, err := newMech("DOES_NOT_EXIST", MechConfig{})
	assert.ErrorIs(t, err, ErrMechNotFound)
	assert.Nil(t, m)
}

func TestNewMech_Found_CallsConstructor(t *testing.T) {
	t.Cleanup(func() { resetRegistry() })

	calls := 0
	RegisterMech(MechInfo{
		Name: "MOCK",
		Constructor: func(config MechConfig) (Mech, error) {
			calls++
			return dummyMech{rand: 42}, nil
		},
	})

	m, err := newMech("MOCK", MechConfig{})
	assert.NoError(t, err)
	assert.NotNil(t, m)
	assert.Equal(t, 1, calls)
	assert.Equal(t, "MOCK", m.Name())
}

func TestMechCompare(t *testing.T) {
	tests := []struct {
		name        string
		a           MechInfo
		b           MechInfo
		want        int
		description string
	}{
		{
			name: "equal mechanisms",
			a: MechInfo{
				Name:         "MECH1",
				MaxSSF:       100,
				Features:     0,
				SecFlags:     0,
				HashStrength: 256,
			},
			b: MechInfo{
				Name:         "MECH2",
				MaxSSF:       100,
				Features:     0,
				SecFlags:     0,
				HashStrength: 256,
			},
			want:        0,
			description: "mechanisms with identical properties should be equal",
		},
		{
			name: "SecNoAnonymous preference",
			a: MechInfo{
				Name:         "MECH1",
				MaxSSF:       0,
				Features:     0,
				SecFlags:     SecNoAnonymous,
				HashStrength: 0,
			},
			b: MechInfo{
				Name:         "MECH2",
				MaxSSF:       0,
				Features:     0,
				SecFlags:     0,
				HashStrength: 0,
			},
			want:        1,
			description: "mechanism with SecNoAnonymous should be preferred",
		},
		{
			name: "SecNoPlainText preference",
			a: MechInfo{
				Name:         "MECH1",
				MaxSSF:       0,
				Features:     0,
				SecFlags:     SecNoPlainText,
				HashStrength: 0,
			},
			b: MechInfo{
				Name:         "MECH2",
				MaxSSF:       0,
				Features:     0,
				SecFlags:     0,
				HashStrength: 0,
			},
			want:        1,
			description: "mechanism with SecNoPlainText should be preferred",
		},
		{
			name: "SecMutualAuth preference",
			a: MechInfo{
				Name:         "MECH1",
				MaxSSF:       0,
				Features:     0,
				SecFlags:     SecMutualAuth,
				HashStrength: 0,
			},
			b: MechInfo{
				Name:         "MECH2",
				MaxSSF:       0,
				Features:     0,
				SecFlags:     0,
				HashStrength: 0,
			},
			want:        1,
			description: "mechanism with SecMutualAuth should be preferred",
		},
		{
			name: "SecNoActive preference",
			a: MechInfo{
				Name:         "MECH1",
				MaxSSF:       0,
				Features:     0,
				SecFlags:     SecNoActive,
				HashStrength: 0,
			},
			b: MechInfo{
				Name:         "MECH2",
				MaxSSF:       0,
				Features:     0,
				SecFlags:     0,
				HashStrength: 0,
			},
			want:        1,
			description: "mechanism with SecNoActive should be preferred",
		},
		{
			name: "SecNoDictionary preference",
			a: MechInfo{
				Name:         "MECH1",
				MaxSSF:       0,
				Features:     0,
				SecFlags:     SecNoDictionary,
				HashStrength: 0,
			},
			b: MechInfo{
				Name:         "MECH2",
				MaxSSF:       0,
				Features:     0,
				SecFlags:     0,
				HashStrength: 0,
			},
			want:        1,
			description: "mechanism with SecNoDictionary should be preferred",
		},
		{
			name: "SecForwardSecrecy preference",
			a: MechInfo{
				Name:         "MECH1",
				MaxSSF:       0,
				Features:     0,
				SecFlags:     SecForwardSecrecy,
				HashStrength: 0,
			},
			b: MechInfo{
				Name:         "MECH2",
				MaxSSF:       0,
				Features:     0,
				SecFlags:     0,
				HashStrength: 0,
			},
			want:        1,
			description: "mechanism with SecForwardSecrecy should be preferred",
		},
		{
			name: "FeatChannelBindings preference",
			a: MechInfo{
				Name:         "MECH1",
				MaxSSF:       0,
				Features:     FeatChannelBindings,
				SecFlags:     0,
				HashStrength: 0,
			},
			b: MechInfo{
				Name:         "MECH2",
				MaxSSF:       0,
				Features:     0,
				SecFlags:     0,
				HashStrength: 0,
			},
			want:        1,
			description: "mechanism with FeatChannelBindings should be preferred",
		},
		{
			name: "MaxSSF preference",
			a: MechInfo{
				Name:         "MECH1",
				MaxSSF:       200,
				Features:     0,
				SecFlags:     0,
				HashStrength: 0,
			},
			b: MechInfo{
				Name:         "MECH2",
				MaxSSF:       100,
				Features:     0,
				SecFlags:     0,
				HashStrength: 0,
			},
			want:        1,
			description: "mechanism with higher MaxSSF should be preferred",
		},
		{
			name: "HashStrength preference",
			a: MechInfo{
				Name:         "MECH1",
				MaxSSF:       0,
				Features:     0,
				SecFlags:     0,
				HashStrength: 512,
			},
			b: MechInfo{
				Name:         "MECH2",
				MaxSSF:       0,
				Features:     0,
				SecFlags:     0,
				HashStrength: 256,
			},
			want:        1,
			description: "mechanism with higher HashStrength should be preferred",
		},
		{
			name: "security flags priority over features",
			a: MechInfo{
				Name:         "MECH1",
				MaxSSF:       0,
				Features:     0,
				SecFlags:     SecNoPlainText,
				HashStrength: 0,
			},
			b: MechInfo{
				Name:         "MECH2",
				MaxSSF:       0,
				Features:     FeatChannelBindings,
				SecFlags:     0,
				HashStrength: 0,
			},
			want:        1,
			description: "security flags should take priority over features",
		},
		{
			name: "features priority over MaxSSF",
			a: MechInfo{
				Name:         "MECH1",
				MaxSSF:       0,
				Features:     FeatChannelBindings,
				SecFlags:     0,
				HashStrength: 0,
			},
			b: MechInfo{
				Name:         "MECH2",
				MaxSSF:       1000,
				Features:     0,
				SecFlags:     0,
				HashStrength: 0,
			},
			want:        1,
			description: "features should take priority over MaxSSF",
		},
		{
			name: "MaxSSF priority over HashStrength",
			a: MechInfo{
				Name:         "MECH1",
				MaxSSF:       100,
				Features:     0,
				SecFlags:     0,
				HashStrength: 0,
			},
			b: MechInfo{
				Name:         "MECH2",
				MaxSSF:       0,
				Features:     0,
				SecFlags:     0,
				HashStrength: 1000,
			},
			want:        1,
			description: "MaxSSF should take priority over HashStrength",
		},
		{
			name: "multiple security flags - higher priority wins",
			a: MechInfo{
				Name:         "MECH1",
				MaxSSF:       0,
				Features:     0,
				SecFlags:     SecNoPlainText,
				HashStrength: 0,
			},
			b: MechInfo{
				Name:         "MECH2",
				MaxSSF:       0,
				Features:     0,
				SecFlags:     SecForwardSecrecy,
				HashStrength: 0,
			},
			want:        1,
			description: "when both have different security flags, prefer the one with higher priority flag",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mechCompare(tt.a, tt.b)
			assert.Equal(t, tt.want, got, tt.description)
			// Test reverse comparison
			if tt.want != 0 {
				assert.Equal(t, -tt.want, mechCompare(tt.b, tt.a), "reverse comparison should return opposite result")
			}
		})
	}
}
