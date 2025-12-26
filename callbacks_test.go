// SPDX-License-Identifier: Apache-2.0

package sasl

import (
	"testing"
)

func TestPrompt_GetAuthDataSimple(t *testing.T) {
	type testCase struct {
		name        string
		dataType    PromptDataType
		prompt      any
		wantPrompt  string
		wantErr     bool
		wantErrStr  string
		shouldBeNil bool
	}
	cases := []testCase{
		{
			name:        "valid AuthnID",
			dataType:    PromptDataTypeAuthnID,
			prompt:      AuthDataSimple{Prompt: "Enter username"},
			wantPrompt:  "Enter username",
			wantErr:     false,
			shouldBeNil: false,
		},
		{
			name:        "valid AuthzID",
			dataType:    PromptDataTypeAuthzID,
			prompt:      AuthDataSimple{Prompt: "Enter authorization ID"},
			wantPrompt:  "Enter authorization ID",
			wantErr:     false,
			shouldBeNil: false,
		},
		{
			name:        "invalid DataType",
			dataType:    PromptDataTypePassword,
			prompt:      AuthDataSimple{Prompt: "Enter password"},
			wantErr:     true,
			wantErrStr:  "not a prompt for authn or authz ID",
			shouldBeNil: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := NewAssert(t)
			prompt := Prompt{
				DataType: tc.dataType,
				prompt:   tc.prompt,
			}
			authData, err := prompt.GetAuthDataSimple()
			if tc.wantErr {
				a.Error(err)
				if tc.wantErrStr != "" {
					a.Contains(err.Error(), tc.wantErrStr)
				}
				if tc.shouldBeNil {
					a.Nil(authData)
				}
			} else {
				a.NoError(err)
				a.NotNil(authData)
				a.Equal(tc.wantPrompt, authData.Prompt)
			}
		})
	}
}

func TestPrompt_GetAuthDataPassword(t *testing.T) {
	type testCase struct {
		name        string
		dataType    PromptDataType
		prompt      any
		wantPrompt  string
		wantErr     bool
		wantErrStr  string
		shouldBeNil bool
	}
	cases := []testCase{
		{
			name:        "valid Password",
			dataType:    PromptDataTypePassword,
			prompt:      AuthDataPassword{Prompt: "Enter password"},
			wantPrompt:  "Enter password",
			wantErr:     false,
			shouldBeNil: false,
		},
		{
			name:        "invalid DataType - AuthnID",
			dataType:    PromptDataTypeAuthnID,
			prompt:      AuthDataPassword{Prompt: "Enter password"},
			wantErr:     true,
			wantErrStr:  "not a prompt for password",
			shouldBeNil: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := NewAssert(t)
			prompt := Prompt{
				DataType: tc.dataType,
				prompt:   tc.prompt,
			}
			authData, err := prompt.GetAuthDataPassword()
			if tc.wantErr {
				a.Error(err)
				if tc.wantErrStr != "" {
					a.Contains(err.Error(), tc.wantErrStr)
				}
				if tc.shouldBeNil {
					a.Nil(authData)
				}
			} else {
				a.NoError(err)
				a.NotNil(authData)
				a.Equal(tc.wantPrompt, authData.Prompt)
			}
		})
	}
}

func TestPrompt_GetAuthDataChallenge(t *testing.T) {
	type testCase struct {
		name           string
		dataType       PromptDataType
		prompt         any
		wantPrompt     string
		wantChallenge  string
		wantDefault    string
		wantEchoPrompt EchoPromptType
		wantErr        bool
		wantErrStr     string
		shouldBeNil    bool
	}
	cases := []testCase{
		{
			name:           "valid Challenge with EchoPrompt",
			dataType:       PromptDataTypeChallenge,
			prompt:         AuthDataChallenge{Prompt: "Enter response", Challenge: "challenge123", DefaultResult: "default", EchoPrompt: EchoPrompt},
			wantPrompt:     "Enter response",
			wantChallenge:  "challenge123",
			wantDefault:    "default",
			wantEchoPrompt: EchoPrompt,
			wantErr:        false,
			shouldBeNil:    false,
		},
		{
			name:           "valid Challenge with NoEchoPrompt",
			dataType:       PromptDataTypeChallenge,
			prompt:         AuthDataChallenge{Prompt: "Enter secret", Challenge: "challenge456", DefaultResult: "", EchoPrompt: NoEchoPrompt},
			wantPrompt:     "Enter secret",
			wantChallenge:  "challenge456",
			wantDefault:    "",
			wantEchoPrompt: NoEchoPrompt,
			wantErr:        false,
			shouldBeNil:    false,
		},
		{
			name:        "invalid DataType - Password",
			dataType:    PromptDataTypePassword,
			prompt:      AuthDataChallenge{Prompt: "Enter response", Challenge: "challenge123"},
			wantErr:     true,
			wantErrStr:  "not a prompt for challenge",
			shouldBeNil: true,
		},
		{
			name:        "invalid prompt type",
			dataType:    PromptDataTypeChallenge,
			prompt:      "not an AuthDataChallenge",
			wantErr:     true,
			wantErrStr:  "prompt is not a challenge prompt",
			shouldBeNil: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := NewAssert(t)
			prompt := Prompt{
				DataType: tc.dataType,
				prompt:   tc.prompt,
			}
			authData, err := prompt.GetAuthDataChallenge()
			if tc.wantErr {
				a.Error(err)
				if tc.wantErrStr != "" {
					a.Contains(err.Error(), tc.wantErrStr)
				}
				if tc.shouldBeNil {
					a.Nil(authData)
				}
			} else {
				a.NoError(err)
				a.NotNil(authData)
				a.Equal(tc.wantPrompt, authData.Prompt)
				a.Equal(tc.wantChallenge, authData.Challenge)
				a.Equal(tc.wantDefault, authData.DefaultResult)
				a.Equal(tc.wantEchoPrompt, authData.EchoPrompt)
			}
		})
	}
}

func TestPrompt_GetAuthDataRealm(t *testing.T) {
	type testCase struct {
		name        string
		dataType    PromptDataType
		prompt      any
		wantRealms  []string
		wantErr     bool
		wantErrStr  string
		shouldBeNil bool
	}
	cases := []testCase{
		{
			name:        "valid Realm",
			dataType:    PromptDataTypeRealm,
			prompt:      AuthDataRealm{AvailableRealms: []string{"realm1", "realm2", "realm3"}},
			wantRealms:  []string{"realm1", "realm2", "realm3"},
			wantErr:     false,
			shouldBeNil: false,
		},
		{
			name:        "valid Realm with empty list",
			dataType:    PromptDataTypeRealm,
			prompt:      AuthDataRealm{AvailableRealms: []string{}},
			wantRealms:  []string{},
			wantErr:     false,
			shouldBeNil: false,
		},
		{
			name:        "invalid DataType - AuthnID",
			dataType:    PromptDataTypeAuthnID,
			prompt:      AuthDataRealm{AvailableRealms: []string{"realm1"}},
			wantErr:     true,
			wantErrStr:  "not a prompt for realm",
			shouldBeNil: true,
		},
		{
			name:        "invalid prompt type",
			dataType:    PromptDataTypeRealm,
			prompt:      "not an AuthDataRealm",
			wantErr:     true,
			wantErrStr:  "prompt is not a realm prompt",
			shouldBeNil: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := NewAssert(t)
			prompt := Prompt{
				DataType: tc.dataType,
				prompt:   tc.prompt,
			}
			authData, err := prompt.GetAuthDataRealm()
			if tc.wantErr {
				a.Error(err)
				if tc.wantErrStr != "" {
					a.Contains(err.Error(), tc.wantErrStr)
				}
				if tc.shouldBeNil {
					a.Nil(authData)
				}
			} else {
				a.NoError(err)
				a.NotNil(authData)
				a.Equal(tc.wantRealms, authData.AvailableRealms)
			}
		})
	}
}

func TestPrompt_SetResult(t *testing.T) {
	t.Run("set result", func(t *testing.T) {
		a := NewAssert(t)
		prompt := Prompt{
			DataType: PromptDataTypeAuthnID,
			prompt:   AuthDataSimple{Prompt: "Enter username"},
		}

		err := prompt.SetResult("test-result")
		a.NoError(err)
		a.Equal("test-result", prompt.result)
	})
}

func TestMkStaticSimpleCallback(t *testing.T) {
	type testCase struct {
		name       string
		staticVal  string
		wantResult string
	}
	cases := []testCase{
		{
			name:       "returns static string",
			staticVal:  "test-username",
			wantResult: "test-username",
		},
		{
			name:       "returns different static string",
			staticVal:  "another-user",
			wantResult: "another-user",
		},
		{
			name:       "ignores authData prompt",
			staticVal:  "static-value",
			wantResult: "static-value",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := NewAssert(t)
			callback := mkStaticSimpleCallback(tc.staticVal)
			result, err := callback(AuthDataSimple{Prompt: "Enter username"})

			a.NoError(err)
			a.Equal(tc.wantResult, result)
		})
	}
}

func TestMkInteractionSimpleCallback(t *testing.T) {
	t.Run("returns ErrInteractionRequired", func(t *testing.T) {
		a := NewAssert(t)
		callback := mkInteractionSimpleCallback()
		result, err := callback(AuthDataSimple{Prompt: "Enter username"})

		a.Error(err)
		a.ErrorIs(err, ErrInteractionRequired)
		a.Empty(result)
	})
}

func TestMkStaticPasswordCallback(t *testing.T) {
	type testCase struct {
		name       string
		staticVal  string
		wantResult string
	}
	cases := []testCase{
		{
			name:       "returns static string",
			staticVal:  "test-password",
			wantResult: "test-password",
		},
		{
			name:       "returns different static string",
			staticVal:  "secret123",
			wantResult: "secret123",
		},
		{
			name:       "ignores authData prompt",
			staticVal:  "static-password",
			wantResult: "static-password",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := NewAssert(t)
			callback := mkStaticPasswordCallback(tc.staticVal)
			result, err := callback(AuthDataPassword{Prompt: "Enter password"})

			a.NoError(err)
			a.Equal(tc.wantResult, result)
		})
	}
}

func TestMkInteractionPasswordCallback(t *testing.T) {
	t.Run("returns ErrInteractionRequired", func(t *testing.T) {
		a := NewAssert(t)
		callback := mkInteractionPasswordCallback()
		result, err := callback(AuthDataPassword{Prompt: "Enter password"})

		a.Error(err)
		a.ErrorIs(err, ErrInteractionRequired)
		a.Empty(result)
	})
}

func TestMkStaticChallengeCallback(t *testing.T) {
	type testCase struct {
		name       string
		staticVal  string
		wantResult string
	}
	cases := []testCase{
		{
			name:       "returns static string",
			staticVal:  "test-response",
			wantResult: "test-response",
		},
		{
			name:       "returns different static string",
			staticVal:  "challenge-response",
			wantResult: "challenge-response",
		},
		{
			name:       "ignores authData fields",
			staticVal:  "static-response",
			wantResult: "static-response",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := NewAssert(t)
			callback := mkStaticChallengeCallback(tc.staticVal)
			result, err := callback(AuthDataChallenge{Prompt: "Enter response", Challenge: "challenge123", DefaultResult: "default", EchoPrompt: EchoPrompt})

			a.NoError(err)
			a.Equal(tc.wantResult, result)
		})
	}
}

func TestMkInteractionChallengeCallback(t *testing.T) {
	t.Run("returns ErrInteractionRequired", func(t *testing.T) {
		a := NewAssert(t)
		callback := mkInteractionChallengeCallback()
		result, err := callback(AuthDataChallenge{
			Prompt:    "Enter response",
			Challenge: "challenge123",
		})

		a.Error(err)
		a.ErrorIs(err, ErrInteractionRequired)
		a.Empty(result)
	})
}

func TestMkStaticRealmCallback(t *testing.T) {
	type testCase struct {
		name       string
		staticVal  string
		wantResult string
	}
	cases := []testCase{
		{
			name:       "returns static string",
			staticVal:  "test-realm",
			wantResult: "test-realm",
		},
		{
			name:       "returns different static string",
			staticVal:  "selected-realm",
			wantResult: "selected-realm",
		},
		{
			name:       "ignores authData available realms",
			staticVal:  "static-realm",
			wantResult: "static-realm",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := NewAssert(t)
			callback := mkStaticRealmCallback(tc.staticVal)
			result, err := callback(AuthDataRealm{AvailableRealms: []string{"realm1", "realm2"}})

			a.NoError(err)
			a.Equal(tc.wantResult, result)
		})
	}
}

func TestMkInteractionRealmCallback(t *testing.T) {
	t.Run("returns ErrInteractionRequired", func(t *testing.T) {
		a := NewAssert(t)
		callback := mkInteractionRealmCallback()
		result, err := callback(AuthDataRealm{
			AvailableRealms: []string{"realm1", "realm2"},
		})

		a.Error(err)
		a.ErrorIs(err, ErrInteractionRequired)
		a.Empty(result)
	})
}
