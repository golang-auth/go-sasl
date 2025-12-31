// SPDX-License-Identifier: Apache-2.0

package sasl

import (
	"errors"
	"fmt"
)

var ErrInteractionRequired = errors.New("interaction required")

type PromptDataType int

const (
	PromptDataTypeAuthnID PromptDataType = iota
	PromptDataTypeAuthzID
	PromptDataTypePassword
	PromptDataTypeChallenge
	PromptDataTypeRealm
)

type EchoPromptType int

const (
	EchoPrompt EchoPromptType = iota
	NoEchoPrompt
	EchoPromptPassword
)

type AuthDataSimple struct {
	Prompt string
}

type AuthDataPassword struct {
	Prompt string
}

type AuthDataChallenge struct {
	Prompt        string
	Challenge     string
	DefaultResult string
	EchoPrompt    EchoPromptType
}

type AuthDataRealm struct {
	AvailableRealms []string
}

type SaslSimpleCallback func(authData AuthDataSimple) (string, error)
type SaslPasswordCallback func(authData AuthDataPassword) (string, error)
type SaslChallengeCallback func(authData AuthDataChallenge) (string, error)
type SaslRealmCallback func(authData AuthDataRealm) (string, error)

type Interaction interface {
	Interact([]Prompt) error
}

type Prompt struct {
	DataType PromptDataType
	prompt   any
	result   string
}

func (n Prompt) GetAuthDataSimple() (*AuthDataSimple, error) {
	if n.DataType != PromptDataTypeAuthnID && n.DataType != PromptDataTypeAuthzID {
		return nil, fmt.Errorf("not a prompt for authn or authz ID")
	}

	if p, ok := n.prompt.(AuthDataSimple); ok {
		return &p, nil
	}

	return nil, fmt.Errorf("prompt is not a simple prompt")
}

func (n Prompt) GetAuthDataPassword() (*AuthDataPassword, error) {
	if n.DataType != PromptDataTypePassword {
		return nil, fmt.Errorf("not a prompt for password")
	}

	if p, ok := n.prompt.(AuthDataPassword); ok {
		return &p, nil
	}

	return nil, fmt.Errorf("prompt is not a password prompt")
}

func (n Prompt) GetAuthDataChallenge() (*AuthDataChallenge, error) {
	if n.DataType != PromptDataTypeChallenge {
		return nil, fmt.Errorf("not a prompt for challenge")
	}

	if p, ok := n.prompt.(AuthDataChallenge); ok {
		return &p, nil
	}

	return nil, fmt.Errorf("prompt is not a challenge prompt")
}

func (n Prompt) GetAuthDataRealm() (*AuthDataRealm, error) {
	if n.DataType != PromptDataTypeRealm {
		return nil, fmt.Errorf("not a prompt for realm")
	}

	if p, ok := n.prompt.(AuthDataRealm); ok {
		return &p, nil
	}

	return nil, fmt.Errorf("prompt is not a realm prompt")
}

func (n *Prompt) SetResult(result string) error {
	n.result = result
	return nil
}

func mkStaticSimpleCallback(s string) SaslSimpleCallback {
	return func(authData AuthDataSimple) (string, error) {
		return s, nil
	}
}
func mkInteractionSimpleCallback() SaslSimpleCallback {
	return func(authData AuthDataSimple) (string, error) {
		return "", ErrInteractionRequired
	}
}
func mkStaticPasswordCallback(s string) SaslPasswordCallback {
	return func(authData AuthDataPassword) (string, error) {
		return s, nil
	}
}
func mkInteractionPasswordCallback() SaslPasswordCallback {
	return func(authData AuthDataPassword) (string, error) {
		return "", ErrInteractionRequired
	}
}
func mkStaticChallengeCallback(s string) SaslChallengeCallback {
	return func(authData AuthDataChallenge) (string, error) {
		return s, nil
	}
}
func mkInteractionChallengeCallback() SaslChallengeCallback {
	return func(authData AuthDataChallenge) (string, error) {
		return "", ErrInteractionRequired
	}
}
func mkStaticRealmCallback(s string) SaslRealmCallback {
	return func(authData AuthDataRealm) (string, error) {
		return s, nil
	}
}
func mkInteractionRealmCallback() SaslRealmCallback {
	return func(authData AuthDataRealm) (string, error) {
		return "", ErrInteractionRequired
	}
}
