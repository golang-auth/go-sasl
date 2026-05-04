package sasl

import (
	"errors"
)

type externalMech struct {
	config        MechConfig
	isEstablished bool
}

func init() {
	RegisterMech(MechInfo{
		Name:        "EXTERNAL",
		Provider:    "go-sasl",
		MaxSSF:      0,
		Features:    FeatWantClientFirst | FeatAllowsProxy,
		SecFlags:    SecNoPlainText | SecNoAnonymous | SecNoDictionary,
		Constructor: newExternalMech,
	})
}

var cbData = map[PromptDataType]any{
	PromptDataTypeAuthzID: AuthDataSimple{Prompt: "Enter authorization ID"},
}

func newExternalMech(config MechConfig) (Mech, error) {
	return &externalMech{
		config: config,
	}, nil
}

func (m *externalMech) Name() string {
	return "EXTERNAL"
}

func (m *externalMech) Dispose() {
}

func (m *externalMech) IsEstablished() bool {
	return m.isEstablished
}

// rfc2222 section 7.1 : Send the required authz identity or an empty string to use
// the authenticated identity
func (m *externalMech) Step(inToken []byte) (outToken []byte, prompts []Prompt, err error) {
	if len(inToken) > 0 {
		return nil, nil, errors.New("input token not expected for EXTERNAL mech")
	}

	if m.config.SecProps&SecNoAnonymous > 0 && m.config.ExternalProperties.AuthID == "anonymous" {
		return nil, nil, errors.New("anonymous authentication is not allowed")
	}

	outToken = []byte("")

	// the authz is optional.  If we have a callback to find it then use it.
	if m.config.Callbacks.AuthzIDCallback != nil {
		authzID, err := m.config.Callbacks.AuthzIDCallback(cbData[PromptDataTypeAuthzID].(AuthDataSimple))
		switch err {
		default:
			return nil, nil, err
		case nil:
			if authzID != "" {
				outToken = []byte(authzID)
			}
		case ErrInteractionRequired:
			prompt, err := NewPrompt(cbData[PromptDataTypeAuthzID])
			if err != nil {
				return nil, nil, err
			}
			prompts = append(prompts, *prompt)
		}
	}

	if len(prompts) > 0 {
		err = ErrInteractionRequired
	}

	return
}
