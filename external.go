package sasl

import "errors"

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
func (m *externalMech) Step(inToken []byte) (outToken []byte, err error) {
	if len(inToken) > 0 {
		return nil, errors.New("input token not expected for EXTERNAL mech")
	}

	if m.config.SecProps&SecNoAnonymous > 0 && m.config.ExternalProperties.AuthID == "anonymous" {
		return nil, errors.New("anonymous authentication is not allowed")
	}

	interact := false
	outToken = []byte("")

	// the authz is optional.  If we have a callback to find it then use it.
	if m.config.Callbacks.AuthzIDCallback != nil {
		authzID, err := m.config.Callbacks.AuthzIDCallback(AuthDataSimple{Prompt: "Enter authorization ID"})
		switch err {
		default:
			return nil, err
		case nil:
			if authzID != "" {
				outToken = []byte(authzID)
			}
		case ErrInteractionRequired:
			interact = true
		}
	}

	if interact {
		err = ErrInteractionRequired
	}

	return
}
