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

	// output token is the requsted authz identity or an empty string
	outToken = []byte(m.config.ExternalProperties.AuthID)
	m.isEstablished = true
	return outToken, nil
}
