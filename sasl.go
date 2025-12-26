// SPDX-License-Identifier: Apache-2.0

package sasl

import (
	"fmt"
	"os/user"
	"strings"
)

func (c *SaslClient) applyPrompt(prompt Prompt) error {
	if prompt.result == "" {
		return nil
	}

	switch prompt.DataType {
	default:
		return fmt.Errorf("unknown prompt type: %d", prompt.DataType)
	case PromptDataTypeAuthnID:
		c.authnIDCallback = mkStaticSimpleCallback(prompt.result)
	case PromptDataTypeAuthzID:
		c.authzIDCallback = mkStaticSimpleCallback(prompt.result)
	case PromptDataTypePassword:
		c.passwordCallback = mkStaticPasswordCallback(prompt.result)
	case PromptDataTypeChallenge:
		c.challengeCallback = mkStaticChallengeCallback(prompt.result)
	case PromptDataTypeRealm:
		c.realmCallback = mkStaticRealmCallback(prompt.result)
	}

	return nil
}

func (c *SaslClient) ApplyPrompts(prompts []Prompt) error {
	for _, prompt := range prompts {
		if err := c.applyPrompt(prompt); err != nil {
			return err
		}
	}
	return nil
}

func systemAuthnID(_ AuthDataSimple) (string, error) {
	user, err := user.Current()
	if err != nil {
		return "", err
	}
	return user.Username, nil
}

type UserInfo struct {
	AuthnID string
	AuthzID string
}

type SaslClient struct {
	saslCommon
	mech Mech

	// mech is expected to fill this in
	UserInfo UserInfo

	authnIDCallback   SaslSimpleCallback
	authzIDCallback   SaslSimpleCallback
	passwordCallback  SaslPasswordCallback
	challengeCallback SaslChallengeCallback
	realmCallback     SaslRealmCallback
}

type SaslClientOption func(*SaslClient) error

func WithAuthnIDFunc(f SaslSimpleCallback) SaslClientOption {
	return func(c *SaslClient) error {
		c.authnIDCallback = f
		return nil
	}
}

func WithAuthzIDFunc(f SaslSimpleCallback) SaslClientOption {
	return func(c *SaslClient) error {
		c.authzIDCallback = f
		return nil
	}
}

func WithPasswordFunc(f SaslPasswordCallback) SaslClientOption {
	return func(c *SaslClient) error {
		c.passwordCallback = f
		return nil
	}
}

func WithChallengeFunc(f SaslChallengeCallback) SaslClientOption {
	return func(c *SaslClient) error {
		c.challengeCallback = f
		return nil
	}
}

func WithRealmFunc(f SaslRealmCallback) SaslClientOption {
	return func(c *SaslClient) error {
		c.realmCallback = f
		return nil
	}
}

func WithAuthnID(authnID string) SaslClientOption {
	return WithAuthnIDFunc(mkStaticSimpleCallback(authnID))
}

func WithAuthzID(authzID string) SaslClientOption {
	return WithAuthzIDFunc(mkStaticSimpleCallback(authzID))
}

func WithPassword(password string) SaslClientOption {
	return WithPasswordFunc(mkStaticPasswordCallback(password))
}

func WithChallenge(challenge string) SaslClientOption {
	return WithChallengeFunc(mkStaticChallengeCallback(challenge))
}

func WithRealm(realm string) SaslClientOption {
	return WithRealmFunc(mkStaticRealmCallback(realm))
}

func NewSaslClient(service string, opts ...SaslOption) (client SaslClient, err error) {
	client = SaslClient{
		saslCommon: saslCommon{
			service: service,
			securityProperties: securityProperties{
				MaxSSF:     ^SSF(0),
				MaxBufSize: 65536,
			},
		},
		authnIDCallback: systemAuthnID,
	}

	for _, o := range opts {
		if err = o(&client.saslCommon); err != nil {
			return
		}
	}

	if len(client.enabledMechs) > 0 {
		client.enabledMechs = trimMechsToRegistered(client.enabledMechs)
	} else {
		// default to all registered mechs
		client.enabledMechs = RegisteredMechs()
	}

	if len(client.enabledMechs) == 0 {
		err = ErrNoMech
	} else {
		client.loggers.Debugf("enabled mechs: [%s]", strings.Join(client.enabledMechs, ", "))
	}

	return client, err
}

func (c SaslClient) IsEstablished() bool {
	if c.mech != nil {
		return c.mech.IsEstablished()
	} else {
		return false
	}
}

// Port of Cyrus SASL sasl_client_start
func (c *SaslClient) Start(serverMechs []string) (outToken []byte, err error) {
	c.mech = nil

	// how much 'extra ssf' do we need if we take the external layer into account?
	var minSSF SSF
	if c.securityProperties.MinSSF < c.externalProperties.SSF {
		minSSF = 0
	} else {
		minSSF = c.securityProperties.MinSSF - c.externalProperties.SSF
	}
	_ = minSSF // TODO: use minSSF when the rest of the code is uncommented

	// Sort the server mechs, preferring those supporting channel bindings (-PLUS)
	// if the client has channel binding data
	orderedMechs, serverCanCb, err := c.orderMechs(serverMechs)
	if err != nil {
		return nil, err
	}

	cbDisposition, err := c.channelBindingDisposition(len(orderedMechs) > 1, serverCanCb)
	if err != nil {
		return nil, err
	}

	// find common mechs between the client and server
	matchingMechs := findMatchingMechs(c.enabledMechs, orderedMechs)

	// find the best match
	bestMech := ""
	for _, mech := range matchingMechs {
		isPlus := isMechPlus(mech)

		mechInfo, err := GetMechInfo(mech)
		if err != nil {
			c.loggers.Warnf("mech %s not registered", mech)
			continue
		}

		// discard if the mech does not meet the min SSF requirement
		if minSSF > mechInfo.MaxSSF {
			c.loggers.Debugf("mech %s max SSF (%d) too low (want %d)", mech, mechInfo.MaxSSF, minSSF)
			continue
		}

		wantSecProps := c.securityProperties.SecFlags

		if (c.externalProperties.SSF > minSSF) && (c.externalProperties.SSF > 1) {
			c.loggers.Debugf("mech %s (max SSF %d) upgraded to non-plaintext (external SSF: %d)", mech, mechInfo.MaxSSF, c.externalProperties.SSF)
			wantSecProps &^= SecNoPlainText
		}

		// does the mech meet the client's security requirements?
		if ((wantSecProps ^ mechInfo.SecFlags) & wantSecProps) != 0 {
			c.loggers.Debugf("mech %s does not meet security requirements", mech)
			continue
		}

		// Can we meet the mech's features requirements?
		if cbDisposition == channelBindingDispUsed && (mechInfo.Features&FeatChannelBindings == 0) {
			c.loggers.Debugf("mech %s does not support channel bindings", mech)
			continue
		}

		if (mechInfo.Features&FeatNeedServerFQDN != 0) && c.serverFQDN == "" {
			c.loggers.Debugf("mech %s requires server FQDN", mech)
			continue
		}

		// Can the mech meet the client's feature requirements?
		if c.needProxy && (mechInfo.Features&FeatAllowsProxy == 0) {
			c.loggers.Debugf("mech %s does not support proxying", mech)
			continue
		}

		if c.needHTTP && (mechInfo.Features&FeatSupportsHTTP == 0) {
			c.loggers.Debugf("mech %s does not support HTTP", mech)
			continue
		}

		if c.channelBinding != nil && isPlus {
			cbDisposition = channelBindingDispUsed
		}

		// this looks like a good fit..
		bestMech = mech
		break
	}

	if bestMech == "" {
		c.loggers.Debugf("no worthy mechs found")
		return nil, ErrNoMech
	}

	c.loggers.Debugf("Chose mech '%s'", bestMech)

	// Create an instance of the chosen mech
	cfg := MechConfig{
		Logger:             c.loggers,
		Service:            c.service,
		ServerFQDN:         c.serverFQDN,
		ClientFQDN:         c.clientFQDN,
		ExternalProperties: c.externalProperties,
		SecProps:           c.securityProperties.SecFlags,
		CBDisposition:      cbDisposition,
	}

	c.mech, err = newMech(bestMech, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate mech '%s': %w", bestMech, err)
	}

	// Perform a step unless the mech needs the server to go first
	mechInfo, err := GetMechInfo(bestMech)
	if err != nil {
		return nil, fmt.Errorf("failed to get mech info for '%s': %w", bestMech, err)
	}

	if mechInfo.Features&FeatServerFirst != 0 {
		return nil, nil
	}

	// otherwise execute the first step
	return c.mech.Step(nil)
}

func (c *SaslClient) Step(inToken []byte) (outToken []byte, err error) {
	if c.mech == nil {
		return nil, ErrNotStarted
	}

	if c.IsEstablished() {
		return nil, ErrAlreadyEstablished
	}

	outToken, err = c.mech.Step(inToken)
	if err != nil {
		return nil, err
	}

	if c.mech.IsEstablished() {
		// The client is done but if the mech wants the server to go last and
		// the protocol does not, then we need to return no data
		if outToken == nil && !c.successData {
			outToken = []byte{}
		}

		if c.UserInfo.AuthnID == "" || c.UserInfo.AuthzID == "" {
			c.loggers.Errorf("mech %s did not canonicalize auth and authz user", c.mech.Name())
			return nil, ErrBadProtocol
		}
	}

	return outToken, nil
}

// func (c SaslClient) ContextParams() (params common.ContextParams, err error) {
// 	if c.mech == nil {
// 		err = common.ErrNotStarted
// 		return
// 	}

// 	if !c.IsEstablished() {
// 		err = common.ErrNotEstablished
// 		return
// 	}

// 	return c.mech.ContextParams(), nil
// }

// func (c *SaslClient) Encode(input []byte) (outToken []byte, err error) {
// 	if c.mech == nil {
// 		return nil, common.ErrNotStarted
// 	}

// 	if !c.IsEstablished() {
// 		return nil, common.ErrNotEstablished
// 	}

// 	// output is the same as input if there is no negotiated security layer
// 	if c.mech.ContextParams().SSF == 0 {
// 		outToken = input
// 	} else {
// 		outToken, err = c.mech.Encode(input)
// 	}

// 	return
// }

// func (c *SaslClient) Decode(inputToken []byte) (output []byte, err error) {
// 	if c.mech == nil {
// 		return nil, common.ErrNotStarted
// 	}

// 	if !c.IsEstablished() {
// 		return nil, common.ErrNotEstablished
// 	}

// 	// output is the same as input if there is no negotiated security layer
// 	if c.mech.ContextParams().SSF == 0 {
// 		output = inputToken
// 	} else {
// 		output, err = c.mech.Decode(inputToken)
// 	}

// 	return
// }

// isMechPlus checks if a mechanism name ends with "-PLUS" (case-insensitive).
// This is equivalent to Cyrus SASL's _mech_plus_p function.
func isMechPlus(mech string) bool {
	mechUpper := strings.ToUpper(mech)
	return len(mech) > 5 && strings.HasSuffix(mechUpper, "-PLUS")
}

// orderMechs implements the Cyrus SASL _sasl_client_order_mechs algorithm.
// It orders mechanisms by placing those that support channel binding (ending with "-PLUS")
// first if the client has channel binding data, followed by those without "-PLUS".
// Returns the ordered list and an error if no mechanisms are found.
func (c *SaslClient) orderMechs(mechs []string) (orderedMechs []string, serverCanCb bool, err error) {
	if len(mechs) == 0 {
		return nil, false, ErrNoMech
	}

	hasCbData := c.channelBinding != nil
	orderedMechs = make([]string, 0, len(mechs))

	// First pass: if has_cb_data is true, collect mechanisms ending with "-PLUS"
	// This matches the C code's do-while loop: first iteration collects PLUS mechs if has_cb_data is true
	if hasCbData {
		for _, mech := range mechs {
			if isMechPlus(mech) {
				orderedMechs = append(orderedMechs, mech)
				serverCanCb = true
			}
		}
	}

	// Second pass: collect mechanisms not ending with "-PLUS"
	// If has_cb_data is false, this is the only pass (collects non-PLUS mechs)
	// If has_cb_data is true, this collects non-PLUS mechs after PLUS mechs
	for _, mech := range mechs {
		if !isMechPlus(mech) {
			orderedMechs = append(orderedMechs, mech)
		}
	}

	if len(orderedMechs) == 0 {
		return nil, false, ErrNoMech
	}

	return
}

// port of Cyrus SASL _sasl_cbinding_disp
func (c *SaslClient) channelBindingDisposition(doingNegotiation bool, serverCanCb bool) (channelBindingDisposition, error) {
	disp := channelBindingDispNone

	if c.channelBinding == nil {
		c.loggers.Debugf("no client-side channel binding requested")
		return channelBindingDispNone, nil
	}

	if doingNegotiation {
		if !serverCanCb && c.channelBinding.Critical {
			c.loggers.Debugf("no server-side channel binding supported and client-side channel binding is critical")
			return channelBindingDispNone, ErrNoMech
		} else {
			disp = channelBindingDispWant
		}
	} else if c.channelBinding.Critical {
		disp = channelBindingDispUsed
	}

	return disp, nil
}

// find all the server mechs that are compatible with the client mechs
func findMatchingMechs(clientMechs []string, serverMechs []string) []string {
	outMechs := make([]string, 0, len(serverMechs))
	for _, clientMech := range clientMechs {
		for _, serverMech := range serverMechs {
			_, equal := isEqualMech(serverMech, clientMech)
			if equal {
				outMechs = append(outMechs, serverMech)
				break
			}
		}
	}

	return outMechs
}

func isEqualMech(reqMech, plugMech string) (plus bool, equal bool) {
	reqMechUpper := strings.ToUpper(reqMech)

	if strings.HasSuffix(reqMechUpper, "-PLUS") {
		plus = true
		reqMechUpper = reqMechUpper[:len(reqMechUpper)-5]
	}

	return plus, strings.EqualFold(reqMechUpper, plugMech)
}
