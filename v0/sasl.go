// Copyright 2021 Jake Scott. All rights reserved.
// Use of this source code is governed by the Apache License
// version 2.0 that can be found in the LICENSE file.
package sasl

import (
	"errors"
	"log"
	"regexp"
	"strings"

	"github.com/golang-auth/go-sasl/common"
	"github.com/golang-auth/go-sasl/pkg/loggable"
	"github.com/golang-auth/go-sasl/registry"

	_ "github.com/golang-auth/go-sasl/gssapi"
)

type SaslClientOption func(*SaslClient) error

type SaslClient struct {
	loggable.Loggable

	mech common.Mech

	service         string
	mechList        []string
	serverFQDN      string
	minSSF          uint
	maxSSF          uint
	maxBufSize      uint // max the client can receive
	secProps        common.SecurityFlag
	extProps        externalProperties
	needHTTP        bool
	channelBindings *common.ChannelBinding
	extraProps      map[string]string
}

type externalProperties struct {
	ssf uint
	//	authID string
}

type SaslPrompt interface {
}

type channelBindingDisposition int

const (
	channelBindingDispNone channelBindingDisposition = iota
	channelBindingDispWant
	channelBindingDispMust
)

func NewSaslClient(service string, opts ...SaslClientOption) (client SaslClient, err error) {
	client = SaslClient{
		service:    service,
		secProps:   common.SecNoAnonymous | common.SecNoPlainText,
		maxBufSize: 65536,
		maxSSF:     ^uint(0),
		extraProps: make(map[string]string),
	}

	for _, o := range opts {
		if err = o(&client); err != nil {
			return
		}
	}

	if len(client.mechList) > 0 {
		// trim the mech list to only those that are registered
		var newMechList []string

		for _, name := range client.mechList {
			if registry.IsRegistered(name) {
				newMechList = append(newMechList, name)
			}
		}

		client.mechList = newMechList
		client.Debugf("using specified registered mechs: [%s]", strings.Join(client.mechList, ", "))
	} else {
		// default to all registered mechs
		client.mechList = registry.Mechs()
		client.Debugf("using all registered mechs: [%s]", strings.Join(client.mechList, ", "))
	}

	if len(client.mechList) == 0 {
		err = common.ErrNoMech
	}

	return client, err
}

var validHostnameRegex = regexp.MustCompile(`^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$`)

func WithServerFQDN(fqdn string) SaslClientOption {
	return func(c *SaslClient) error {
		if fqdn != "" {
			if !validHostnameRegex.Match([]byte(fqdn)) {
				return errors.New("bad hostname")
			}

			c.serverFQDN = fqdn
		}

		return nil
	}
}

func WithMechList(mechs []string) SaslClientOption {
	return func(c *SaslClient) error {
		if len(mechs) > 0 {
			c.mechList = mechs
		}

		return nil
	}
}

func WithMinSSF(ssf uint) SaslClientOption {
	return func(c *SaslClient) error {
		c.minSSF = ssf
		return nil
	}
}

func WithMaxSSF(ssf uint) SaslClientOption {
	return func(c *SaslClient) error {
		c.maxSSF = ssf
		return nil
	}
}

func WithNeedHTTP() SaslClientOption {
	return func(c *SaslClient) error {
		c.needHTTP = true
		return nil
	}
}

func WithChannelBindings(cb common.ChannelBinding) SaslClientOption {
	return func(c *SaslClient) error {
		c.channelBindings = &cb
		return nil
	}
}

func WithMaxBufSize(size uint) SaslClientOption {
	return func(c *SaslClient) error {
		c.maxBufSize = size
		return nil
	}
}

func WithSecurityProps(props common.SecurityFlag) SaslClientOption {
	return func(c *SaslClient) error {
		c.secProps = props & (common.SecNoPlainText | common.SecNoActive | common.SecNoDictionary | common.SecForwardSecrecy | common.SecNoAnonymous | common.SecPassCredentials | common.SecMutualAuth)
		return nil
	}
}

func WithExtraProps(key, value string) SaslClientOption {
	return func(c *SaslClient) error {
		c.extraProps[key] = value
		return nil
	}
}

func WithDebugLogger(l *log.Logger) SaslClientOption {
	return func(c *SaslClient) error {
		return loggable.WithDebugLogger(l)(&c.Loggable)
	}
}
func WithInfoLogger(l *log.Logger) SaslClientOption {
	return func(c *SaslClient) error {
		return loggable.WithInfoLogger(l)(&c.Loggable)
	}
}
func WithWarnLogger(l *log.Logger) SaslClientOption {
	return func(c *SaslClient) error {
		return loggable.WithWarnLogger(l)(&c.Loggable)
	}
}
func WithErrorLogger(l *log.Logger) SaslClientOption {
	return func(c *SaslClient) error {
		return loggable.WithErrorLogger(l)(&c.Loggable)
	}
}

func (c SaslClient) IsEstablished() bool {
	if c.mech != nil {
		return c.mech.IsEstablished()
	} else {
		return false
	}
}

func (c *SaslClient) Start() (outToken []byte, err error) {
	c.mech = nil

	// how much 'extra ssf' do we need if we take the external layer into account?
	var minSSF uint
	if c.minSSF < c.extProps.ssf {
		minSSF = 0
	} else {
		minSSF = c.minSSF - c.extProps.ssf
	}

	cbDisposition, err := c.channelBindingDisposition()
	if err != nil {
		return nil, err
	}

	// find the first mech that matches the security requirements
	var chosenMech string
	for _, mech := range c.mechList {
		mechProps := registry.Properties(mech)

		// discard if the mech does not meet the min SSF requirement
		if minSSF > mechProps.MaxSSF {
			c.Debugf("mech %s max SSF (%d) too low (want %d)", mech, mechProps.MaxSSF, minSSF)
			continue
		}

		wantSecProps := c.secProps
		if (c.extProps.ssf > c.minSSF) && (c.extProps.ssf > 1) {
			c.Debugf("mech %s (max SSF %d) upgraded to non-plaintext (external SSF: %d)", mech, mechProps.MaxSSF, c.extProps.ssf)
			wantSecProps &^= common.SecNoPlainText
		}

		// does mech meet security requirements?
		if ((wantSecProps ^ mechProps.SecurityProperties) & wantSecProps) != 0 {
			c.Debugf("mech %s does not meet security requirements", mech)
			continue
		}

		// does our configuration meet the mech's feature requirements?

		if cbDisposition == channelBindingDispMust && (mechProps.Fearures&common.FeatChannelBindings == 0) {
			c.Debugf("mech %s does not support channel bindings", mech)
			continue
		}

		if (mechProps.Fearures&common.FeatNeedServerFQDN != 0) && c.serverFQDN == "" {
			c.Debugf("mech %s requires server FQDN", mech)
			continue
		}

		// do the mech's features cover the required features?
		if c.needHTTP && (mechProps.Fearures&common.FeatSupportsHTTP == 0) {
			c.Debugf("mech %s does not support HTTP", mech)
			continue
		}

		// this looks like a good fit..
		chosenMech = mech
		break
	}

	if chosenMech == "" {
		return nil, common.ErrNoMech
	}

	c.Debugf("Chose mech %s", chosenMech)

	// Create an instance of the chosen mech
	cfg := common.MechConfig{
		Logger:         c.Loggable,
		Service:        c.service,
		ServerFQDN:     c.serverFQDN,
		MinSSF:         c.minSSF,
		MaxSSF:         c.maxSSF,
		MaxBufSize:     c.maxBufSize,
		ExternalSSF:    c.extProps.ssf,
		SecProps:       c.secProps,
		HTTPMode:       c.needHTTP,
		ExtraProps:     c.extraProps,
		ChannelBinding: c.channelBindings,
	}
	c.mech = registry.NewMech(chosenMech, cfg)

	// Don't return a token if the mech wants the server to go first
	mechProps := c.mech.MechProperties()
	if mechProps.Fearures&common.FeatServerFirst != 0 {
		return nil, nil
	}

	// otherwise execute the first step
	return c.Step(nil)
}

func (c *SaslClient) Step(inToken []byte) (outToken []byte, err error) {
	if c.mech == nil {
		return nil, common.ErrNotStarted
	}

	if c.IsEstablished() {
		return nil, common.ErrAlreadyEstablished
	}

	return c.mech.Step(inToken)
}

func (c SaslClient) ContextParams() (params common.ContextParams, err error) {
	if c.mech == nil {
		err = common.ErrNotStarted
		return
	}

	if !c.IsEstablished() {
		err = common.ErrNotEstablished
		return
	}

	return c.mech.ContextParams(), nil
}

func (c *SaslClient) Encode(input []byte) (outToken []byte, err error) {
	if c.mech == nil {
		return nil, common.ErrNotStarted
	}

	if !c.IsEstablished() {
		return nil, common.ErrNotEstablished
	}

	// output is the same as input if there is no negotiated security layer
	if c.mech.ContextParams().SSF == 0 {
		outToken = input
	} else {
		outToken, err = c.mech.Encode(input)
	}

	return
}

func (c *SaslClient) Decode(inputToken []byte) (output []byte, err error) {
	if c.mech == nil {
		return nil, common.ErrNotStarted
	}

	if !c.IsEstablished() {
		return nil, common.ErrNotEstablished
	}

	// output is the same as input if there is no negotiated security layer
	if c.mech.ContextParams().SSF == 0 {
		output = inputToken
	} else {
		output, err = c.mech.Decode(inputToken)
	}

	return
}

func supportsChannelBindings(mechList []string) bool {
	supported := false

	for _, mech := range mechList {
		mechProps := registry.Properties(mech)
		if mechProps.Fearures&common.FeatChannelBindings > 0 {
			supported = true
			break
		}
	}

	return supported
}

// port of Cyrus SASL _sasl_cbinding_disp
func (c *SaslClient) channelBindingDisposition() (disp channelBindingDisposition, err error) {
	serverSupported := supportsChannelBindings(c.mechList)
	disp = channelBindingDispNone
	if c.channelBindings == nil {
		c.Debugf("no channel binding requested")
		return
	}

	switch {
	// if negotiating mechs..
	case len(c.mechList) > 0:
		// error if we require CB and the server doesn't support it
		if !serverSupported && c.channelBindings.Critical {
			c.Debugf("no negotiating mechs support channel binding which is critical for us")
			err = common.ErrNoMech
			return
		} else {
			// otherwise indicate that we want CB for now
			disp = channelBindingDispWant
		}
	// if not negotiating mechs, we must have CB if critical
	case c.channelBindings.Critical:
		disp = channelBindingDispMust
	}

	return
}
