// Copyright 2021 Jake Scott. All rights reserved.
// Use of this source code is governed by the Apache License
// version 2.0 that can be found in the LICENSE file.
package gssapi

import (
	"errors"
	"fmt"
	"strings"

	"github.com/golang-auth/go-sasl/common"
	"github.com/golang-auth/go-sasl/pkg/loggable"
	"github.com/golang-auth/go-sasl/registry"

	"github.com/golang-auth/go-gssapi/v2"
	gsscommon "github.com/golang-auth/go-gssapi/v2/common"
	_ "github.com/golang-auth/go-gssapi/v2/krb5"
)

const mechName = "GSSAPI"

func init() {
	// see: https://www.iana.org/assignments/sasl-mechanisms/sasl-mechanisms.xhtml

	registry.Register(mechName, NewMech, common.MechProps{
		MaxSSF:             256,
		SecurityProperties: common.SecNoPlainText | common.SecNoActive | common.SecNoAnonymous | common.SecMutualAuth | common.SecPassCredentials,
		Fearures:           common.FeatNeedServerFQDN | common.FeatWantClientFirst | common.FeatChannelBindings,
	})
}

type qop uint8

const (
	layerNone qop = 1 << iota
	layerIntegrity
	layerConfidentiality
)

func (q qop) String() string {
	var names []string
	if q&layerNone > 0 {
		names = append(names, "none")
	}
	if q&layerIntegrity > 0 {
		names = append(names, "integrity")
	}
	if q&layerConfidentiality > 0 {
		names = append(names, "confidentiality")
	}

	return strings.Join(names, ", ")
}

type state uint8

const (
	stateAuthenticating state = iota
	stateSSFCap
	stateAuthenticated
)

type GSSAPIMech struct {
	loggable.Loggable
	config            common.MechConfig
	client            gssapi.Mech
	qop               qop
	ssf               uint
	state             state
	maxOutputBufferSz uint32
}

func NewMech(cfg common.MechConfig) common.Mech {
	cfg.Logger.Debugf("new GSSAPIMech")
	return &GSSAPIMech{
		Loggable: cfg.Logger,
		config:   cfg,
		client:   gssapi.NewMech("kerberos_v5"),
		state:    stateAuthenticating,
	}
}

func (m GSSAPIMech) Name() string {
	return mechName
}

func (m GSSAPIMech) MechProperties() common.MechProps {
	return registry.Properties(mechName)
}

func (m *GSSAPIMech) Step(inToken []byte) (outToken []byte, err error) {
	switch m.state {
	case stateAuthenticating:
		return m.stepAuthenticating(inToken)
	case stateSSFCap:
		return m.stepSSFCap(inToken)
	case stateAuthenticated:
		return nil, common.ErrAlreadyEstablished
	}

	return nil, fmt.Errorf("gssapi: step - bad state (%d)", m.state)
}

func (m *GSSAPIMech) stepAuthenticating(inToken []byte) (outToken []byte, err error) {
	m.Debugf("gssapi: step (authenticating)")

	// only the first time..
	if inToken == nil {
		if len(m.config.ServerFQDN) == 0 {
			return nil, errors.New("server FQDN not provided")
		}
		princName := m.config.Service + "/" + m.config.ServerFQDN

		var flags gssapi.ContextFlag = gssapi.ContextFlagMutual | gssapi.ContextFlagSequence
		if m.config.MaxSSF > m.config.ExternalSSF {
			flags |= gssapi.ContextFlagInteg

			if (m.config.MaxSSF - m.config.ExternalSSF) > 1 {
				flags |= gssapi.ContextFlagConf
			}
		}

		m.Debugf("gssapi: requesting flags [%s]", flags.String())

		// convery SASL channel binding data to GSSAPI channel binding data
		var gsscb *gsscommon.ChannelBinding = nil
		if m.config.ChannelBinding != nil {
			gsscb = &gsscommon.ChannelBinding{
				Data: m.config.ChannelBinding.Data,
			}
		}

		if err = m.client.Initiate(princName, flags, gsscb); err != nil {
			return
		}

		switch {
		case m.client.ContextFlags()&gssapi.ContextFlagInteg == 0:
			m.qop = layerNone
		case m.client.ContextFlags()&gssapi.ContextFlagConf == 0:
			m.qop = layerNone | layerIntegrity
		default:
			m.qop = layerNone | layerIntegrity | layerConfidentiality
		}

		inToken = []byte{}
		m.Debugf("gssapi: step GSSAPI context initiated")
	}

	outToken, err = m.client.Continue(inToken)

	if m.client.IsEstablished() {
		if m.config.HTTPMode {
			m.Debugf("gssapi: step, GSSAPI context established (HTTP mode)")
			m.state = stateAuthenticated
		} else {
			m.Debugf("gssapi: step, GSSAPI context established, negotiating SSF")
			m.state = stateSSFCap
			if outToken == nil {
				outToken = []byte{}
			}
		}
	}

	return outToken, err
}

func (m *GSSAPIMech) stepSSFCap(inToken []byte) (outToken []byte, err error) {
	// inToken should be a wrapped token sent to us by the SASL server following the
	// establishment of the GSSAPI context
	m.Debugf("gssapi: step (negotiating SSF)")

	// read the server's quality-of-protection offer
	data, _, err := m.client.Unwrap(inToken)
	if err != nil {
		return nil, err
	}

	if len(data) != 4 {
		return nil, fmt.Errorf("gssapi: bad SSF negotiate token (%d bytes, wanted 4)", len(data))
	}
	var serverQOPOffer qop = qop(data[0])
	m.Debugf("server QOP offer: %s,   our QOP: %s", serverQOPOffer, m.qop)

	channelSSF := m.client.SSF()
	m.Debugf("GSSAPI SSF: %d", channelSSF)
	if m.config.MinSSF > (channelSSF + m.config.ExternalSSF) {
		return nil, common.ErrTooWeak{MechSSF: channelSSF, ExtSSF: m.config.ExternalSSF, RequiredSSF: m.config.MinSSF}
	}

	// how much 'SSF' is the mech allowed to provide and how much does it have to provide?
	var allowedSSF, needSSF uint
	if m.config.MaxSSF >= m.config.ExternalSSF {
		allowedSSF = m.config.MaxSSF - m.config.ExternalSSF
		m.Debugf("residual SSF premitted: %d", allowedSSF)
	}
	if m.config.MinSSF >= m.config.ExternalSSF {
		needSSF = m.config.MinSSF - m.config.ExternalSSF
		m.Debugf("required SSF remaining: %d", needSSF)
	}

	var qopChoice qop
	switch {
	case m.qop&layerConfidentiality > 0 && serverQOPOffer&layerConfidentiality > 0 && allowedSSF >= channelSSF && needSSF <= channelSSF:
		qopChoice = layerConfidentiality
		m.ssf = channelSSF

		// AD explicitly requires integrity when requesting confidentiality
		if val, ok := m.config.ExtraProps["ad_compat"]; ok && isTrue(val) {
			qopChoice = layerConfidentiality | layerIntegrity
		}

	case m.qop&layerIntegrity > 0 && serverQOPOffer&layerIntegrity > 0 && allowedSSF >= 1 && needSSF <= 2:
		qopChoice = layerIntegrity
		m.ssf = 1
	case m.qop&layerNone > 0 && serverQOPOffer&layerNone > 0 && needSSF <= 0:
		qopChoice = layerNone
		m.ssf = 0
	default:
		return nil, errors.New("no suitable security layer available")
	}

	m.Debugf("selected QOP: %s, ssf: %d", qopChoice, m.ssf)

	// max message size the server will accept
	m.maxOutputBufferSz = uint32(data[1])<<16 | uint32(data[2])<<8 + uint32(data[3])
	m.Debugf("server max input buffer size: %d", m.maxOutputBufferSz)

	if m.ssf > 0 {
		// max size of an pre-wrapped message we can send to the server
		m.maxOutputBufferSz = m.client.WrapSizeLimit(m.maxOutputBufferSz, (m.ssf > 1))
		m.Debugf("our max unwrapped output buffer size: %d", m.maxOutputBufferSz)
	}

	dataOut := make([]byte, 4)
	if qopChoice > 1 {
		max := minUint(m.config.MaxBufSize, 0xFFFFFF) // the max is 16777215
		m.Debugf("our max input buffer size: %d", max)
		dataOut[1] = byte(max >> 16 & 0xff)
		dataOut[2] = byte(max >> 8 & 0xff)
		dataOut[3] = byte(max >> 0 & 0xff)
	}
	dataOut[0] = byte(qopChoice)

	// Create the wrapped token to send to the server
	outToken, err = m.client.Wrap(dataOut, false)
	if err != nil {
		return nil, err
	}

	m.state = stateAuthenticated
	return outToken, err
}

func (m GSSAPIMech) IsEstablished() bool {
	return (m.state == stateAuthenticated)
}

func (m GSSAPIMech) ContextParams() common.ContextParams {
	return common.ContextParams{
		SSF:                m.ssf,
		MaxPeerMessageSize: m.maxOutputBufferSz,
	}
}

func (m *GSSAPIMech) Encode(input []byte) (outToken []byte, err error) {
	if m.ssf == 0 {
		return nil, errors.New("can't encode data: no security layer negotiated")
	}

	return m.client.Wrap(input, (m.ssf > 1))
}

func (m *GSSAPIMech) Decode(inputToken []byte) (output []byte, err error) {
	if m.ssf == 0 {
		return nil, errors.New("can't decode data: no security layer negotiated")
	}

	output, _, err = m.client.Unwrap(inputToken)
	return
}

func isTrue(val string) bool {
	return val == "1" || val == "y" || val == "on" || val == "t"
}

func minUint(a, b uint) uint {
	if a < b {
		return a
	}
	return b
}
