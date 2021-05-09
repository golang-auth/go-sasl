// Copyright 2021 Jake Scott. All rights reserved.
// Use of this source code is governed by the Apache License
// version 2.0 that can be found in the LICENSE file.
package common

import (
	"github.com/golang-auth/go-sasl/pkg/loggable"
)

type MechProps struct {
	MaxSSF             uint
	SecurityProperties SecurityFlag
	Fearures           Feature
}

type ContextParams struct {
	SSF                uint
	MaxPeerMessageSize uint32
}

type MechConfig struct {
	Logger         loggable.Loggable
	Service        string
	ServerFQDN     string
	MinSSF         uint
	MaxSSF         uint
	MaxBufSize     uint
	ExternalSSF    uint
	SecProps       SecurityFlag
	HTTPMode       bool
	ExtraProps     map[string]string
	ChannelBinding *ChannelBinding
}

type Mech interface {
	Name() string
	MechProperties() MechProps
	IsEstablished() bool
	ContextParams() ContextParams
	Step(inToken []byte) (outToken []byte, err error)
	Encode(input []byte) (outToken []byte, err error)
	Decode(inputToken []byte) (output []byte, err error)
}
