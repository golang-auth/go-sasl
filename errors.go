// SPDX-License-Identifier: Apache-2.0

package sasl

import (
	"errors"
	"fmt"
)

var (
	ErrNoMech             = errors.New("no worthy mechs found")
	ErrNotStarted         = errors.New("must use Start() before Step()")
	ErrAlreadyEstablished = errors.New("context is already established")
	ErrNotEstablished     = errors.New("context is not established")
	ErrBadProtocol        = errors.New("bad protocol")
	ErrBadChannelBinding  = errors.New("channel binding failure")
)

type ErrTooWeak struct {
	MechSSF     uint
	ExtSSF      uint
	RequiredSSF uint
}

func (e ErrTooWeak) Error() string {
	if e.ExtSSF > 0 {
		return fmt.Sprintf("negotiated SSF (%d) + external SSF (%d) is less than required SSF (%d)", e.MechSSF, e.ExtSSF, e.RequiredSSF)
	} else {
		return fmt.Sprintf("negotiated SSF (%d) is less than required SSF (%d)", e.MechSSF, e.RequiredSSF)
	}
}
