// Copyright 2021 Jake Scott. All rights reserved.
// Use of this source code is governed by the Apache License
// version 2.0 that can be found in the LICENSE file.
package common

import (
	"errors"
	"fmt"
)

var (
	ErrNoMech             = errors.New("no worthy mechs found")
	ErrNotStarted         = errors.New("must use Start() before Step()")
	ErrAlreadyEstablished = errors.New("context is already established")
	ErrNotEstablished     = errors.New("context is not established")
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
