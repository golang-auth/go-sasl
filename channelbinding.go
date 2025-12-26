// SPDX-License-Identifier: Apache-2.0

package sasl

type ChannelBinding struct {
	Name     string
	Critical bool
	Data     []byte
}

type channelBindingDisposition int

const (
	channelBindingDispNone channelBindingDisposition = iota
	channelBindingDispWant
	channelBindingDispUsed
)
