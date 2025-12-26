// SPDX-License-Identifier: Apache-2.0

package sasl

import (
	"testing"
)

func TestNewSaslClient_WithLoggers(t *testing.T) {
	a := NewAssert(t)
	t.Cleanup(func() { resetRegistry() })
	RegisterMech(MechInfo{Name: "TEST"})

	loggers := NewTestLoggers(t)
	client, err := NewSaslClient("imap", WithLoggers(loggers))
	a.NoErrorFatal(err)
	a.NotNil(client)
	a.Equal(loggers, client.loggers)
}

func TestNewSaslClient_WithServerFQDN(t *testing.T) {
	a := NewAssert(t)
	t.Cleanup(func() { resetRegistry() })
	RegisterMech(MechInfo{Name: "TEST"})

	client, err := NewSaslClient("imap", WithServerFQDN("mail.example.com"))
	a.NoErrorFatal(err)
	a.Equal("mail.example.com", client.serverFQDN)
}

func TestNewSaslClient_WithServerFQDN_Invalid(t *testing.T) {
	a := NewAssert(t)
	_, err := NewSaslClient("imap", WithServerFQDN("invalid-.hostname"))
	a.Error(err)
}

func TestNewSaslClient_WithAvailableMechs(t *testing.T) {
	a := NewAssert(t)
	// Register a test mech first
	t.Cleanup(func() { resetRegistry() })
	RegisterMech(MechInfo{Name: "TEST"})

	client, err := NewSaslClient("imap", WithAvailableMechs([]string{"TEST"}))
	a.NoErrorFatal(err)
	a.Contains(client.enabledMechs, "TEST")
}

func TestNewSaslClient_WithAvailableMechs_Unregistered(t *testing.T) {
	a := NewAssert(t)
	t.Cleanup(func() { resetRegistry() })
	// No mechs registered, so providing unregistered mechs should result in ErrNoMech
	_, err := NewSaslClient("imap", WithAvailableMechs([]string{"UNREGISTERED"}))
	a.ErrorIs(err, ErrNoMech)
}

func TestNewSaslClient_WithAvailableMechs_Mixed(t *testing.T) {
	a := NewAssert(t)
	t.Cleanup(func() { resetRegistry() })
	RegisterMech(MechInfo{Name: "VALID"})

	client, err := NewSaslClient("imap", WithAvailableMechs([]string{"VALID", "INVALID"}))
	a.NoErrorFatal(err)
	a.Contains(client.enabledMechs, "VALID")
	a.NotContains(client.enabledMechs, "INVALID")
}

func TestNewSaslClient_WithMinSSF(t *testing.T) {
	a := NewAssert(t)
	t.Cleanup(func() { resetRegistry() })
	RegisterMech(MechInfo{Name: "TEST"})

	client, err := NewSaslClient("imap", WithMinSSF(128))
	a.NoErrorFatal(err)
	a.Equal(SSF(128), client.securityProperties.MinSSF)
}

func TestNewSaslClient_WithMaxSSF(t *testing.T) {
	a := NewAssert(t)
	t.Cleanup(func() { resetRegistry() })
	RegisterMech(MechInfo{Name: "TEST"})

	client, err := NewSaslClient("imap", WithMaxSSF(256))
	a.NoErrorFatal(err)
	a.Equal(SSF(256), client.securityProperties.MaxSSF)
}

func TestNewSaslClient_WithSecurityFlags(t *testing.T) {
	a := NewAssert(t)
	t.Cleanup(func() { resetRegistry() })
	RegisterMech(MechInfo{Name: "TEST"})

	client, err := NewSaslClient("imap", WithSecurityFlags(SecMutualAuth))
	a.NoErrorFatal(err)
	a.Equal(SecMutualAuth, client.securityProperties.SecFlags)
}

func TestNewSaslClient_WithMaxBufSize(t *testing.T) {
	a := NewAssert(t)
	t.Cleanup(func() { resetRegistry() })
	RegisterMech(MechInfo{Name: "TEST"})

	client, err := NewSaslClient("imap", WithMaxBufSize(32768))
	a.NoErrorFatal(err)
	a.Equal(uint32(32768), client.securityProperties.MaxBufSize)
}

func TestNewSaslClient_WithExternalSSF(t *testing.T) {
	a := NewAssert(t)
	t.Cleanup(func() { resetRegistry() })
	RegisterMech(MechInfo{Name: "TEST"})

	client, err := NewSaslClient("imap", WithExternalSSF(64))
	a.NoErrorFatal(err)
	a.Equal(SSF(64), client.externalProperties.SSF)
}

func TestNewSaslClient_WithExternalAuthID(t *testing.T) {
	a := NewAssert(t)
	t.Cleanup(func() { resetRegistry() })
	RegisterMech(MechInfo{Name: "TEST"})

	client, err := NewSaslClient("imap", WithExternalAuthID("user@example.com"))
	a.NoErrorFatal(err)
	a.Equal("user@example.com", client.externalProperties.AuthID)
}

func TestNewSaslClient_WithNeedHTTP(t *testing.T) {
	a := NewAssert(t)
	t.Cleanup(func() { resetRegistry() })
	RegisterMech(MechInfo{Name: "TEST"})

	client, err := NewSaslClient("imap", WithNeedHTTP())
	a.NoErrorFatal(err)
	a.True(client.needHTTP)
}

func TestNewSaslClient_WithChannelBindings(t *testing.T) {
	a := NewAssert(t)
	t.Cleanup(func() { resetRegistry() })
	RegisterMech(MechInfo{Name: "TEST"})

	cb := ChannelBinding{
		Name:     "tls-server-end-point",
		Critical: true,
		Data:     []byte{0x01, 0x02, 0x03, 0x04},
	}
	client, err := NewSaslClient("imap", WithChannelBindings(cb))
	a.NoErrorFatal(err)
	a.NotNil(client.channelBinding)
	a.Equal("tls-server-end-point", client.channelBinding.Name)
	a.True(client.channelBinding.Critical)
	a.Equal([]byte{0x01, 0x02, 0x03, 0x04}, client.channelBinding.Data)
}

func TestNewSaslClient_MultipleOptions(t *testing.T) {
	a := NewAssert(t)
	t.Cleanup(func() { resetRegistry() })
	RegisterMech(MechInfo{Name: "VALID"})

	loggers := NewTestLoggers(t)
	client, err := NewSaslClient("smtp",
		WithLoggers(loggers),
		WithServerFQDN("mail.example.com"),
		WithMinSSF(128),
		WithMaxSSF(256),
	)
	a.NoErrorFatal(err)
	a.Equal("smtp", client.service)
	a.Equal("mail.example.com", client.serverFQDN)
	a.Equal(loggers, client.loggers)
	a.Equal(SSF(128), client.securityProperties.MinSSF)
	a.Equal(SSF(256), client.securityProperties.MaxSSF)
}

func TestNewSaslClient_OptionError(t *testing.T) {
	a := NewAssert(t)
	// Test that an option that returns an error causes NewSaslClient to fail
	_, err := NewSaslClient("imap", WithServerFQDN("invalid-.hostname"))
	a.Error(err)
}
