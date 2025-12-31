// SPDX-License-Identifier: Apache-2.0

package sasl

import (
	"testing"
)

type dummySaslCommonExt struct {
	saslCommon
}

func (d *dummySaslCommonExt) getCommon() *saslCommon {
	return &d.saslCommon
}

func TestSaslOption_WithLoggers(t *testing.T) {
	a := NewAssert(t)

	loggers := NewTestLoggers(t)
	d := dummySaslCommonExt{}
	o := WithLoggers(loggers)
	err := o(&d)
	a.NoErrorFatal(err)
	a.Equal(loggers, d.loggers)
}

func TestSaslOption_WithServerFQDN(t *testing.T) {
	a := NewAssert(t)

	d := dummySaslCommonExt{}
	o := WithServerFQDN("mail.example.com")
	err := o(&d)
	a.NoErrorFatal(err)
	a.Equal("mail.example.com", d.serverFQDN)
}

func TestSaslOption_WithServerFQDN_Invalid(t *testing.T) {
	a := NewAssert(t)

	d := dummySaslCommonExt{}
	o := WithServerFQDN("invalid-.hostname")
	err := o(&d)
	a.Error(err)
}

func TestSaslOption_WithAvailableMechs(t *testing.T) {
	a := NewAssert(t)

	d := dummySaslCommonExt{}
	o := WithAvailableMechs([]string{"TEST"})
	err := o(&d)
	a.NoErrorFatal(err)
	a.Contains(d.enabledMechs, "TEST")
}

func TestSaslOption_WithMinSSF(t *testing.T) {
	a := NewAssert(t)

	d := dummySaslCommonExt{}
	o := WithMinSSF(128)
	err := o(&d)
	a.NoErrorFatal(err)
	a.Equal(SSF(128), d.securityProperties.MinSSF)
}

func TestSaslOption_WithMaxSSF(t *testing.T) {
	a := NewAssert(t)

	d := dummySaslCommonExt{}
	o := WithMaxSSF(256)
	err := o(&d)
	a.NoErrorFatal(err)
	a.Equal(SSF(256), d.securityProperties.MaxSSF)
}

func TestSaslOption_WithSecurityFlags(t *testing.T) {
	a := NewAssert(t)

	d := dummySaslCommonExt{}
	o := WithSecurityFlags(SecMutualAuth)
	err := o(&d)
	a.NoErrorFatal(err)
	a.Equal(SecMutualAuth, d.securityProperties.SecFlags)
}

func TestSaslOption_WithMaxBufSize(t *testing.T) {
	a := NewAssert(t)

	d := dummySaslCommonExt{}
	o := WithMaxBufSize(32768)
	err := o(&d)
	a.NoErrorFatal(err)
	a.Equal(uint32(32768), d.securityProperties.MaxBufSize)
}

func TestSaslOption_WithExternalSSF(t *testing.T) {
	a := NewAssert(t)

	d := dummySaslCommonExt{}
	o := WithExternalSSF(64)
	err := o(&d)
	a.NoErrorFatal(err)
	a.Equal(SSF(64), d.externalProperties.SSF)
}

func TestSaslOption_WithExternalAuthID(t *testing.T) {
	a := NewAssert(t)

	d := dummySaslCommonExt{}
	o := WithExternalAuthID("user@example.com")
	err := o(&d)
	a.NoErrorFatal(err)
	a.Equal("user@example.com", d.externalProperties.AuthID)
}

func TestSaslOption_WithNeedHTTP(t *testing.T) {
	a := NewAssert(t)

	d := dummySaslCommonExt{}
	o := WithNeedHTTP()
	err := o(&d)
	a.NoErrorFatal(err)
	a.True(d.needHTTP)
}

func TestSaslOption_WithChannelBindings(t *testing.T) {
	a := NewAssert(t)

	cb := ChannelBinding{
		Name:     "tls-server-end-point",
		Critical: true,
		Data:     []byte{0x01, 0x02, 0x03, 0x04},
	}
	d := dummySaslCommonExt{}
	o := WithChannelBindings(cb)
	err := o(&d)
	a.NoErrorFatal(err)
	a.NotNil(d.channelBinding)
	a.Equal("tls-server-end-point", d.channelBinding.Name)
	a.True(d.channelBinding.Critical)
	a.Equal([]byte{0x01, 0x02, 0x03, 0x04}, d.channelBinding.Data)
}

func TestSaslOption_MultipleOptions(t *testing.T) {
	a := NewAssert(t)

	loggers := NewTestLoggers(t)
	d := dummySaslCommonExt{}
	opts := []SaslOption{
		WithLoggers(loggers),
		WithServerFQDN("mail.example.com"),
		WithMinSSF(128),
		WithMaxSSF(256),
	}
	for _, o := range opts {
		err := o(&d)
		a.NoErrorFatal(err)
	}
	a.Equal("mail.example.com", d.serverFQDN)
	a.Equal(loggers, d.loggers)
	a.Equal(SSF(128), d.securityProperties.MinSSF)
	a.Equal(SSF(256), d.securityProperties.MaxSSF)
}

func TestSaslOption_WithAuthnIDFunc(t *testing.T) {
	a := NewAssert(t)

	called := false
	testValue := "test-authn-id"
	f := func(authData AuthDataSimple) (string, error) {
		called = true
		return testValue, nil
	}

	d := dummySaslCommonExt{}
	o := WithAuthnIDFunc(f)
	err := o(&d)
	a.NoErrorFatal(err)
	a.NotNil(d.callbacks.AuthnIDCallback)

	result, err := d.callbacks.AuthnIDCallback(AuthDataSimple{Prompt: "Enter authn ID"})
	a.NoError(err)
	a.True(called)
	a.Equal(testValue, result)
}

func TestSaslOption_WithAuthzIDFunc(t *testing.T) {
	a := NewAssert(t)

	called := false
	testValue := "test-authz-id"
	f := func(authData AuthDataSimple) (string, error) {
		called = true
		return testValue, nil
	}

	d := dummySaslCommonExt{}
	o := WithAuthzIDFunc(f)
	err := o(&d)
	a.NoErrorFatal(err)
	a.NotNil(d.callbacks.AuthzIDCallback)

	result, err := d.callbacks.AuthzIDCallback(AuthDataSimple{Prompt: "Enter authz ID"})
	a.NoError(err)
	a.True(called)
	a.Equal(testValue, result)
}

func TestSaslOption_WithPasswordFunc(t *testing.T) {
	a := NewAssert(t)

	called := false
	testValue := "test-password"
	f := func(authData AuthDataPassword) (string, error) {
		called = true
		return testValue, nil
	}

	d := dummySaslCommonExt{}
	o := WithPasswordFunc(f)
	err := o(&d)
	a.NoErrorFatal(err)
	a.NotNil(d.callbacks.PasswordCallback)

	result, err := d.callbacks.PasswordCallback(AuthDataPassword{Prompt: "Enter password"})
	a.NoError(err)
	a.True(called)
	a.Equal(testValue, result)
}

func TestSaslOption_WithChallengeFunc(t *testing.T) {
	a := NewAssert(t)

	called := false
	testValue := "test-response"
	f := func(authData AuthDataChallenge) (string, error) {
		called = true
		return testValue, nil
	}

	d := dummySaslCommonExt{}
	o := WithChallengeFunc(f)
	err := o(&d)
	a.NoErrorFatal(err)
	a.NotNil(d.callbacks.ChallengeCallback)

	result, err := d.callbacks.ChallengeCallback(AuthDataChallenge{
		Prompt:        "Enter response",
		Challenge:     "challenge123",
		DefaultResult: "default",
		EchoPrompt:    EchoPrompt,
	})
	a.NoError(err)
	a.True(called)
	a.Equal(testValue, result)
}

func TestSaslOption_WithRealmFunc(t *testing.T) {
	a := NewAssert(t)

	called := false
	testValue := "test-realm"
	f := func(authData AuthDataRealm) (string, error) {
		called = true
		return testValue, nil
	}

	d := dummySaslCommonExt{}
	o := WithRealmFunc(f)
	err := o(&d)
	a.NoErrorFatal(err)
	a.NotNil(d.callbacks.RealmCallback)

	result, err := d.callbacks.RealmCallback(AuthDataRealm{
		AvailableRealms: []string{"realm1", "realm2"},
	})
	a.NoError(err)
	a.True(called)
	a.Equal(testValue, result)
}

func TestSaslOption_WithAuthnID(t *testing.T) {
	a := NewAssert(t)

	authnID := "user@example.com"
	d := dummySaslCommonExt{}
	o := WithAuthnID(authnID)
	err := o(&d)
	a.NoErrorFatal(err)
	a.NotNil(d.callbacks.AuthnIDCallback)

	result, err := d.callbacks.AuthnIDCallback(AuthDataSimple{Prompt: "Enter authn ID"})
	a.NoError(err)
	a.Equal(authnID, result)
}

func TestSaslOption_WithAuthzID(t *testing.T) {
	a := NewAssert(t)

	authzID := "admin@example.com"
	d := dummySaslCommonExt{}
	o := WithAuthzID(authzID)
	err := o(&d)
	a.NoErrorFatal(err)
	a.NotNil(d.callbacks.AuthzIDCallback)

	result, err := d.callbacks.AuthzIDCallback(AuthDataSimple{Prompt: "Enter authz ID"})
	a.NoError(err)
	a.Equal(authzID, result)
}

func TestSaslOption_WithPassword(t *testing.T) {
	a := NewAssert(t)

	password := "secret123"
	d := dummySaslCommonExt{}
	o := WithPassword(password)
	err := o(&d)
	a.NoErrorFatal(err)
	a.NotNil(d.callbacks.PasswordCallback)

	result, err := d.callbacks.PasswordCallback(AuthDataPassword{Prompt: "Enter password"})
	a.NoError(err)
	a.Equal(password, result)
}

func TestSaslOption_WithChallenge(t *testing.T) {
	a := NewAssert(t)

	response := "response123"
	d := dummySaslCommonExt{}
	o := WithChallenge(response)
	err := o(&d)
	a.NoErrorFatal(err)
	a.NotNil(d.callbacks.ChallengeCallback)

	result, err := d.callbacks.ChallengeCallback(AuthDataChallenge{
		Prompt:        "Enter response",
		Challenge:     "challenge123",
		DefaultResult: "default",
		EchoPrompt:    EchoPrompt,
	})
	a.NoError(err)
	a.Equal(response, result)
}

func TestSaslOption_WithRealm(t *testing.T) {
	a := NewAssert(t)

	realm := "example.com"
	d := dummySaslCommonExt{}
	o := WithRealm(realm)
	err := o(&d)
	a.NoErrorFatal(err)
	a.NotNil(d.callbacks.RealmCallback)

	result, err := d.callbacks.RealmCallback(AuthDataRealm{
		AvailableRealms: []string{"realm1", "realm2"},
	})
	a.NoError(err)
	a.Equal(realm, result)
}

func TestSaslOption_WithAuthIDInteractive(t *testing.T) {
	a := NewAssert(t)

	d := dummySaslCommonExt{}
	o := WithAuthIDInteractive()
	err := o(&d)
	a.NoErrorFatal(err)
	a.NotNil(d.callbacks.AuthnIDCallback)

	result, err := d.callbacks.AuthnIDCallback(AuthDataSimple{Prompt: "Enter authn ID"})
	a.Error(err)
	a.Equal(ErrInteractionRequired, err)
	a.Equal("", result)
}

func TestSaslOption_WithAuthzIDInteractive(t *testing.T) {
	a := NewAssert(t)

	d := dummySaslCommonExt{}
	o := WithAuthzIDInteractive()
	err := o(&d)
	a.NoErrorFatal(err)
	a.NotNil(d.callbacks.AuthzIDCallback)

	result, err := d.callbacks.AuthzIDCallback(AuthDataSimple{Prompt: "Enter authz ID"})
	a.Error(err)
	a.Equal(ErrInteractionRequired, err)
	a.Equal("", result)
}

func TestSaslOption_WithPasswordInteractive(t *testing.T) {
	a := NewAssert(t)

	d := dummySaslCommonExt{}
	o := WithPasswordInteractive()
	err := o(&d)
	a.NoErrorFatal(err)
	a.NotNil(d.callbacks.PasswordCallback)

	result, err := d.callbacks.PasswordCallback(AuthDataPassword{Prompt: "Enter password"})
	a.Error(err)
	a.Equal(ErrInteractionRequired, err)
	a.Equal("", result)
}

func TestSaslOption_WithChallengeInteractive(t *testing.T) {
	a := NewAssert(t)

	d := dummySaslCommonExt{}
	o := WithChallengeInteractive()
	err := o(&d)
	a.NoErrorFatal(err)
	a.NotNil(d.callbacks.ChallengeCallback)

	result, err := d.callbacks.ChallengeCallback(AuthDataChallenge{
		Prompt:        "Enter response",
		Challenge:     "challenge123",
		DefaultResult: "default",
		EchoPrompt:    EchoPrompt,
	})
	a.Error(err)
	a.Equal(ErrInteractionRequired, err)
	a.Equal("", result)
}

func TestSaslOption_WithRealmInteractive(t *testing.T) {
	a := NewAssert(t)

	d := dummySaslCommonExt{}
	o := WithRealmInteractive()
	err := o(&d)
	a.NoErrorFatal(err)
	a.NotNil(d.callbacks.RealmCallback)

	result, err := d.callbacks.RealmCallback(AuthDataRealm{
		AvailableRealms: []string{"realm1", "realm2"},
	})
	a.Error(err)
	a.Equal(ErrInteractionRequired, err)
	a.Equal("", result)
}
