// SPDX-License-Identifier: Apache-2.0

package sasl

import (
	"errors"
	"net/netip"
	"regexp"
)

// SSF defines the security strength factor (SSF) for a SASL mechanism
type SSF uint

// options common to SASL clients and servers
type saslCommon struct {
	loggers            Loggers
	service            string
	serverFQDN         string
	clientFQDN         string
	enabledMechs       []string
	securityProperties securityProperties
	externalProperties ExternalProperties
	localAddress       netip.AddrPort
	remoteAddress      netip.AddrPort
	successData        bool
	needHTTP           bool
	needProxy          bool
	channelBinding     *ChannelBinding
	callbacks          Callbacks
}

type ExternalProperties struct {
	SSF    SSF
	AuthID string
}

type saslCommonExt interface {
	getCommon() *saslCommon
}

type SaslOption func(saslCommonExt) error

var validHostnameRegex = regexp.MustCompile(`^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$`)

func WithServerFQDN(fqdn string) SaslOption {
	return func(c saslCommonExt) error {
		common := c.getCommon()
		if fqdn != "" {
			if !validHostnameRegex.Match([]byte(fqdn)) {
				return errors.New("bad hostname")
			}

			common.serverFQDN = fqdn
		}

		return nil
	}
}

func WithAvailableMechs(mechs []string) SaslOption {
	return func(c saslCommonExt) error {
		common := c.getCommon()
		if len(mechs) > 0 {
			common.enabledMechs = mechs
		}

		return nil
	}
}

func WithMinSSF(ssf SSF) SaslOption {
	return func(c saslCommonExt) error {
		common := c.getCommon()
		common.securityProperties.MinSSF = ssf
		return nil
	}
}

func WithMaxSSF(ssf SSF) SaslOption {
	return func(c saslCommonExt) error {
		common := c.getCommon()
		common.securityProperties.MaxSSF = ssf
		return nil
	}
}

func WithSecurityFlags(props SecurityFlag) SaslOption {
	return func(c saslCommonExt) error {
		common := c.getCommon()
		common.securityProperties.SecFlags = props
		return nil
	}
}

func WithMaxBufSize(size uint32) SaslOption {
	return func(c saslCommonExt) error {
		common := c.getCommon()
		common.securityProperties.MaxBufSize = size
		return nil
	}
}

func WithExternalSSF(ssf SSF) SaslOption {
	return func(c saslCommonExt) error {
		common := c.getCommon()
		common.externalProperties.SSF = ssf
		return nil
	}
}

func WithExternalAuthID(authID string) SaslOption {
	return func(c saslCommonExt) error {
		common := c.getCommon()
		common.externalProperties.AuthID = authID
		return nil
	}
}

func WithSuccessData() SaslOption {
	return func(c saslCommonExt) error {
		common := c.getCommon()
		common.successData = true
		return nil
	}
}

func WithNeedHTTP() SaslOption {
	return func(c saslCommonExt) error {
		common := c.getCommon()
		common.needHTTP = true
		return nil
	}
}

func WithNeedProxy() SaslOption {
	return func(c saslCommonExt) error {
		common := c.getCommon()
		common.needProxy = true
		return nil
	}
}

func WithChannelBindings(cb ChannelBinding) SaslOption {
	return func(c saslCommonExt) error {
		common := c.getCommon()
		common.channelBinding = &cb
		return nil
	}
}

func WithLoggers(loggers Loggers) SaslOption {
	return func(c saslCommonExt) error {
		common := c.getCommon()
		common.loggers = loggers
		return nil
	}
}

func WithAuthnIDFunc(f SaslSimpleCallback) SaslOption {
	return func(c saslCommonExt) error {
		common := c.getCommon()
		common.callbacks.AuthnIDCallback = f
		return nil
	}
}

func WithAuthzIDFunc(f SaslSimpleCallback) SaslOption {
	return func(c saslCommonExt) error {
		common := c.getCommon()
		common.callbacks.AuthzIDCallback = f
		return nil
	}
}

func WithPasswordFunc(f SaslPasswordCallback) SaslOption {
	return func(c saslCommonExt) error {
		common := c.getCommon()
		common.callbacks.PasswordCallback = f
		return nil
	}
}

func WithChallengeFunc(f SaslChallengeCallback) SaslOption {
	return func(c saslCommonExt) error {
		common := c.getCommon()
		common.callbacks.ChallengeCallback = f
		return nil
	}
}

func WithRealmFunc(f SaslRealmCallback) SaslOption {
	return func(c saslCommonExt) error {
		common := c.getCommon()
		common.callbacks.RealmCallback = f
		return nil
	}
}

func WithAuthnID(authnID string) SaslOption {
	return WithAuthnIDFunc(mkStaticSimpleCallback(authnID))
}

func WithAuthzID(authzID string) SaslOption {
	return WithAuthzIDFunc(mkStaticSimpleCallback(authzID))
}

func WithPassword(password string) SaslOption {
	return WithPasswordFunc(mkStaticPasswordCallback(password))
}

func WithChallenge(challenge string) SaslOption {
	return WithChallengeFunc(mkStaticChallengeCallback(challenge))
}

func WithRealm(realm string) SaslOption {
	return WithRealmFunc(mkStaticRealmCallback(realm))
}

func WithAuthIDInteractive() SaslOption {
	return WithAuthnIDFunc(mkInteractionSimpleCallback())
}

func WithAuthzIDInteractive() SaslOption {
	return WithAuthzIDFunc(mkInteractionSimpleCallback())
}

func WithPasswordInteractive() SaslOption {
	return WithPasswordFunc(mkInteractionPasswordCallback())
}

func WithChallengeInteractive() SaslOption {
	return WithChallengeFunc(mkInteractionChallengeCallback())
}

func WithRealmInteractive() SaslOption {
	return WithRealmFunc(mkInteractionRealmCallback())
}
