// SPDX-License-Identifier: Apache-2.0

package sasl

import (
	"errors"
	"net/netip"
	"regexp"
)

// SSF defines the security strength factor (SSF) for a SASL mechanism
type SSF uint

type SaslOption func(*saslCommon) error

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
}

type ExternalProperties struct {
	SSF    SSF
	AuthID string
}

var validHostnameRegex = regexp.MustCompile(`^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$`)

func WithServerFQDN(fqdn string) SaslOption {
	return func(c *saslCommon) error {
		if fqdn != "" {
			if !validHostnameRegex.Match([]byte(fqdn)) {
				return errors.New("bad hostname")
			}

			c.serverFQDN = fqdn
		}

		return nil
	}
}

func WithAvailableMechs(mechs []string) SaslOption {
	return func(c *saslCommon) error {
		if len(mechs) > 0 {
			c.enabledMechs = mechs
		}

		return nil
	}
}

func WithMinSSF(ssf SSF) SaslOption {
	return func(c *saslCommon) error {
		c.securityProperties.MinSSF = ssf
		return nil
	}
}

func WithMaxSSF(ssf SSF) SaslOption {
	return func(c *saslCommon) error {
		c.securityProperties.MaxSSF = ssf
		return nil
	}
}

func WithSecurityFlags(props SecurityFlag) SaslOption {
	return func(c *saslCommon) error {
		c.securityProperties.SecFlags = props
		return nil
	}
}

func WithMaxBufSize(size uint32) SaslOption {
	return func(c *saslCommon) error {
		c.securityProperties.MaxBufSize = size
		return nil
	}
}

func WithExternalSSF(ssf SSF) SaslOption {
	return func(c *saslCommon) error {
		c.externalProperties.SSF = ssf
		return nil
	}
}

func WithExternalAuthID(authID string) SaslOption {
	return func(c *saslCommon) error {
		c.externalProperties.AuthID = authID
		return nil
	}
}

func WithSuccessData() SaslOption {
	return func(c *saslCommon) error {
		c.successData = true
		return nil
	}
}

func WithNeedHTTP() SaslOption {
	return func(c *saslCommon) error {
		c.needHTTP = true
		return nil
	}
}

func WithNeedProxy() SaslOption {
	return func(c *saslCommon) error {
		c.needProxy = true
		return nil
	}
}

func WithChannelBindings(cb ChannelBinding) SaslOption {
	return func(c *saslCommon) error {
		c.channelBinding = &cb
		return nil
	}
}

func WithLoggers(loggers Loggers) SaslOption {
	return func(c *saslCommon) error {
		c.loggers = loggers
		return nil
	}
}
