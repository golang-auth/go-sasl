// SPDX-License-Identifier: Apache-2.0

package sasl

import (
	"testing"
)

func TestNewSaslClient_Basic(t *testing.T) {
	a := NewAssert(t)
	t.Cleanup(func() { resetRegistry() })
	RegisterMech(MechInfo{Name: "TEST"})

	client, err := NewSaslClient("imap")
	a.NoErrorFatal(err)
	a.NotNil(client)
	a.Equal("imap", client.service)

	// check the defaults
	a.Equal(SSF(^uint(0)), client.securityProperties.MaxSSF)
	a.Equal(SecNoAnonymous|SecNoPlainText, client.securityProperties.SecFlags)
	a.Equal(uint32(65536), client.securityProperties.MaxBufSize)
}

func TestNewSaslClient_DefaultMechs(t *testing.T) {
	a := NewAssert(t)
	// Reset registry and register a test mech
	t.Cleanup(func() { resetRegistry() })
	RegisterMech(MechInfo{Name: "TEST1"})
	RegisterMech(MechInfo{Name: "TEST2"})

	client, err := NewSaslClient("imap")
	a.NoErrorFatal(err)
	// Should have all registered mechs
	enabledMechs := client.enabledMechs
	a.Contains(enabledMechs, "TEST1")
	a.Contains(enabledMechs, "TEST2")
}

func TestNewSaslClient_NoMechsAvailable(t *testing.T) {
	a := NewAssert(t)
	// Reset registry to empty
	t.Cleanup(func() { resetRegistry() })

	_, err := NewSaslClient("imap")
	a.ErrorIs(err, ErrNoMech)
}

func TestIsEqualMech(t *testing.T) {
	a := NewAssert(t)

	tests := []struct {
		name      string
		reqMech   string
		plugMech  string
		wantPlus  bool
		wantEqual bool
	}{
		{
			name:      "exact match without PLUS",
			reqMech:   "DIGEST-MD5",
			plugMech:  "DIGEST-MD5",
			wantPlus:  false,
			wantEqual: true,
		},
		{
			name:      "case-insensitive match without PLUS",
			reqMech:   "digest-md5",
			plugMech:  "DIGEST-MD5",
			wantPlus:  false,
			wantEqual: true,
		},
		{
			name:      "case-insensitive match without PLUS reversed",
			reqMech:   "DIGEST-MD5",
			plugMech:  "digest-md5",
			wantPlus:  false,
			wantEqual: true,
		},
		{
			name:      "match with PLUS suffix uppercase",
			reqMech:   "DIGEST-MD5-PLUS",
			plugMech:  "DIGEST-MD5",
			wantPlus:  true,
			wantEqual: true,
		},
		{
			name:      "match with PLUS suffix lowercase",
			reqMech:   "digest-md5-plus",
			plugMech:  "DIGEST-MD5",
			wantPlus:  true,
			wantEqual: true,
		},
		{
			name:      "match with PLUS suffix mixed case",
			reqMech:   "Digest-Md5-Plus",
			plugMech:  "DIGEST-MD5",
			wantPlus:  true,
			wantEqual: true,
		},
		{
			name:      "match with PLUS suffix and case-insensitive plugMech",
			reqMech:   "DIGEST-MD5-PLUS",
			plugMech:  "digest-md5",
			wantPlus:  true,
			wantEqual: true,
		},
		{
			name:      "no match different mechs",
			reqMech:   "DIGEST-MD5",
			plugMech:  "PLAIN",
			wantPlus:  false,
			wantEqual: false,
		},
		{
			name:      "no match with PLUS suffix but different base mech",
			reqMech:   "DIGEST-MD5-PLUS",
			plugMech:  "PLAIN",
			wantPlus:  true,
			wantEqual: false,
		},
		{
			name:      "no match prefix but not equal",
			reqMech:   "DIGEST-MD5-EXTRA",
			plugMech:  "DIGEST-MD5",
			wantPlus:  false,
			wantEqual: false,
		},
		{
			name:      "PLUS suffix but not matching base",
			reqMech:   "PLAIN-PLUS",
			plugMech:  "DIGEST-MD5",
			wantPlus:  true,
			wantEqual: false,
		},
		{
			name:      "empty strings",
			reqMech:   "",
			plugMech:  "",
			wantPlus:  false,
			wantEqual: true,
		},
		{
			name:      "empty reqMech with non-empty plugMech",
			reqMech:   "",
			plugMech:  "DIGEST-MD5",
			wantPlus:  false,
			wantEqual: false,
		},
		{
			name:      "non-empty reqMech with empty plugMech",
			reqMech:   "DIGEST-MD5",
			plugMech:  "",
			wantPlus:  false,
			wantEqual: false,
		},
		{
			name:      "just PLUS suffix",
			reqMech:   "-PLUS",
			plugMech:  "",
			wantPlus:  true,
			wantEqual: true,
		},
		{
			name:      "PLUS in middle not detected",
			reqMech:   "DIGEST-PLUS-MD5",
			plugMech:  "DIGEST-PLUS-MD5",
			wantPlus:  false,
			wantEqual: true,
		},
		{
			name:      "lowercase plus suffix",
			reqMech:   "digest-md5-plus",
			plugMech:  "DIGEST-MD5",
			wantPlus:  true,
			wantEqual: true,
		},
		{
			name:      "GSSAPI example",
			reqMech:   "GSSAPI",
			plugMech:  "GSSAPI",
			wantPlus:  false,
			wantEqual: true,
		},
		{
			name:      "GSSAPI with PLUS",
			reqMech:   "GSSAPI-PLUS",
			plugMech:  "GSSAPI",
			wantPlus:  true,
			wantEqual: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPlus, gotEqual := isEqualMech(tt.reqMech, tt.plugMech)
			a.Equal(tt.wantPlus, gotPlus, "plus mismatch for reqMech=%q, plugMech=%q", tt.reqMech, tt.plugMech)
			a.Equal(tt.wantEqual, gotEqual, "equal mismatch for reqMech=%q, plugMech=%q", tt.reqMech, tt.plugMech)
		})
	}
}

func TestIsMechPlus(t *testing.T) {
	a := NewAssert(t)

	tests := []struct {
		name     string
		mech     string
		wantPlus bool
	}{
		{
			name:     "uppercase PLUS suffix",
			mech:     "DIGEST-MD5-PLUS",
			wantPlus: true,
		},
		{
			name:     "lowercase plus suffix",
			mech:     "digest-md5-plus",
			wantPlus: true,
		},
		{
			name:     "mixed case Plus suffix",
			mech:     "Digest-Md5-Plus",
			wantPlus: true,
		},
		{
			name:     "PLUS in uppercase",
			mech:     "GSSAPI-PLUS",
			wantPlus: true,
		},
		{
			name:     "no PLUS suffix",
			mech:     "DIGEST-MD5",
			wantPlus: false,
		},
		{
			name:     "PLAIN mechanism",
			mech:     "PLAIN",
			wantPlus: false,
		},
		{
			name:     "PLUS in middle not detected",
			mech:     "DIGEST-PLUS-MD5",
			wantPlus: false,
		},
		{
			name:     "empty string",
			mech:     "",
			wantPlus: false,
		},
		{
			name:     "just -PLUS",
			mech:     "-PLUS",
			wantPlus: false,
		},
		{
			name:     "just -plus lowercase",
			mech:     "-plus",
			wantPlus: false,
		},
		{
			name:     "PLUS at start not detected",
			mech:     "PLUS-DIGEST-MD5",
			wantPlus: false,
		},
		{
			name:     "contains plus but not suffix",
			mech:     "SCRAM-PLUS-SHA-256",
			wantPlus: false,
		},
		{
			name:     "exactly 4 characters",
			mech:     "PLUS",
			wantPlus: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isMechPlus(tt.mech)
			a.Equal(tt.wantPlus, got, "isMechPlus(%q) = %v, want %v", tt.mech, got, tt.wantPlus)
		})
	}
}

func TestOrderMechs(t *testing.T) {
	a := NewAssert(t)

	tests := []struct {
		name            string
		mechs           []string
		channelBinding  *ChannelBinding
		wantOrdered     []string
		wantServerCanCb bool
		wantErr         error
	}{
		{
			name:  "with channel binding data, PLUS mechs first",
			mechs: []string{"PLAIN", "DIGEST-MD5-PLUS", "GSSAPI", "SCRAM-SHA-256-PLUS"},
			channelBinding: &ChannelBinding{
				Name: "tls-unique",
				Data: []byte("test"),
			},
			wantOrdered:     []string{"DIGEST-MD5-PLUS", "SCRAM-SHA-256-PLUS", "PLAIN", "GSSAPI"},
			wantServerCanCb: true,
			wantErr:         nil,
		},
		{
			name:            "without channel binding data, preserve original order",
			mechs:           []string{"PLAIN", "DIGEST-MD5-PLUS", "GSSAPI", "SCRAM-SHA-256-PLUS"},
			channelBinding:  nil,
			wantOrdered:     []string{"PLAIN", "GSSAPI"},
			wantServerCanCb: false,
			wantErr:         nil,
		},
		{
			name:            "empty mech list",
			mechs:           []string{},
			channelBinding:  nil,
			wantOrdered:     nil,
			wantServerCanCb: false,
			wantErr:         ErrNoMech,
		},
		{
			name:  "all PLUS mechs with channel binding",
			mechs: []string{"DIGEST-MD5-PLUS", "SCRAM-SHA-256-PLUS", "GSSAPI-PLUS"},
			channelBinding: &ChannelBinding{
				Name: "tls-unique",
				Data: []byte("test"),
			},
			wantOrdered:     []string{"DIGEST-MD5-PLUS", "SCRAM-SHA-256-PLUS", "GSSAPI-PLUS"},
			wantServerCanCb: true,
			wantErr:         nil,
		},
		{
			name:            "all PLUS mechs without channel binding",
			mechs:           []string{"DIGEST-MD5-PLUS", "SCRAM-SHA-256-PLUS", "GSSAPI-PLUS"},
			channelBinding:  nil,
			wantOrdered:     nil,
			wantServerCanCb: false,
			wantErr:         ErrNoMech,
		},
		{
			name:  "all non-PLUS mechs with channel binding",
			mechs: []string{"PLAIN", "DIGEST-MD5", "GSSAPI"},
			channelBinding: &ChannelBinding{
				Name: "tls-unique",
				Data: []byte("test"),
			},
			wantOrdered:     []string{"PLAIN", "DIGEST-MD5", "GSSAPI"},
			wantServerCanCb: false,
			wantErr:         nil,
		},
		{
			name:            "all non-PLUS mechs without channel binding",
			mechs:           []string{"PLAIN", "DIGEST-MD5", "GSSAPI"},
			channelBinding:  nil,
			wantOrdered:     []string{"PLAIN", "DIGEST-MD5", "GSSAPI"},
			wantServerCanCb: false,
			wantErr:         nil,
		},
		{
			name:  "single PLUS mech with channel binding",
			mechs: []string{"SCRAM-SHA-256-PLUS"},
			channelBinding: &ChannelBinding{
				Name: "tls-unique",
				Data: []byte("test"),
			},
			wantOrdered:     []string{"SCRAM-SHA-256-PLUS"},
			wantServerCanCb: true,
			wantErr:         nil,
		},
		{
			name:            "single non-PLUS mech",
			mechs:           []string{"PLAIN"},
			channelBinding:  nil,
			wantOrdered:     []string{"PLAIN"},
			wantServerCanCb: false,
			wantErr:         nil,
		},
		{
			name:  "mixed case PLUS mechs",
			mechs: []string{"PLAIN", "digest-md5-plus", "GSSAPI", "Scram-Sha-256-Plus"},
			channelBinding: &ChannelBinding{
				Name: "tls-unique",
				Data: []byte("test"),
			},
			wantOrdered:     []string{"digest-md5-plus", "Scram-Sha-256-Plus", "PLAIN", "GSSAPI"},
			wantServerCanCb: true,
			wantErr:         nil,
		},
		{
			name:  "channel binding with empty data",
			mechs: []string{"PLAIN", "DIGEST-MD5-PLUS"},
			channelBinding: &ChannelBinding{
				Name: "tls-unique",
				Data: []byte{},
			},
			wantOrdered:     []string{"DIGEST-MD5-PLUS", "PLAIN"},
			wantServerCanCb: true,
			wantErr:         nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(func() { resetRegistry() })
			RegisterMech(MechInfo{Name: "TEST"})

			var client SaslClient
			var err error
			if tt.channelBinding != nil {
				client, err = NewSaslClient("test", WithChannelBindings(*tt.channelBinding))
			} else {
				client, err = NewSaslClient("test")
			}
			a.NoErrorFatal(err)

			gotOrdered, gotServerCanCb, gotErr := client.orderMechs(tt.mechs)

			if tt.wantErr != nil {
				a.ErrorIs(gotErr, tt.wantErr)
				a.Nil(gotOrdered)
			} else {
				a.NoError(gotErr)
				a.Equal(tt.wantOrdered, gotOrdered, "ordered mechs mismatch")
				a.Equal(tt.wantServerCanCb, gotServerCanCb, "serverCanCb mismatch")
			}
		})
	}
}
