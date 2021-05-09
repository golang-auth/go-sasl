package sasl

import (
	"log"
	"os"
	"strings"
	"testing"

	"github.com/golang-auth/go-sasl/common"
	"github.com/golang-auth/go-sasl/registry"
	"github.com/stretchr/testify/assert"
)

func TestWithServerFQDN(t *testing.T) {
	cli := SaslClient{}

	opt := WithServerFQDN("foo.bar.com")
	assert.NoError(t, opt(&cli), "foo.bar.com is a valid hostname")
	assert.Equal(t, "foo.bar.com", cli.serverFQDN)

	opt = WithServerFQDN("foo")
	assert.NoError(t, opt(&cli), "foo is a valid hostname")
	assert.Equal(t, "foo", cli.serverFQDN)

	opt = WithServerFQDN("invalid-.hostname")
	assert.Error(t, opt(&cli), "invalid-.hostname is not a valid hostname")
}

func TestLogging(t *testing.T) {
	sb := strings.Builder{}
	loggerD := log.New(&sb, "testD: ", 0)
	loggerI := log.New(&sb, "testI: ", 0)
	loggerW := log.New(&sb, "testW: ", 0)
	loggerE := log.New(&sb, "testE: ", 0)

	cli, err := NewSaslClient("imap",
		WithDebugLogger(loggerD),
		WithInfoLogger(loggerI),
		WithWarnLogger(loggerW),
		WithErrorLogger(loggerE),
	)
	assert.NoError(t, err)
	cli.Debugf("debug testing 1 2 3")
	cli.Infof("info testing 1 2 3")
	cli.Warnf("warn testing 1 2 3")
	cli.Errorf("error testing 1 2 3")

	assert.Contains(t, sb.String(), "testD: debug testing 1 2 3\n")
	assert.Contains(t, sb.String(), "testI: info testing 1 2 3\n")
	assert.Contains(t, sb.String(), "testW: warn testing 1 2 3\n")
	assert.Contains(t, sb.String(), "testE: error testing 1 2 3\n")
}

func TestNewSaslClientMechs(t *testing.T) {
	l := log.New(os.Stderr, "unittest: ", 0)
	opts := []SaslClientOption{
		WithDebugLogger(l), WithInfoLogger(l), WithWarnLogger(l), WithErrorLogger(l),
	}

	// use default mech list
	cli1, err := NewSaslClient("imap", opts...)
	assert.NoError(t, err)
	assert.Equal(t, []string{"GSSAPI"}, cli1.mechList)

	// specify some good, some bad mechs - expect just the good ones back
	opts2 := append(opts, WithMechList([]string{"GSSAPI", "foo"}))
	cli2, err := NewSaslClient("imap", opts2...)
	assert.NoError(t, err)
	assert.Equal(t, []string{"GSSAPI"}, cli2.mechList)

	// specify all bad mechs - expect error
	opts3 := append(opts, WithMechList([]string{"foo", "bar"}))
	_, err = NewSaslClient("imap", opts3...)
	assert.ErrorIs(t, common.ErrNoMech, err)
}

type mockMech struct {
}

func (m mockMech) Name() string {
	return "MOCK"
}
func (m mockMech) MechProperties() common.MechProps {
	return common.MechProps{}
}
func (m mockMech) IsEstablished() bool {
	return false
}
func (m mockMech) Step(inToken []byte) (outToken []byte, err error) {
	return nil, nil
}
func (m mockMech) ContextParams() common.ContextParams {
	return common.ContextParams{}
}
func (m mockMech) Encode([]byte) ([]byte, error) {
	return nil, nil
}
func (m mockMech) Decode([]byte) ([]byte, error) {
	return nil, nil
}

type mockMech1 struct {
	mockMech
}
type mockMech2 struct {
	mockMech
}
type mockMech3 struct {
	mockMech
}

func newMockMech1(cfg common.MechConfig) common.Mech {
	return &mockMech1{}
}
func newMockMech2(cfg common.MechConfig) common.Mech {
	return &mockMech2{}
}
func newMockMech3(cfg common.MechConfig) common.Mech {
	return &mockMech3{}
}

func TestSaslClientStart(t *testing.T) {
	registry.Register("MECH1", newMockMech1, common.MechProps{
		MaxSSF:             256,
		SecurityProperties: common.SecNoPlainText | common.SecNoActive | common.SecNoAnonymous | common.SecMutualAuth | common.SecPassCredentials,
		Fearures:           common.FeatWantClientFirst | common.FeatDontUseUserPassword,
	})

	registry.Register("MECH2", newMockMech2, common.MechProps{
		MaxSSF:             0,
		SecurityProperties: common.SecNoAnonymous | common.SecPassCredentials,
		Fearures:           common.FeatWantClientFirst,
	})

	registry.Register("MECH3", newMockMech3, common.MechProps{
		MaxSSF:             10,
		SecurityProperties: common.SecNoPlainText | common.SecNoAnonymous | common.SecPassCredentials,
		Fearures:           common.FeatWantClientFirst,
	})

	// try with all 3 mechs and no external layer, default options
	// should choose MECH1
	cli, err := NewSaslClient("imap", WithMechList([]string{"MECH1", "MECH2", "MECH3"}))
	assert.NoError(t, err)
	_, err = cli.Start()
	assert.NoError(t, err)
	assert.IsType(t, &mockMech1{}, cli.mech, "MECH1 is preferred")

	// same but with a difference preference order.  MECH3 should be chosen because
	// it supports the default security requirements
	cli, err = NewSaslClient("imap", WithMechList([]string{"MECH2", "MECH3", "MECH1"}))
	assert.NoError(t, err)
	_, err = cli.Start()
	assert.NoError(t, err)
	assert.IsType(t, &mockMech3{}, cli.mech, "MECH1 is preferred")

	// same but with a min-ssf 20 - should choose MECH1
	cli, err = NewSaslClient("imap",
		WithMechList([]string{"MECH2", "MECH3", "MECH1"}),
		WithMinSSF(20))
	assert.NoError(t, err)
	_, err = cli.Start()
	assert.NoError(t, err)
	assert.IsType(t, &mockMech1{}, cli.mech)

	// same but assume we have an external layer with SSF 15, should choose MECH3 again
	// because the new mech only needs to provide 5 'ssf units'
	cli, err = NewSaslClient("imap",
		WithMechList([]string{"MECH2", "MECH3", "MECH1"}),
		WithMinSSF(20))
	cli.extProps.ssf = 15
	assert.NoError(t, err)
	_, err = cli.Start()
	assert.NoError(t, err)
	assert.IsType(t, &mockMech3{}, cli.mech)

	// now set the external SSF to 25;  MECH2 is now preferred because we no longer need
	// the SecNoPlainText property
	cli, err = NewSaslClient("imap",
		WithMechList([]string{"MECH2", "MECH3", "MECH1"}),
		WithMinSSF(20))
	cli.extProps.ssf = 25
	assert.NoError(t, err)
	_, err = cli.Start()
	assert.NoError(t, err)
	assert.IsType(t, &mockMech2{}, cli.mech)
}
