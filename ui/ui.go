// SPDX-License-Identifier: Apache-2.0

package ui

import (
	"fmt"

	"github.com/charmbracelet/huh"

	"github.com/golang-auth/go-sasl"
)

type UI struct {
	prompts []sasl.Prompt
}

func NewUI() *UI {
	return &UI{}
}

// custom result type so that we can tell the difference betweeen
// an empty result and one that was not filled in.
type result struct {
	value *string
}

func (r *result) Set(value string) {
	r.value = new(string)
	*r.value = value
}

func (r *result) Get() string {
	if r.value == nil {
		return ""
	}
	return *r.value
}

func (ui *UI) Interact(prompts []sasl.Prompt) error {
	ui.prompts = prompts
	results := make([]result, len(ui.prompts))

	fields, err := ui.makeFields(results)
	if err != nil {
		return err
	}

	controls := []huh.Field{
		huh.NewNote().
			Title("Information required for authentication").
			Description("The application requires the following information to authenticate you."),
	}

	controls = append(controls, fields...)

	form := huh.NewForm(
		huh.NewGroup(controls...),
	)

	if err = form.Run(); err != nil {
		return err
	}

	for i, result := range results {
		fmt.Printf("result[%d]: %+v\n", i, result)
		if result.value == nil {
			continue
		}
		err = ui.prompts[i].SetResult(*result.value)
		if err != nil {
			return err
		}
	}

	return nil
}

func (ui *UI) makeFields(results []result) ([]huh.Field, error) {
	fields := make([]huh.Field, len(ui.prompts))

	for i, prompt := range ui.prompts {
		switch prompt.DataType {
		case sasl.PromptDataTypeAuthnID:
			fields[i] = huh.NewInput().
				Title("User ID").
				Description("Your own user ID").
				Accessor(&results[i]).
				CharLimit(64)
		case sasl.PromptDataTypeAuthzID:
			fields[i] = huh.NewInput().
				Title("Authorization user ID").
				Description("The ID of the user to which you are authorizing\nLeave blank to use your own user ID").
				Accessor(&results[i]).
				CharLimit(64)
		case sasl.PromptDataTypePassword:
			fields[i] = huh.NewInput().
				Title("Password").
				Accessor(&results[i]).
				EchoMode(huh.EchoModePassword).
				CharLimit(64)
		case sasl.PromptDataTypeChallenge:
			challenge, err := prompt.GetAuthDataChallenge()
			if err != nil {
				return nil, err
			}

			f := huh.NewInput().
				Title("Server challenge").
				Description(challenge.Challenge).
				Placeholder(challenge.DefaultResult).
				Accessor(&results[i]).
				CharLimit(64)
			switch challenge.EchoPrompt {
			case sasl.NoEchoPrompt:
				f.EchoMode(huh.EchoModeNone)
			case sasl.EchoPromptPassword:
				f.EchoMode(huh.EchoModePassword)
			}
			fields[i] = f
		case sasl.PromptDataTypeRealm:
			realm, err := prompt.GetAuthDataRealm()
			if err != nil {
				return nil, err
			}
			s := huh.NewSelect[string]().
				Title("Realm").
				Description("The realm to which you are authenticating").
				Accessor(&results[i])

			opts := make([]huh.Option[string], len(realm.AvailableRealms))
			for i, realm := range realm.AvailableRealms {
				opts[i] = huh.Option[string]{
					Key:   realm,
					Value: realm,
				}
			}
			s.Options(opts...)
			fields[i] = s
		}
	}

	return fields, nil
}
