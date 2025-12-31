package main

import (
	"fmt"
	"log"

	"github.com/golang-auth/go-sasl"
)

func main() {
	// prompts := sasl.MakeAllPrompts()

	// ui := ui.NewUI(prompts)
	// ui.Interact()

	// for _, prompt := range prompts {
	// 	fmt.Printf("prompt: %+v\n", prompt)
	// }

	saslClient, err := sasl.NewSaslClient("blurg",
		sasl.WithAuthzIDInteractive(),
	)
	if err != nil {
		log.Fatalf("failed to create sasl client: %v", err)
	}

	outToken, err := saslClient.Start([]string{"PLAIN"})
	if err != nil {
		log.Fatalf("failed to start sasl client: %v", err)
	}

	fmt.Printf("sasl client: %+v\n", saslClient)
}
