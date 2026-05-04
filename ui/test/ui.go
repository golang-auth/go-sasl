package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"

	imap "github.com/emersion/go-imap/v2/imapclient"
	"github.com/golang-auth/go-sasl"
	"github.com/golang-auth/go-sasl/ui"
)

var key = `
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCLshMYrLnvQ4Xd
xTV/6QcG4OszISusAljsQfD0wnk4DAg6eXOl6+N2TaHqg0UxX13A7iaVSnfRAyi1
pvyfU8wwUgqo63wJ4g3IwmG08QBSr/WeLEC6XwrApBKVq6ciWijp0V/7avLWjTZ3
MkowEiOldbT/Z45jg6RyEJiTcJr1aOlwn9zHX1/l/hsgflq6XTZhjYSHefjLVen9
Yfq1+Gb9rwUTTDTp/hjmjj5QP0vQ5ResildjMq/zKOJ0r8iLJX/IMTPruWCs6YHG
5Ymi9dPGKZQnAP5hS50nvVlQz4F+xzjiQrOR28Z7GnSnJk69XiA+rk2X0G85rPxm
rgiWW5lBAgMBAAECggEACkNwEb0HACQ23p9Rme81+/Rkc2I5gi6998W0fVcYbty7
cghgTc1x7cwwXDl+yOzXx4f3v7oz6WBRCl+VaeNPOjGc5OJAP72jA5/8a73VJz4U
TqWzr72x3Ytwbhypb+Wt4dfnNGKcKtU/Liy8tKFwiwSF4snp9TfDyjmb7CE20Vbj
GWui9OnmbD8m1sW0/C5gVInLaJn6HIbpYG2jUQLPTUOD0i6bbR4bW1YQ+uiiAF5L
QQVsldVwj6MM0mcbEX6FXYAR9qOsWl70WtL11tk2aIphiJM5BK2hzNr0aQW29e1U
orkZQuALBfCYeTDnx8aW5d8OiGV23CCUi2tg8ND+UQKBgQDEDydF7uc4SXh/RbFY
tx803p44YbeoFHC6Y6dWqviRqEWu27nlduKQhQJ5XuxA7RzPt6v1IVJpt9AGrWIw
PstRIqtptUUKxPxCoL3Vbehz7UJe9tM6q5XDTVJ2XhL6W6m6eepczYYdYW/oN1Op
pM2WPknHsQYEEenj5TYM0F35nQKBgQC2Z4vQ0lzcsOhV8aI4nw5XRlFJkwze9oj/
yP5xSXbOC7tDTkBLUTYyi69f34ixaMp7I8d9W9+dhzzDCB4lDZVq/X28q6d7mWHo
+hAP++UPXYNotaQwfsELODesIlB+OWB0Wyx6EkLze2hi+k2fQ7d5jGJf+B+UKz9r
BW8IQd+u9QKBgBdIkWptt8nod8XtmeUmQi9+LJ4XhL8SRlzsTsgtH730lOnyMD5/
AuMU2LlfO4FuZ1iHwIUpAueJK8xPNPTz0CN/kYnJPDzOLgMfocvB9LQnvhUXDPjP
vcZm3V8vRuOylRKPPfTtd3rvwmF6iJYB+2RXW126uTMsiXFGHEgjSrXFAoGAQuio
uOjxd2LNVvlT8EEoGYuJtdtjFUaJ6onoC9ZO5jYXcxD5NKeNoezrX9e3ZJxz6ceu
HaXd2QMKnuATbrQU4zIpNVQiE4yoBbX0vmhAFerPkVFP8RoN5fexNEtCC4swfn4T
SpP4Sygxml0GrC1C2CtOyrVRoCBdGvzbRcQkMSECgYANgf6iB/1qM5Bb+K4otJUl
0QdSdc48/OQ2x2E6BUH6BjCMdvEuU/oJYls7Vje0cDsLwiJX5REs3Z8bPF8x9L3O
1MrlYQF+910ahZ8lb+zkGGza6NFkEPIlHDpQqSHhIMW6DEo+RIzHP4NrzEHayXnX
7Q709XxFvuQkvdfYIiE3dA==
-----END PRIVATE KEY-----
`

var cert = `
-----BEGIN CERTIFICATE-----
MIIDhTCCAm2gAwIBAgIUGTWrc69oqgOcKVwjF3Gmx5rJmNAwDQYJKoZIhvcNAQEL
BQAwUjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5ZMREwDwYDVQQHDAhOZXcgWW9y
azEQMA4GA1UECgwHSmFrZSBDbzERMA8GA1UEAwwIZmVkb3Jhdm0wHhcNMjUxMjMw
MDA1NzA0WhcNMzUxMjI4MDA1NzA0WjBSMQswCQYDVQQGEwJVUzELMAkGA1UECAwC
TlkxETAPBgNVBAcMCE5ldyBZb3JrMRAwDgYDVQQKDAdKYWtlIENvMREwDwYDVQQD
DAhmZWRvcmF2bTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAIuyExis
ue9Dhd3FNX/pBwbg6zMhK6wCWOxB8PTCeTgMCDp5c6Xr43ZNoeqDRTFfXcDuJpVK
d9EDKLWm/J9TzDBSCqjrfAniDcjCYbTxAFKv9Z4sQLpfCsCkEpWrpyJaKOnRX/tq
8taNNncySjASI6V1tP9njmODpHIQmJNwmvVo6XCf3MdfX+X+GyB+WrpdNmGNhId5
+MtV6f1h+rX4Zv2vBRNMNOn+GOaOPlA/S9DlF6yKV2Myr/Mo4nSvyIslf8gxM+u5
YKzpgcbliaL108YplCcA/mFLnSe9WVDPgX7HOOJCs5HbxnsadKcmTr1eID6uTZfQ
bzms/GauCJZbmUECAwEAAaNTMFEwHQYDVR0OBBYEFNzKZQrHLQtm7Sm5chsJmTUb
UOcaMB8GA1UdIwQYMBaAFNzKZQrHLQtm7Sm5chsJmTUbUOcaMA8GA1UdEwEB/wQF
MAMBAf8wDQYJKoZIhvcNAQELBQADggEBAH9tSR3wtDXwVfackdU7MsTSrL/yQygS
umk3aN/ELJEvET99+Snnvpcf2RckTsipObLi/YcJdWmCXT19i9rychDF1pUziE7q
PFjNdJL0aYTdUi7mEarVdYdPWBMjDQkf1oC2OR0PAQw6lJ83mlGG+MPHn5tWSudD
lMV7hdskE5h/YLW04fxlNTAZIR/9YbiVCeRy3K77r/p8kBy4FTaxUNWp4qb299Pl
YCsLSxbRbjH+RInGOclTAAbtwQtFfKTWQc5B9InvAK6xtsh3yqZtUiCpxPoyW4w+
5IM7EHSN2vRkHrGncSz27dNA1t7/jrRBJlYiaJxl92UANmlc9QXCMbA=
-----END CERTIFICATE-----
`

func main() {

	certDer, _ := pem.Decode([]byte(cert))
	cert, err := x509.ParseCertificate(certDer.Bytes)
	if err != nil {
		log.Fatalf("failed to parse cert: %v", err)
	}

	keyDer, _ := pem.Decode([]byte(key))
	key, err := x509.ParsePKCS8PrivateKey(keyDer.Bytes)
	if err != nil {
		log.Fatalf("failed to parse key: %v", err)
	}

	imapOptions := imap.Options{
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			Certificates: []tls.Certificate{
				{
					Certificate: [][]byte{cert.Raw},
					PrivateKey:  key,
				},
			},
		},
	}

	imapClient, err := imap.DialStartTLS("fedoravm:1234", &imapOptions)
	if err != nil {
		log.Fatalf("failed to dial imap: %v", err)
	}

	saslOptions := []sasl.SaslOption{
		sasl.WithAuthzIDInteractive(),
		sasl.WithInteraction(ui.NewUI()),
	}

	saslClient, err := sasl.NewSaslClient("imap", saslOptions...)
	if err != nil {
		log.Fatalf("failed to create sasl client: %v", err)
	}

	err = imapClient.Authenticate(saslClient)
	if err != nil {
		log.Fatalf("failed to authenticate: %v", err)
	}

	fmt.Println("authenticated")
}
