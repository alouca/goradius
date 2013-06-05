package main

import (
	"../"
	"fmt"
)

func main() {
	r := goradius.NewGoRadius("../dict/radius-dict.json", "../dict/vendor-dict.json", true, true)

	if r == nil {
		fmt.Printf("Error initializing Radius: %s\n")
		return
	}

	avps, err := r.StartUDPServer(1812, SampleSharedSecret)
	acct, err := r.StartUDPServer(1813, SampleSharedSecret)

	if err != nil {
		fmt.Printf("Unable to start server: %s\n", err.Error())
		return
	}

	for {
		select {
		case p := <-avps:
			fmt.Printf("Got packet: %s\n", p.String())
			for _, avp := range p.AVPS {
				fmt.Printf("Received AVP %s %s %+v\n", avp.Name, avp.Type, avp.Content)
			}

			if p.PacketType == "Access-Request" {
				// Send a sample "Access-Accept" Response

				resp := new(goradius.RadiusPacket)
				resp.Code = uint(2)
				resp.PacketId = p.PacketId
				resp.Authenticator = p.Authenticator
				resp.SharedSecret = "testing123"
				resp.Originator = p.Originator

				r.SendPacket(resp)
			}
		case p := <-acct:
			fmt.Printf("Got Acct packet: %s\n", p.String())
			for _, avp := range p.AVPS {
				fmt.Printf("Received AVP %s %s %+v\n", avp.Name, avp.Type, avp.Content)
			}
			// Verify Authenticator
			verify := p.VerifyAuthenticator()

			if verify {
				fmt.Printf("Authentication Verified\n")
			} else {
				fmt.Printf("Packet Authentication Failed\n")
			}

			if p.PacketType == "Accounting-Request" {
				// Send a sample "Accounting-Response"

				resp := new(goradius.RadiusPacket)
				resp.Code = uint(5)                  // Accounting-Response
				resp.PacketId = p.PacketId           // Keep the original Packet ID
				resp.Authenticator = p.Authenticator // Set the Authenticator to the original hash
				resp.SharedSecret = "testing123"
				resp.Originator = p.Originator

				r.SendPacket(resp)
			}

		}
	}
}

func SampleSharedSecret(nas string) string {
	return "testing123"
}
