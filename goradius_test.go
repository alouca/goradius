package goradius

import (
	"testing"
)

func TestUDPServer(t *testing.T) {
	r := NewGoRadius("dict/radius-dict.json", "dict/vendor-dict.json", true, true)

	if r == nil {
		t.FailNow()
	}

	avps, err := r.StartUDPServer(1812, SampleSharedSecret)
	acct, err := r.StartUDPServer(1813, SampleSharedSecret)

	if err != nil {
		t.Fatalf("Unable to start server: %s\n", err.Error())
	}

	for {
		select {
		case p := <-avps:
			t.Logf("Got packet: %s\n", p.String())
			for _, avp := range p.AVPS {
				t.Logf("Received AVP %s %s %+v\n", avp.Name, avp.Type, avp.Content)
			}

			if p.PacketType == "Access-Request" {
				// Send a sample "Access-Accept" Response

				resp := new(RadiusPacket)
				resp.Code = uint(2)
				resp.PacketId = p.PacketId
				resp.Authenticator = p.Authenticator
				resp.SharedSecret = "testing123"
				resp.Originator = p.Originator

				r.SendPacket(resp)
			}
			return
		case p := acct:
			t.Logf("Got Acct packet: %s\n", p.String())
			for _, avp := range p.AVPS {
				t.Logf("Received AVP %s %s %+v\n", avp.Name, avp.Type, avp.Content)
			}

		}
	}
}

func SampleSharedSecret(nas string) string {
	return "testing123"
}
