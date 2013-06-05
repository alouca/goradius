package goradius

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
)

var (
	packetCodes map[uint]string = map[uint]string{
		1:   "Access-Request",
		2:   "Access-Accept",
		3:   "Access-Reject",
		4:   "Accounting-Request",
		5:   "Accounting-Response",
		6:   "Accounting-Status",
		7:   "Password-Request",
		8:   "Password-Ack",
		9:   "Password-Reject",
		10:  "Accounting-Message",
		11:  "Access-Challenge",
		12:  "Status-Server",
		13:  "Status-Client",
		28:  "Reserved",
		29:  "Next-Passcode",
		30:  "New-Pin",
		255: "Reserved",
	}
)

type RadiusPacket struct {
	Originator    *net.UDPAddr         // The origin IP address of the packet
	SharedSecret  string               // Shared Secret
	Code          uint                 // Packet Code
	PacketType    string               // Packet Type, based on Code
	PacketId      uint                 // Packet Identifier
	Authenticator []byte               // Authenticator Signature
	AVPS          []AttributeValuePair // A list of Attribute-value Pairs
	Raw           []byte               // A buffer with the original raw data
}

// Attribute-Value Pair structure
type AttributeValuePair struct {
	Name    string
	Type    string
	Length  uint8
	Content interface{}
}

func (p *RadiusPacket) String() string {
	return fmt.Sprintf("Radius Packet %s (%d) ID: %d - %d AVPs", p.PacketType, p.Code, p.PacketId, len(p.AVPS))
}

// Verifies the Authenticator Field if it matches our shared-secret
func (p *RadiusPacket) VerifyAuthenticator() bool {
	// Calculate the Request Authenticator Hash
	h := md5.New()
	h.Write(p.Raw[0:4])                                             // Code + Identifier + Length
	h.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) // 16 Zero Octets
	h.Write(p.Raw[20:])                                             // Request Attributes
	h.Write([]byte(p.SharedSecret))                                 // Shared-Secret, as retrieved by SharedSecret Callback
	ours := h.Sum(nil)

	// Loop & compare byte-by-byte
	for i := 0; i < 16; i++ {
		if p.Raw[4+i] != ours[i] {
			return false
		}
	}

	return true
}

func (p *RadiusPacket) Marshal() []byte {
	packetBuffer := make([]byte, 0, 1500)
	packet := bytes.NewBuffer(packetBuffer)

	// Write Packet Code & ID
	packet.WriteByte(byte(p.Code))
	packet.WriteByte(byte(p.PacketId))

	avpBuffer := make([]byte, 0, 1500)
	avps := bytes.NewBuffer(avpBuffer)

	if len(p.AVPS) > 0 {
		for _, avp := range p.AVPS {
			if m, ok := marshalMap[avp.Name]; ok {
				avpBytes := m(avp, p)
				avps.Write(avpBytes)
			} else {
				l.Debug("No Marshaller found for AVP %s (%d)\n", avp.Name, avp.Type)
			}
		}
	}
	var packetLen uint16 = 4 + 16 + uint16(avps.Len())
	// Write packet length
	l.Debug("AVPs Length: %d\n", avps.Len())
	binary.Write(packet, binary.BigEndian, packetLen)

	// If authenticator is empty, we assume that we'll be generating one
	if p.Authenticator == nil {
		l.Debug("Nil authenticator, generating one\n")
		// generate 16 random ints
		randInts := rand.Perm(16)
		p.Authenticator = make([]byte, 16)
		for i := 0; i < 16; i++ {
			p.Authenticator[0] = byte(randInts[i])
		}
	} else {
		// Calculate Response Authenticator
		h := md5.New()
		temp := packet.Bytes()
		h.Write(temp[0:4])
		h.Write(p.Authenticator)
		h.Write(avps.Bytes())
		io.WriteString(h, p.SharedSecret)
		p.Authenticator = h.Sum(nil)
	}

	packet.Write(p.Authenticator)
	packet.Write(avps.Bytes())

	return packet.Bytes()
}
