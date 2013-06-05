package goradius

import (
	"encoding/json"
	"fmt"
	"github.com/alouca/goconfig"
	"github.com/alouca/gologger"
	"io/ioutil"
	"net"
)

var (
	l *logger.Logger
	c *config.Config

	// Various Maps necessary for Marshalling/unmarshalling data
	radiusMap  map[int]RadiusDictionary
	vendorMap  map[int]VendorDictionary
	parserMap  map[string]ContentParser
	marshalMap map[string]MarshalHelper
)

// Radius Content Parser Function Signature
type ContentParser func([]byte, *RadiusPacket) interface{}

// Marshaller signature
type MarshalHelper func(AttributeValuePair, *RadiusPacket) []byte

// Radius Shared-Secret Provider Signature
type SharedSecretProvider func(string) string

/*
 * Dictionary Structure Definitions
 */

// RADIUS Dictionary (RFC2865 + RFC2866)
type RadiusDictionary struct {
	Attribute   int
	Name        string
	ContentType string
}

// Vendor-Specific Attribute Dictionary
type VendorDictionary struct {
	VendorID int
	Name     string
	TLVs     []TLV
	TLVMap   map[int]TLV
}

// Type-Length-Value Structure
type TLV struct {
	Type        uint8
	Name        string
	ContentType string
}

type GoRadius struct {
	SharedSecret SharedSecretProvider
	conn         *net.UDPConn
}

/*
 * Create a new RADIUS parser, providing the RADIUS & Vendor-Specific TLV Dictionary JSON files.
 * Option to enable debug & verbose output to aid in troubleshooting
 */
func NewGoRadius(radDictFile, vendorDictFile string, debug, verbose bool) *GoRadius {
	l = logger.CreateLogger(verbose, debug)

	radDict, err := ioutil.ReadFile(radDictFile)
	if err != nil {
		l.Fatal("Unable to read RADIUS Dictionary file: %s\n", err.Error())
		return nil
	}

	vendorDict, err := ioutil.ReadFile(vendorDictFile)
	if err != nil {
		l.Fatal("Unable to read Vendor Dictionary file: %s\n", err.Error())
		return nil
	}

	var vendorData []VendorDictionary
	var radiusData []RadiusDictionary

	// Parse dictionaries
	err = json.Unmarshal(vendorDict, &vendorData)
	if err != nil {
		l.Fatal("Unable to unmarshal JSON Vendor Dictionary: %s\n", err.Error())
		return nil
	}
	err = json.Unmarshal(radDict, &radiusData)
	if err != nil {
		l.Fatal("Unable to unmarshal JSON RADIUS Dictionary: %s\n", err.Error())
		return nil
	}

	r := new(GoRadius)
	radiusMap = make(map[int]RadiusDictionary)
	vendorMap = make(map[int]VendorDictionary)

	// Register default-parsers
	parserMap = map[string]ContentParser{
		"VSA":              VendorParser,
		"IP":               IPParser,
		"Acct-Status-Type": AcctStatusTypeParser,
		"uint16":           ParseUint16,
		"uint32":           ParseUint32,
		"string":           ParseString,
		"userpassword":     ParseUserPassword,
		"uvarint":          ParseUvarint,
		"fallback":         FallbackParser,
	}

	marshalMap = map[string]MarshalHelper{
		"string": StringMarshaller,
	}

	// Load dictionaries

	for _, attr := range radiusData {
		radiusMap[attr.Attribute] = attr
	}

	for _, vsa := range vendorData {
		vsa.TLVMap = make(map[int]TLV)
		for _, tlv := range vsa.TLVs {
			vsa.TLVMap[int(tlv.Type)] = tlv
		}

		vendorMap[vsa.VendorID] = vsa
	}

	return r
}

func (r *GoRadius) SendPacket(p *RadiusPacket) error {
	rawPacket := p.Marshal()

	r.SendRawPacket(rawPacket, p.Originator)
	l.Debug("Sent response to %s (Data len: %d)\n", p.Originator.String(), len(rawPacket))
	return nil
}

func (r *GoRadius) SendRawPacket(data []byte, dest *net.UDPAddr) error {
	if r.conn != nil {
		n, err := r.conn.WriteToUDP(data, dest)
		if err != nil {
			fmt.Errorf("Error writing to destination: %s\n", err.Error())
		} else {
			l.Debug("Wrote %d bytes to destination %s\n", n, dest.String())
			return nil
		}
	}
	return fmt.Errorf("No UDP Server started\n")
}

// Registers a new AVP Parser
func RegisterParser(name string, parser ContentParser) error {
	if _, ok := parserMap[name]; ok {
		return fmt.Errorf("Parser with name %s is already registered\n", name)
	}

	if parser == nil {
		return fmt.Errorf("Parser function cannot be null\n")
	}

	parserMap[name] = parser

	return nil
}

func (r *GoRadius) StartUDPServer(port int, ssp SharedSecretProvider) (chan *RadiusPacket, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, fmt.Errorf("Unable to resolve UDP Address: %s\n", err.Error())
	}

	conn, err := net.ListenUDP("udp", udpAddr)

	if err != nil {
		return nil, fmt.Errorf("Error on listen: %s\n", err.Error())
	}

	r.SharedSecret = ssp

	r.conn = conn

	c := make(chan *RadiusPacket, 10000)

	go func() {
		for {
			b := make([]byte, 1500)

			n, raddr, err := conn.ReadFromUDP(b)

			if err != nil {
				l.Error("Error reading data: %s\n", err.Error())
			} else {
				l.Debug("Read %d bytes from %s\n", n, raddr.IP.String())

				go func() {
					data := r.ParseRadiusPacket(raddr, b[0:n])
					l.Debug("Parsed total of %d AVPs\n", len(data.AVPS))
					c <- data
				}()
			}
		}
	}()

	return c, nil
}

// RADIUS Packet Parser
// Returns an array of parsed Attribute-Value Pairs
func (r *GoRadius) ParseRadiusPacket(source *net.UDPAddr, data []byte) *RadiusPacket {
	p := new(RadiusPacket)

	p.Raw = data

	p.Originator = source
	// Parse the header

	// First byte is the Code
	l.Debug("Packet Code: %d\n", uint(data[0]))
	p.Code = uint(data[0])

	// Set string packet code
	if packetCode, ok := packetCodes[p.Code]; ok {
		p.PacketType = packetCode
	} else {
		p.PacketType = "Unknown"
	}

	// Second byte is the Identifier
	l.Debug("Packet Identifier: %d\n", uint(data[1]))
	p.PacketId = uint(data[1])

	// Find the packet length
	pl := uint16(data[2])<<8 | uint16(data[3])

	l.Debug("Packet length: %d\n", pl)

	if int(pl) != len(data) {
		l.Fatal("Packet length and provided data do not match %d vs %d", int(pl), len(data))
	}

	p.Authenticator = data[4:20]
	l.Debug("Authenticator: %x\n", p.Authenticator)

	// Get the shared-secret from provided call-back
	p.SharedSecret = r.SharedSecret(source.IP.String())

	// start decoding AVPs from byte 20
	cursor := 20

	pairs := make([]AttributeValuePair, 0, 10)

	for cursor < len(data) {
		avpType := uint8(data[cursor])
		cursor++
		avpLength := uint8(data[cursor])
		cursor++

		//fmt.Printf("AVP Length: %d\n", avpLength)
		read := int(avpLength) + cursor - 2

		avpContent := data[cursor:read]
		cursor += int(avpLength) - 2

		var parsedContent interface{}
		var name, ctype string

		if avp, ok := radiusMap[int(avpType)]; ok {
			// Parse the content
			parser := parserMap[avp.ContentType]
			l.Debug("Type: %s(%d), Length: %d, Content-Type: %s\n", avp.Name, avpType, avpLength, avp.ContentType)
			parsedContent = parser(avpContent, p)
			name = avp.Name
			ctype = avp.ContentType

		} else {
			l.Debug("Unknown Type %d, Length %d\n", avpType, avpLength)
			parser := parserMap["fallback"]
			name = "unknown"
			ctype = "fallback"
			parsedContent = parser(avpContent, p)
		}

		pairs = append(pairs, AttributeValuePair{name, ctype, avpLength, parsedContent})

	}

	p.AVPS = pairs
	return p
}

// parseInt64 treats the given bytes as a big-endian, signed integer and
// returns the result.
func parseInt64(bytes []byte) (ret int64, err error) {
	if len(bytes) > 8 {
		// We'll overflow an int64 in this case.
		err = fmt.Errorf("integer too large")
		return
	}
	for bytesRead := 0; bytesRead < len(bytes); bytesRead++ {
		ret <<= 8
		ret |= int64(bytes[bytesRead])
	}

	// Shift up and down in order to sign extend the result.
	ret <<= 64 - uint8(len(bytes))*8
	ret >>= 64 - uint8(len(bytes))*8
	return
}

func Uvarint(buf []byte) (x uint64) {
	for i, b := range buf {
		x = x<<8 + uint64(b)
		if i == 7 {
			return
		}
	}
	return
}

func HelperParseUint16(content []byte) int {
	number := uint8(content[1]) | uint8(content[0])<<8
	//fmt.Printf("\t%d\n", number)

	return int(number)
}
