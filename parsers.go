package goradius

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"io"
)

/* Accounting Status Parser
 */
func AcctStatusTypeParser(b []byte, r *RadiusPacket) interface{} {
	// Assemble the uint from the content
	status := uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24
	var strStatus string

	switch status {
	case 1:
		strStatus = "Start"
	case 2:
		strStatus = "Stop"
	case 3:
		strStatus = "Interim-Update"
	case 4:
		strStatus = "Accounting-On"
	case 5:
		strStatus = "Accounting-Off"
	default:
		strStatus = "Unknown"
	}

	strStatus = fmt.Sprintf("%s(%d)", strStatus, status)

	//	fmt.Printf("\t%s\n", strStatus)

	return strStatus
}

type VSA struct {
	Name  string
	Value interface{}
}

// Parses vendor-specific attribute (VSA)
func VendorParser(avpContent []byte, rp *RadiusPacket) interface{} {
	var vendor uint32
	var vendorType, vendorLength uint8
	var vendorContent []byte

	// Vendor is 4 bytes
	vendor = uint32(avpContent[3]) | uint32(avpContent[2])<<8 | uint32(avpContent[1])<<16 | uint32(avpContent[0])<<24

	vendorType = uint8(avpContent[4])
	vendorLength = uint8(avpContent[5])

	var cont VSA

	// Fetch Vendor
	if v, ok := vendorMap[int(vendor)]; ok {
		if tlv, ok := v.TLVMap[int(vendorType)]; ok {
			l.Debug("\tVendor: %s(%d) - Type %s(%d) - Content-Type: %s - Length %d\n", v.Name, vendor, tlv.Name, vendorType, tlv.ContentType, vendorLength)
			vendorContent = avpContent[6:]

			// Parse the content
			parser := parserMap[tlv.ContentType]
			cont.Value = parser(vendorContent, rp)
			cont.Name = tlv.Name
		} else {
			l.Debug("\tVendor: %s(%d) - Type: Unknown(%d) - Length %d\n", v.Name, vendor, vendorType, vendorLength)
		}

	} else {
		l.Debug("\tUnknown vendor %d\n", vendor)
	}

	return cont
}

func FallbackParser(content []byte, r *RadiusPacket) interface{} {
	return content
}

func ParseUserPassword(content []byte, r *RadiusPacket) interface{} {
	if len(content) < 16 {
		l.Error("Error decoding password: too short\n")
		return nil
	}

	if len(content) > 128 {
		l.Error("Error decoding password: too long\n")
		return nil
	}

	if len(content)%16 != 0 {
		l.Error("Error decoding password: incorrect length\n")
		return nil

	}

	// Second XOR part is the Authenticator on first iteration
	secondPart := r.Authenticator
	retBuffer := make([]byte, 0, 128)
	ret := bytes.NewBuffer(retBuffer)

	for i := 0; i < len(content); i = i + 16 {
		h := md5.New()

		io.WriteString(h, r.SharedSecret)
		h.Write(secondPart)

		hash := h.Sum(nil)
		xor_result := make([]byte, 16)

		for j := 0; j < 16; j++ {
			xor_result[j] = content[i+j] ^ hash[j]

			if xor_result[j] == 0x00 {
				xor_result = xor_result[0:j]
				break
			}
		}
		ret.Write(xor_result)
		if len(content) > 16 {
			secondPart = content[i : i+16]
		}
	}

	return string(ret.Bytes())
}

// Parses IP Addresses
func IPParser(content []byte, r *RadiusPacket) interface{} {
	//	fmt.Printf("\tIP: %d.%d.%d.%d\n", content[0], content[1], content[2], content[3])
	return fmt.Sprintf("%d.%d.%d.%d", content[0], content[1], content[2], content[3])
}

// Parses UINT16
func ParseUint16(content []byte, r *RadiusPacket) interface{} {
	number := uint8(content[1]) | uint8(content[0])<<8
	//fmt.Printf("\t%d\n", number)

	return number
}

// Parses UINT32
func ParseUint32(content []byte, r *RadiusPacket) interface{} {
	number := uint32(content[3]) | uint32(content[2])<<8 | uint32(content[1])<<16 | uint32(content[0])<<24
	//fmt.Printf("\t%d\n", number)

	return number
}

func ParseUvarint(buf []byte, r *RadiusPacket) interface{} {
	var x uint64
	for i, b := range buf {
		x = x<<8 + uint64(b)
		if i == 7 {
			return x
		}
	}
	return x
}

// Parses Strings
func ParseString(content []byte, r *RadiusPacket) interface{} {
	str := string(content)
	//fmt.Printf("\t%s\n", str)

	return str
}
