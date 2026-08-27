package bgpmrt

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// MRT RFC 6396 Constants
const (
	MRT_TABLE_DUMP_V2 = 13

	// TABLE_DUMP_V2 Subtypes
	MRT_SUBTYPE_PEER_INDEX_TABLE   = 1
	MRT_SUBTYPE_RIB_IPV4_UNICAST   = 2
	MRT_SUBTYPE_RIB_IPV4_MULTICAST = 3
	MRT_SUBTYPE_RIB_IPV6_UNICAST   = 4
	MRT_SUBTYPE_RIB_IPV6_MULTICAST = 5
	MRT_SUBTYPE_RIB_GENERIC        = 6

	// BGP Path Attribute Types (RFC 4271)
	BGP_ATTR_ORIGIN    = 1
	BGP_ATTR_AS_PATH   = 2
	BGP_ATTR_NEXT_HOP  = 3
	BGP_ATTR_MED       = 4
	BGP_ATTR_COMMUNITY = 8
	BGP_ATTR_AS4_PATH  = 17

	// AS_PATH Segment Types
	AS_SET             = 1
	AS_SEQUENCE        = 2
	AS_CONFED_SEQUENCE = 3
	AS_CONFED_SET      = 4
)

// BGPRecord stores the routing information associated with a prefix.
type BGPRecord struct {
	Prefix    string
	OriginASN string
	ASPath    string
}

type bgpTrieNode struct {
	children [2]*bgpTrieNode
	entry    *BGPRecord
}

// BGPRadixTree provides fast Longest Prefix Match (LPM) for IPv4 and IPv6 routes.
type BGPRadixTree struct {
	root4      *bgpTrieNode
	root6      *bgpTrieNode
	totalCount int
}

func NewBGPRadixTree() *BGPRadixTree {
	return &BGPRadixTree{
		root4: &bgpTrieNode{},
		root6: &bgpTrieNode{},
	}
}

// Insert inserts a route entry for a given prefix into the tree.
func (t *BGPRadixTree) Insert(prefix netip.Prefix, record *BGPRecord) {
	addr := prefix.Addr()
	bits := prefix.Bits()

	var root *bgpTrieNode
	if addr.Is4() {
		root = t.root4
	} else {
		root = t.root6
	}

	curr := root
	rawBytes := addr.AsSlice()

	for i := 0; i < bits; i++ {
		byteIdx := i / 8
		bitIdx := 7 - (i % 8)
		bit := (rawBytes[byteIdx] >> bitIdx) & 1

		if curr.children[bit] == nil {
			curr.children[bit] = &bgpTrieNode{}
		}
		curr = curr.children[bit]
	}

	if curr.entry == nil {
		t.totalCount++
	}
	curr.entry = record
}

// Lookup performs a zero-allocation Longest Prefix Match (LPM) for an IP address.
func (t *BGPRadixTree) Lookup(ip net.IP) *BGPRecord {
	if ip == nil {
		return nil
	}

	// Convert to netip.Addr
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return nil
	}
	addr = addr.Unmap()

	var curr *bgpTrieNode
	var maxBits int
	if addr.Is4() {
		curr = t.root4
		maxBits = 32
	} else {
		curr = t.root6
		maxBits = 128
	}

	var bestMatch *BGPRecord
	rawBytes := addr.AsSlice()

	for i := 0; i < maxBits; i++ {
		if curr.entry != nil {
			bestMatch = curr.entry
		}

		byteIdx := i / 8
		bitIdx := 7 - (i % 8)
		bit := (rawBytes[byteIdx] >> bitIdx) & 1

		if curr.children[bit] == nil {
			break
		}
		curr = curr.children[bit]
	}

	if curr != nil && curr.entry != nil {
		bestMatch = curr.entry
	}

	return bestMatch
}

// TotalPrefixes returns the total number of prefixes loaded into the tree.
func (t *BGPRadixTree) TotalPrefixes() int {
	return t.totalCount
}

// MRTParser parses RFC 6396 MRT files and populates a BGPRadixTree.
type MRTParser struct {
	tree *BGPRadixTree
}

func NewMRTParser() *MRTParser {
	return &MRTParser{
		tree: NewBGPRadixTree(),
	}
}

// ParseFile parses an MRT file from disk, transparently handling gzip decompression if needed.
func (p *MRTParser) ParseFile(filePath string) (*BGPRadixTree, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open MRT file: %w", err)
	}
	defer f.Close()

	var r io.Reader = f
	// Check magic bytes for gzip
	var magic [2]byte
	if _, err := f.Read(magic[:]); err == nil {
		_, _ = f.Seek(0, io.SeekStart)
		if magic[0] == 0x1f && magic[1] == 0x8b {
			gzReader, err := gzip.NewReader(f)
			if err != nil {
				return nil, fmt.Errorf("failed to initialize gzip reader: %w", err)
			}
			defer gzReader.Close()
			r = gzReader
		}
	} else {
		_, _ = f.Seek(0, io.SeekStart)
	}

	return p.Parse(r)
}

// Parse parses MRT stream records from an io.Reader.
func (p *MRTParser) Parse(r io.Reader) (*BGPRadixTree, error) {
	headerBuf := make([]byte, 12)

	for {
		_, err := io.ReadFull(r, headerBuf)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			return nil, fmt.Errorf("error reading MRT header: %w", err)
		}

		mrtType := binary.BigEndian.Uint16(headerBuf[4:6])
		mrtSubtype := binary.BigEndian.Uint16(headerBuf[6:8])
		mrtLength := binary.BigEndian.Uint32(headerBuf[8:12])

		recordBuf := make([]byte, mrtLength)
		if _, err := io.ReadFull(r, recordBuf); err != nil {
			return nil, fmt.Errorf("error reading MRT body: %w", err)
		}

		if mrtType == MRT_TABLE_DUMP_V2 {
			p.parseTableDumpV2(mrtSubtype, recordBuf)
		}
	}

	return p.tree, nil
}

func (p *MRTParser) parseTableDumpV2(subtype uint16, data []byte) {
	switch subtype {
	case MRT_SUBTYPE_RIB_IPV4_UNICAST, MRT_SUBTYPE_RIB_IPV4_MULTICAST:
		p.parseRIBEntries(data, 4)
	case MRT_SUBTYPE_RIB_IPV6_UNICAST, MRT_SUBTYPE_RIB_IPV6_MULTICAST:
		p.parseRIBEntries(data, 6)
	}
}

func (p *MRTParser) parseRIBEntries(data []byte, ipVersion int) {
	if len(data) < 5 {
		return
	}

	// 4 bytes sequence number
	offset := 4
	prefixLen := int(data[offset])
	offset++

	prefixBytesCount := (prefixLen + 7) / 8
	if offset+prefixBytesCount > len(data) {
		return
	}

	var ipBytes []byte
	if ipVersion == 4 {
		ipBytes = make([]byte, 4)
	} else {
		ipBytes = make([]byte, 16)
	}
	copy(ipBytes, data[offset:offset+prefixBytesCount])
	offset += prefixBytesCount

	addr, ok := netip.AddrFromSlice(ipBytes)
	if !ok {
		return
	}
	prefix, err := addr.Prefix(prefixLen)
	if err != nil {
		return
	}

	if offset+2 > len(data) {
		return
	}
	entryCount := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	// We parse the first valid RIB entry (best path)
	for i := 0; i < entryCount; i++ {
		if offset+8 > len(data) {
			break
		}
		// Peer Index (2) + Originated Time (4) + Attr Length (2)
		attrLength := int(binary.BigEndian.Uint16(data[offset+6 : offset+8]))
		offset += 8

		if offset+attrLength > len(data) {
			break
		}

		attrData := data[offset : offset+attrLength]
		offset += attrLength

		asPath, originASN := parseBGPAttributes(attrData)
		if len(asPath) > 0 || len(originASN) > 0 {
			rec := &BGPRecord{
				Prefix:    prefix.String(),
				OriginASN: originASN,
				ASPath:    asPath,
			}
			p.tree.Insert(prefix, rec)
			break // First path parsed
		}
	}
}

func parseBGPAttributes(data []byte) (asPath string, originASN string) {
	offset := 0
	for offset < len(data) {
		if offset+2 > len(data) {
			break
		}
		flags := data[offset]
		attrType := data[offset+1]
		offset += 2

		var attrLen int
		if flags&0x10 != 0 { // Extended length
			if offset+2 > len(data) {
				break
			}
			attrLen = int(binary.BigEndian.Uint16(data[offset : offset+2]))
			offset += 2
		} else {
			if offset+1 > len(data) {
				break
			}
			attrLen = int(data[offset])
			offset++
		}

		if offset+attrLen > len(data) {
			break
		}

		val := data[offset : offset+attrLen]
		offset += attrLen

		if attrType == BGP_ATTR_AS_PATH || attrType == BGP_ATTR_AS4_PATH {
			asPath, originASN = parseASPath(val)
		}
	}
	return asPath, originASN
}

func parseASPath(data []byte) (asPath string, originASN string) {
	offset := 0
	var asList []string

	for offset < len(data) {
		if offset+2 > len(data) {
			break
		}
		segType := data[offset]
		segLen := int(data[offset+1])
		offset += 2

		// Each ASN is 4 bytes in 32-bit AS mode (TABLE_DUMP_V2 default)
		// If data length indicates 2-byte ASNs, adapt
		asSize := 4
		if len(data[offset:]) == segLen*2 {
			asSize = 2
		}

		for i := 0; i < segLen; i++ {
			if offset+asSize > len(data) {
				break
			}
			var asn uint32
			if asSize == 4 {
				asn = binary.BigEndian.Uint32(data[offset : offset+4])
			} else {
				asn = uint32(binary.BigEndian.Uint16(data[offset : offset+2]))
			}
			offset += asSize

			asnStr := strconv.FormatUint(uint64(asn), 10)
			if segType == AS_SEQUENCE || segType == AS_SET {
				asList = append(asList, asnStr)
			}
		}
	}

	if len(asList) > 0 {
		asPath = strings.Join(asList, " ")
		originASN = asList[len(asList)-1]
	} else {
		asPath = "-"
		originASN = "-"
	}

	return asPath, originASN
}

// WriteSampleMRT creates a valid RFC 6396 MRT TABLE_DUMP_V2 stream containing specified routes.
// Useful for unit tests, benchmarks, and test fixtures.
func WriteSampleMRT(w io.Writer, routes []BGPRecord) error {
	for seq, r := range routes {
		prefix, err := netip.ParsePrefix(r.Prefix)
		if err != nil {
			return err
		}

		var body bytes.Buffer
		// Sequence number (4 bytes)
		_ = binary.Write(&body, binary.BigEndian, uint32(seq))
		// Prefix length (1 byte)
		_ = body.WriteByte(byte(prefix.Bits()))
		// Prefix bytes
		addrBytes := prefix.Addr().AsSlice()
		prefixBytesLen := (prefix.Bits() + 7) / 8
		_, _ = body.Write(addrBytes[:prefixBytesLen])

		// Entry count (uint16 = 1)
		_ = binary.Write(&body, binary.BigEndian, uint16(1))

		// RIB Entry: Peer Index (2) + Originated Time (4) + Attr Length (2) + Attrs
		var attrBuf bytes.Buffer
		// Encode AS_PATH attribute
		if len(r.ASPath) > 0 && r.ASPath != "-" {
			asTokens := strings.Fields(r.ASPath)
			var pathVal bytes.Buffer
			_ = pathVal.WriteByte(byte(AS_SEQUENCE))
			_ = pathVal.WriteByte(byte(len(asTokens)))
			for _, tok := range asTokens {
				asn, _ := strconv.ParseUint(tok, 10, 32)
				_ = binary.Write(&pathVal, binary.BigEndian, uint32(asn))
			}

			// BGP Attr Header: Flags(0x40 = Transitive), Type(2 = AS_PATH)
			_ = attrBuf.WriteByte(0x40)
			_ = attrBuf.WriteByte(byte(BGP_ATTR_AS_PATH))
			_ = attrBuf.WriteByte(byte(pathVal.Len()))
			_, _ = attrBuf.Write(pathVal.Bytes())
		}

		var ribEntry bytes.Buffer
		_ = binary.Write(&ribEntry, binary.BigEndian, uint16(0)) // Peer index
		_ = binary.Write(&ribEntry, binary.BigEndian, uint32(0)) // Originated time
		_ = binary.Write(&ribEntry, binary.BigEndian, uint16(attrBuf.Len()))
		_, _ = ribEntry.Write(attrBuf.Bytes())

		_, _ = body.Write(ribEntry.Bytes())

		// MRT Header: Timestamp (4) + Type (2) + Subtype (2) + Length (4)
		subtype := uint16(MRT_SUBTYPE_RIB_IPV4_UNICAST)
		if prefix.Addr().Is6() {
			subtype = uint16(MRT_SUBTYPE_RIB_IPV6_UNICAST)
		}

		var mrtHdr bytes.Buffer
		_ = binary.Write(&mrtHdr, binary.BigEndian, uint32(1700000000))
		_ = binary.Write(&mrtHdr, binary.BigEndian, uint16(MRT_TABLE_DUMP_V2))
		_ = binary.Write(&mrtHdr, binary.BigEndian, subtype)
		_ = binary.Write(&mrtHdr, binary.BigEndian, uint32(body.Len()))

		if _, err := w.Write(mrtHdr.Bytes()); err != nil {
			return err
		}
		if _, err := w.Write(body.Bytes()); err != nil {
			return err
		}
	}
	return nil
}
