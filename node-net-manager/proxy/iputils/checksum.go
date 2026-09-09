package iputils

import "encoding/binary"

// Internet checksums (RFC 1071/1624) are one's-complement 16-bit sums.
// Translating a packet only ever rewrites the source/destination address
// fields, never the payload, so there is no need to walk the payload and
// recompute a checksum from scratch: RFC 1624 gives an O(1) way to update an
// existing checksum for a field replacement:
//
//	HC' = ~(~HC + ~m + m')   (all additions are one's-complement, i.e. with
//	                          end-around carry)
//
// which generalizes to replacing several 16-bit words at once by summing
// ~m_i for every old word and m'_i for every new word before folding.
//
// The sum is accumulated 32 bits at a time rather than 16. RFC 1071 permits
// deferring the carries, and a 32-bit word's two halves land at different
// positions in the accumulator, so folding at the end is equivalent to having
// summed the halves separately - at a quarter of the loads.

// foldCarry reduces a deferred-carry accumulator to a 16-bit one's-complement
// sum. Deliberately unrolled rather than looping until it converges: the
// widest sum this package builds is 16 complemented 32-bit words plus a
// checksum (under 2^40), for which this fixed sequence always converges, and a
// data-dependent loop on the packet path buys nothing.
func foldCarry(sum uint64) uint16 {
	sum = (sum >> 32) + (sum & 0xffffffff)
	sum = (sum >> 16) + (sum & 0xffff)
	sum = (sum >> 16) + (sum & 0xffff)
	sum = (sum >> 16) + (sum & 0xffff)
	return uint16(sum)
}

// checksumAdjust applies the RFC 1624 incremental update to checksum (as
// stored on the wire, big-endian) for a field replacement whose delta - the
// deferred-carry sum of ~old and new over the replaced words - the caller has
// already accumulated. See addrDelta4/addrDelta16.
func checksumAdjust(checksum uint16, delta uint64) uint16 {
	return ^foldCarry(uint64(^checksum) + delta)
}

// addrDelta4 is the delta contributed by replacing one 4-byte address.
func addrDelta4(old []byte, new *[4]byte) uint64 {
	return uint64(^readUint32(old)) + uint64(readUint32(new[:]))
}

// addrDelta16 is the delta contributed by replacing one 16-byte address, read
// as four 32-bit words per side.
func addrDelta16(old []byte, new *[16]byte) uint64 {
	_ = old[15] // one bounds check up front instead of four
	return uint64(^readUint32(old[0:4])) + uint64(^readUint32(old[4:8])) +
		uint64(^readUint32(old[8:12])) + uint64(^readUint32(old[12:16])) +
		uint64(readUint32(new[0:4])) + uint64(readUint32(new[4:8])) +
		uint64(readUint32(new[8:12])) + uint64(readUint32(new[12:16]))
}

func readUint16(b []byte) uint16 {
	return binary.BigEndian.Uint16(b)
}

func writeUint16(b []byte, v uint16) {
	binary.BigEndian.PutUint16(b, v)
}

func readUint32(b []byte) uint32 {
	return binary.BigEndian.Uint32(b)
}
