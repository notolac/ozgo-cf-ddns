package ipdetect

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

const (
	typeTXT   = 16
	classCHAO = 3
)

// whoami asks a Cloudflare resolver for the source address of the query
// (TXT whoami.cloudflare in the CHAOS class). The transport family decides
// which address comes back.
func whoami(ctx context.Context, v6 bool, server string) (netip.Addr, error) {
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}
	network := "udp4"
	if v6 {
		network = "udp6"
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, network, server)
	if err != nil {
		return netip.Addr{}, err
	}
	defer conn.Close()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(5 * time.Second)
	}
	_ = conn.SetDeadline(deadline)

	// A random query ID makes off-path spoofing of the answer harder.
	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return netip.Addr{}, err
	}
	id := binary.BigEndian.Uint16(idb[:])
	if _, err := conn.Write(buildQuery(id)); err != nil {
		return netip.Addr{}, err
	}
	buf := make([]byte, 1232)
	n, err := conn.Read(buf)
	if err != nil {
		return netip.Addr{}, err
	}
	txt, err := parseTXT(buf[:n], id)
	if err != nil {
		return netip.Addr{}, err
	}
	if len(txt) == 0 {
		return netip.Addr{}, errors.New("empty whoami answer")
	}
	return Parse(txt[0], v6)
}

// whoamiQuestion is the encoded question: whoami.cloudflare. TXT CH.
var whoamiQuestion = []byte("\x06whoami\x0acloudflare\x00\x00\x10\x00\x03")

func buildQuery(id uint16) []byte {
	// Header: ID, flags (RD), QDCOUNT=1, ANCOUNT=NSCOUNT=ARCOUNT=0.
	b := []byte{0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(b[0:2], id)
	return append(b, whoamiQuestion...)
}

// parseTXT extracts the TXT strings from a DNS response.
func parseTXT(msg []byte, id uint16) ([]string, error) {
	if len(msg) < 12 {
		return nil, errors.New("short DNS response")
	}
	if binary.BigEndian.Uint16(msg[0:2]) != id {
		return nil, errors.New("DNS response ID mismatch")
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	if flags&0x8000 == 0 {
		return nil, errors.New("DNS message is not a response")
	}
	if flags&0x0200 != 0 {
		return nil, errors.New("DNS response truncated")
	}
	if rcode := flags & 0x000f; rcode != 0 {
		return nil, fmt.Errorf("DNS rcode %d", rcode)
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	off := 12
	var err error
	for range qd {
		if off, err = skipName(msg, off); err != nil {
			return nil, err
		}
		off += 4
	}
	var out []string
	for range an {
		if off, err = skipName(msg, off); err != nil {
			return nil, err
		}
		if off+10 > len(msg) {
			return nil, errors.New("truncated DNS answer")
		}
		typ := binary.BigEndian.Uint16(msg[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		off += 10
		if off+rdlen > len(msg) {
			return nil, errors.New("truncated DNS rdata")
		}
		if typ == typeTXT {
			rd := msg[off : off+rdlen]
			for j := 0; j < len(rd); {
				l := int(rd[j])
				j++
				if j+l > len(rd) {
					return nil, errors.New("malformed TXT rdata")
				}
				out = append(out, string(rd[j:j+l]))
				j += l
			}
		}
		off += rdlen
	}
	return out, nil
}

func skipName(msg []byte, off int) (int, error) {
	for {
		if off >= len(msg) {
			return 0, errors.New("truncated DNS name")
		}
		l := int(msg[off])
		switch {
		case l == 0:
			return off + 1, nil
		case l&0xc0 == 0xc0:
			if off+2 > len(msg) {
				return 0, errors.New("truncated DNS name pointer")
			}
			return off + 2, nil
		case l&0xc0 != 0:
			return 0, errors.New("unsupported DNS label type")
		default:
			off += 1 + l
		}
	}
}
