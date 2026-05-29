package rules

import (
	"fmt"
	"net"
	"strings"
)

// IPv4LPMKey mirrors the BPF LPM trie key layout:
// struct { __u32 prefixlen; __u8 addr[4]; }.
type IPv4LPMKey struct {
	Prefixlen uint32
	Addr      [4]byte
}

func ParseIPv4CIDRList(raw string) ([]IPv4LPMKey, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}

	parts := strings.Split(raw, ",")
	keys := make([]IPv4LPMKey, 0, len(parts))
	for _, part := range parts {
		cidr := strings.TrimSpace(part)
		if cidr == "" {
			continue
		}

		key, err := ParseIPv4CIDRKey(cidr)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}

	return keys, nil
}

func ParseIPv4CIDRKey(cidr string) (IPv4LPMKey, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return IPv4LPMKey{}, err
	}

	ip4 := ipNet.IP.To4()
	if ip4 == nil {
		return IPv4LPMKey{}, fmt.Errorf("only IPv4 CIDR is supported: %s", cidr)
	}

	ones, bits := ipNet.Mask.Size()
	if bits != 32 {
		return IPv4LPMKey{}, fmt.Errorf("only IPv4 CIDR is supported: %s", cidr)
	}

	var key IPv4LPMKey
	key.Prefixlen = uint32(ones)
	copy(key.Addr[:], ip4)
	return key, nil
}

func (k IPv4LPMKey) IP() net.IP {
	return net.IPv4(k.Addr[0], k.Addr[1], k.Addr[2], k.Addr[3]).To4()
}

func (k IPv4LPMKey) String() string {
	return fmt.Sprintf("%s/%d", k.IP().String(), k.Prefixlen)
}
