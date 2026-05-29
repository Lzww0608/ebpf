package rules

import (
	"net"
	"reflect"
	"testing"
)

func TestParseIPv4CIDRKeyCanonicalizesNetworkAddress(t *testing.T) {
	key, err := ParseIPv4CIDRKey("198.51.100.23/24")
	if err != nil {
		t.Fatalf("ParseIPv4CIDRKey returned error: %v", err)
	}

	want := IPv4LPMKey{
		Prefixlen: 24,
		Addr:      [4]byte{198, 51, 100, 0},
	}
	if key != want {
		t.Fatalf("key = %+v, want %+v", key, want)
	}
}

func TestParseIPv4CIDRKeyAcceptsSingleHost(t *testing.T) {
	key, err := ParseIPv4CIDRKey("203.0.113.7/32")
	if err != nil {
		t.Fatalf("ParseIPv4CIDRKey returned error: %v", err)
	}

	want := IPv4LPMKey{
		Prefixlen: 32,
		Addr:      [4]byte{203, 0, 113, 7},
	}
	if key != want {
		t.Fatalf("key = %+v, want %+v", key, want)
	}
}

func TestParseIPv4CIDRKeyRejectsIPv6(t *testing.T) {
	if _, err := ParseIPv4CIDRKey("2001:db8::/32"); err == nil {
		t.Fatal("ParseIPv4CIDRKey accepted IPv6 CIDR")
	}
}

func TestParseIPv4CIDRListTrimsAndSkipsEmptyItems(t *testing.T) {
	keys, err := ParseIPv4CIDRList(" 10.0.0.0/8, ,192.0.2.1/32 ")
	if err != nil {
		t.Fatalf("ParseIPv4CIDRList returned error: %v", err)
	}

	want := []IPv4LPMKey{
		{Prefixlen: 8, Addr: [4]byte{10, 0, 0, 0}},
		{Prefixlen: 32, Addr: [4]byte{192, 0, 2, 1}},
	}
	if !reflect.DeepEqual(keys, want) {
		t.Fatalf("keys = %+v, want %+v", keys, want)
	}
}

func TestIPv4LPMKeyString(t *testing.T) {
	key := IPv4LPMKey{Prefixlen: 16, Addr: [4]byte{172, 16, 0, 0}}
	if got, want := key.String(), "172.16.0.0/16"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}

func TestIPv4LPMKeyIP(t *testing.T) {
	key := IPv4LPMKey{Addr: [4]byte{198, 51, 100, 44}}
	if got, want := key.IP(), net.IPv4(198, 51, 100, 44).To4(); !got.Equal(want) {
		t.Fatalf("IP() = %v, want %v", got, want)
	}
}
