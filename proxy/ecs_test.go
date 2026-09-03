package main

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func newQuery(t *testing.T, name string) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	return m
}

func getEcs(t *testing.T, req *dns.Msg) *dns.EDNS0_SUBNET {
	t.Helper()
	edns := req.IsEdns0()
	if edns == nil {
		return nil
	}
	for _, opt := range edns.Option {
		if ecs, ok := opt.(*dns.EDNS0_SUBNET); ok {
			return ecs
		}
	}
	return nil
}

func TestInjectEcs_NoExistingEcs_IPv4(t *testing.T) {
	req := newQuery(t, "example.com")
	addr := &net.UDPAddr{IP: net.ParseIP("172.16.3.45"), Port: 53531}
	injectEcs(req, addr)
	ecs := getEcs(t, req)
	if ecs == nil {
		t.Fatal("ECS option 未注入")
	}
	if ecs.Family != 1 {
		t.Errorf("Family = %d, want 1 (IPv4)", ecs.Family)
	}
	if ecs.SourceNetmask != 32 {
		t.Errorf("SourceNetmask = %d, want 32 (/32 精确客户端)", ecs.SourceNetmask)
	}
	if ecs.Address.String() != "172.16.3.45" {
		t.Errorf("Address = %s, want 172.16.3.45", ecs.Address)
	}
}

func TestInjectEcs_NoExistingEcs_IPv6(t *testing.T) {
	req := newQuery(t, "example.com")
	addr := &net.TCPAddr{IP: net.ParseIP("fd00::42"), Port: 53531}
	injectEcs(req, addr)
	ecs := getEcs(t, req)
	if ecs == nil {
		t.Fatal("ECS option 未注入")
	}
	if ecs.Family != 2 {
		t.Errorf("Family = %d, want 2 (IPv6)", ecs.Family)
	}
	if ecs.SourceNetmask != 128 {
		t.Errorf("SourceNetmask = %d, want 128 (/128 精确客户端)", ecs.SourceNetmask)
	}
}

func TestInjectEcs_ExistingEcsPassthrough(t *testing.T) {
	// 上级转发器已注入 ECS：不覆盖（透传）
	req := newQuery(t, "example.com")
	edns := new(dns.OPT)
	edns.Hdr.Name = "."
	edns.Hdr.Rrtype = dns.TypeOPT
	existing := new(dns.EDNS0_SUBNET)
	existing.Code = dns.EDNS0SUBNET
	existing.Family = 1
	existing.SourceNetmask = 24
	existing.Address = net.ParseIP("10.1.2.0")
	edns.Option = append(edns.Option, existing)
	req.Extra = append(req.Extra, edns)

	addr := &net.UDPAddr{IP: net.ParseIP("172.16.3.45"), Port: 53531}
	injectEcs(req, addr)

	ecs := getEcs(t, req)
	if ecs != existing {
		t.Fatal("已有 ECS 被覆盖（应透传）")
	}
	if ecs.SourceNetmask != 24 || ecs.Address.String() != "10.1.2.0" {
		t.Errorf("ECS 被改写: mask=%d addr=%s", ecs.SourceNetmask, ecs.Address)
	}
}

func TestInjectEcs_NilAddrSkips(t *testing.T) {
	req := newQuery(t, "example.com")
	injectEcs(req, nil)
	if getEcs(t, req) != nil {
		t.Fatal("无对端地址时不应注入")
	}
	if req.IsEdns0() != nil {
		t.Fatal("无对端地址时不应附加 OPT")
	}
}

func TestInjectEcs_PackRoundtrip(t *testing.T) {
	// 序列化/反序列化回环：平台侧 dnslib 按 RFC 7871 字节解析
	req := newQuery(t, "example.com")
	addr := &net.UDPAddr{IP: net.ParseIP("172.16.3.45"), Port: 53531}
	injectEcs(req, addr)

	packed, err := req.Pack()
	if err != nil {
		t.Fatalf("Pack 失败: %v", err)
	}
	parsed := new(dns.Msg)
	if err := parsed.Unpack(packed); err != nil {
		t.Fatalf("Unpack 失败: %v", err)
	}
	ecs := getEcs(t, parsed)
	if ecs == nil {
		t.Fatal("回环后 ECS 丢失")
	}
	if ecs.Address.String() != "172.16.3.45" || ecs.SourceNetmask != 32 {
		t.Errorf("回环后 ECS 损坏: addr=%s mask=%d", ecs.Address, ecs.SourceNetmask)
	}
}

func TestPeerIP(t *testing.T) {
	cases := []struct {
		addr net.Addr
		want string
	}{
		{&net.UDPAddr{IP: net.ParseIP("1.2.3.4")}, "1.2.3.4"},
		{&net.TCPAddr{IP: net.ParseIP("::1")}, "::1"},
		{nil, "<nil>"},
	}
	for _, c := range cases {
		got := peerIP(c.addr)
		if got == nil {
			if c.want != "<nil>" {
				t.Errorf("peerIP(%v) = nil, want %s", c.addr, c.want)
			}
			continue
		}
		if got.String() != c.want {
			t.Errorf("peerIP(%v) = %s, want %s", c.addr, got, c.want)
		}
	}
}
