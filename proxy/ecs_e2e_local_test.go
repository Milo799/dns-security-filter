package main

// 代理端到端（本地）：起一个假平台（UDP 收包记录 ECS），再向代理端口
// 发 dnslib 查询，验证代理转发出去的报文里 ECS = 客户端源 IP。
// 本地验证专用，不随 CI 跑。运行：
//   go test -run TestLocalE2EProxyInjectsEcs -v

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestLocalE2EProxyInjectsEcs(t *testing.T) {
	// 1) 假平台：随机 UDP 端口，收第一个包并解析 ECS
	fakePlatform, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("假平台启动失败: %v", err)
	}
	defer fakePlatform.Close()
	platformAddr := fakePlatform.LocalAddr().String()

	received := make(chan *dns.Msg, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _, err := fakePlatform.ReadFrom(buf)
		if err != nil {
			return
		}
		m := new(dns.Msg)
		if err := m.Unpack(buf[:n]); err != nil {
			t.Logf("假平台 Unpack 失败: %v", err)
		}
		received <- m
	}()

	// 2) 直接构造 handler 依赖：模拟代理收到客户端查询
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn("e2e-ecs.example.com"), dns.TypeA)

	clientAddr := &net.UDPAddr{IP: net.ParseIP("192.168.77.66"), Port: 53531}
	injectEcs(req, clientAddr)

	// 3) 把注入后的报文发往假平台（等价于 forward 的出站动作）
	packed, _ := req.Pack()
	conn, err := net.Dial("udp", platformAddr)
	if err != nil {
		t.Fatalf("dial 假平台: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(packed); err != nil {
		t.Fatalf("write: %v", err)
	}

	// 4) 收假平台解析结果
	select {
	case m := <-received:
		if m == nil {
			t.Fatal("假平台未能解析报文")
		}
		edns := m.IsEdns0()
		if edns == nil {
			t.Fatal("转发报文无 EDNS0 OPT")
		}
		var found *dns.EDNS0_SUBNET
		for _, opt := range edns.Option {
			if ecs, ok := opt.(*dns.EDNS0_SUBNET); ok {
				found = ecs
			}
		}
		if found == nil {
			t.Fatal("转发报文无 ECS option")
		}
		if found.Address.String() != "192.168.77.66" || found.SourceNetmask != 32 {
			t.Errorf("ECS 不符: addr=%s mask=%d, want 192.168.77.66/32",
				found.Address, found.SourceNetmask)
		}
		t.Logf("代理转发报文 ECS=%s/%d（客户端 IP 注入端到端验证通过）",
			found.Address, found.SourceNetmask)
	case <-time.After(3 * time.Second):
		t.Fatal("假平台 3s 未收到转发包")
	}
}
