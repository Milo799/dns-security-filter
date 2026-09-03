package main

import (
	"log"
	"net"

	"github.com/miekg/dns"
)

// injectEcs 在转发前把真实客户端源 IP 注入查询报文的 EDNS0
// Client Subnet（RFC 7871，option code 8）。
//
// 背景（Task #158，生产观察 2026-09-03）：平台提取客户端 IP 完全依赖
// 报文里的 ECS option，但现实链路里几乎没人发 ECS——
//   - Windows DNS 服务器转发器（条件转发器/转发器模式）不附加 ECS；
//   - 终端直接把 DNS 配到代理 IP 时，系统 stub resolver 也不发 ECS。
// 于是过滤日志的客户端 IP 恒为空。代理是链路上唯一同时知道"真实
// 客户端源 IP"和"上游是谁"的位置，由它注入 ECS 是标准做法（与
// 公网递归 resolver 接收上游转发时的行为一致）。
//
// 规则：
//   - 请求已带 ECS：视为上游（如域控/上级转发器）已注入，透传不改写；
//   - 无 ECS：附加 option，source = 客户端 IP，源前缀 /32（IPv4）或
//     /128（IPv6），scope 0——只携带单终端精确地址，不聚合子网，
//     平台侧日志可见完整客户端 IP；
//   - 客户端 IP 解析失败（如 Unix socket 等无对端）：跳过注入，
//     平台仍按无 ECS 旧口径处理（client_ip 空，不影响过滤）。
//
// 注意：注入仅发生在代理→平台的转发报文里；应答原样回传，客户端
// 不会感知 OPT 差异（客户端请求若无 EDNS0，平台应答里的 OPT 属
// 正常 RFC 6891 行为，主流 resolver 均兼容）。
func injectEcs(req *dns.Msg, clientAddr net.Addr) {
	ip := peerIP(clientAddr)
	if ip == nil {
		return
	}

	// 已有 ECS：上游已注入，透传（不覆盖他人的客户端信息）
	if edns := req.IsEdns0(); edns != nil {
		for _, opt := range edns.Option {
			if ecs, ok := opt.(*dns.EDNS0_SUBNET); ok {
				_ = ecs // 存在即透传
				return
			}
		}
	}

	// 附加/复用 OPT RR 并写入 ECS option
	edns := req.IsEdns0()
	if edns == nil {
		edns = new(dns.OPT)
		edns.Hdr.Name = "."
		edns.Hdr.Rrtype = dns.TypeOPT
		req.Extra = append(req.Extra, edns)
	}
	var family = 1
	var srcBits uint8 = 32
	if ip.To4() == nil {
		family = 2
		srcBits = 128
	}
	ecs := new(dns.EDNS0_SUBNET)
	ecs.Code = dns.EDNS0SUBNET
	ecs.Family = uint16(family)
	ecs.SourceNetmask = srcBits
	ecs.Address = ip
	edns.Option = append(edns.Option, ecs)
}

// peerIP 从 UDP/TCP 连接对端地址提取 IP（nil = 提取失败，跳过注入）
func peerIP(addr net.Addr) net.IP {
	if addr == nil {
		return nil
	}
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP
	case *net.TCPAddr:
		return a.IP
	}
	// "ip:port" 字符串兜底
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	return net.ParseIP(host)
}

// ecsDebugLog 排障期打印注入结果（log_enabled 时每查询一行，方便核对）
func ecsDebugLog(enabled bool, req *dns.Msg, clientAddr net.Addr) {
	if !enabled {
		return
	}
	ip := peerIP(clientAddr)
	if ip == nil {
		log.Printf("ecs: skip (no peer ip)")
		return
	}
	if edns := req.IsEdns0(); edns != nil {
		for _, opt := range edns.Option {
			if ecs, ok := opt.(*dns.EDNS0_SUBNET); ok {
				log.Printf("ecs: passthrough existing source=%s/%d",
					ecs.Address, ecs.SourceNetmask)
				return
			}
		}
	}
	log.Printf("ecs: injected %s/%d", ip, map[bool]uint8{true: 32, false: 128}[ip.To4() != nil])
}
