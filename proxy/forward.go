package main

import (
	"time"

	"github.com/miekg/dns"
)

// forward 将客户端查询原样转发至安全过滤平台，并返回其应答。
// 不做任何协议转换、不修改报文内容（含 EDNS0 OPT RR）。
// 平台不可用/超时时返回 SERVFAIL（RFC 1035 RCODE=2），
// 由 Windows DNS 侧人工切换转发器绕过。
func forward(req *dns.Msg, cfg *Config) *dns.Msg {
	client := &dns.Client{
		Net:     "udp",
		Timeout: time.Duration(cfg.ForwardTimeout) * time.Second,
		// 与客户端协商的 UDP 载荷上限保持一致（请求带 EDNS0 时由其 size 决定）
		UDPSize: 4096,
	}

	resp, _, err := client.Exchange(req, cfg.Upstream())
	if err != nil {
		return servfail(req)
	}

	// 平台应答过大（TC 置位）时，用 TCP 向平台重发一次，取完整应答
	if resp.Truncated {
		tcpClient := &dns.Client{
			Net:     "tcp",
			Timeout: time.Duration(cfg.ForwardTimeout) * time.Second,
		}
		if tcpResp, _, terr := tcpClient.Exchange(req, cfg.Upstream()); terr == nil {
			return tcpResp
		}
		// TCP 重试失败：回传带 TC 的应答，客户端会自行改用 TCP 重试
	}
	return resp
}

// servfail 构造 SERVFAIL 应答，保持与请求相同的 ID 与 Question
func servfail(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeServerFailure)
	return m
}
