package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/miekg/dns"
)

var cfg *Config

// handler 处理每个进入的 DNS 查询：原样转发至平台，回传应答
func handler(w dns.ResponseWriter, req *dns.Msg) {
	resp := forward(req, cfg)

	if cfg.LogEnabled {
		q := req.Question
		qname := ""
		qtype := ""
		if len(q) > 0 {
			qname = q[0].Name
			qtype = dns.TypeToString[q[0].Qtype]
		}
		log.Printf("req qname=%s qtype=%s rcode=%d", qname, qtype, resp.Rcode)
	}

	// 原样回传应答（ID、EDNS0 等字段均不改动）
	if err := w.WriteMsg(resp); err != nil {
		log.Printf("回传应答失败: %v", err)
	}
}

func main() {
	configPath := flag.String("config", "config.yaml", "配置文件路径")
	flag.Parse()

	if _, err := os.Stat(*configPath); err != nil {
		fmt.Fprintf(os.Stderr, "找不到配置文件 %s（可复制 proxy.example.yaml 为 config.yaml 后修改）\n", *configPath)
		os.Exit(1)
	}

	var err error
	cfg, err = LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "配置加载失败: %v\n", err)
		os.Exit(1)
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(".", handler)

	addr := cfg.Listen()
	log.Printf("DNS 代理中间件启动，监听 %s，转发至平台 %s", addr, cfg.Upstream())

	// UDP 与 TCP 同时监听
	udpServer := &dns.Server{Addr: addr, Net: "udp", Handler: mux}
	tcpServer := &dns.Server{Addr: addr, Net: "tcp", Handler: mux}

	errCh := make(chan error, 2)
	go func() { errCh <- udpServer.ListenAndServe() }()
	go func() { errCh <- tcpServer.ListenAndServe() }()

	// 任一服务异常退出即整体退出
	if err := <-errCh; err != nil {
		log.Fatalf("DNS 服务异常退出: %v", err)
	}
}
