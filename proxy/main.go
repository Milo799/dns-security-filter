package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"

	"github.com/miekg/dns"
)

var cfg *Config

// 构建元信息：由 Makefile / deploy/install-proxy.sh 经 -ldflags 注入。
//
// 为什么需要（2026-10-14 部署事故复盘）：代理曾把"仓库里的旧预编译产物"
// 当成交付物装到生产——上线的是 49305c0 编译的二进制（缺 Task#158 客户端
// IP 注入），而源码早已更新到含 ecs.go 的版本，导致客户端 IP 长期恒为空，
// 且从二进制表面看不出来。现在二进制自带可自查的版本戳：
//
//	dns-proxy -version   → dns-proxy rev=49305c0 built=... go=...
//
// 部署脚本据此拒绝安装与源码不一致的产物（见 install-proxy.sh 第 3 步）。
var (
	buildRev  = "unknown" // 编译时的 git 提交短哈希（-X main.buildRev=...）
	buildTime = "unknown" // 编译时间 UTC（-X main.buildTime=...）
)

// versionString 返回单行版本信息（供 -version、启动日志与部署脚本解析）
func versionString() string {
	return fmt.Sprintf("dns-proxy rev=%s built=%s go=%s",
		buildRev, buildTime, runtime.Version())
}

// handler 处理每个进入的 DNS 查询：注入客户端 ECS（Task #158）后
// 转发至平台，回传应答
func handler(w dns.ResponseWriter, req *dns.Msg) {
	// Task #158：注入真实客户端源 IP（无 ECS 时附加 /32 或 /128；
	// 请求已带 ECS 则透传）。平台日志的客户端 IP 由此而来。
	if cfg.EcsEnabled {
		injectEcs(req, w.RemoteAddr())
		ecsDebugLog(cfg.LogEnabled, req, w.RemoteAddr())
	}

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
	showVersion := flag.Bool("version", false, "打印构建版本信息后退出")
	flag.Parse()

	// 版本自证：不读配置、不需要 root，供部署脚本核对"装的这份是不是当前源码编的"
	if *showVersion {
		fmt.Println(versionString())
		return
	}

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
	log.Printf("构建版本：%s", versionString())
	log.Printf("DNS 代理中间件启动，监听 %s，转发至平台 %s", addr, cfg.Upstream())
	// 客户端 IP 注入状态显式落日志：这项一旦静默失效，平台侧 client_ip
	// 全空却无任何报错（本次事故即如此），journalctl 一行即可判定
	log.Printf("客户端 IP 注入（EDNS0 ECS）：%s",
		map[bool]string{true: "已启用", false: "已关闭"}[cfg.EcsEnabled])

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
