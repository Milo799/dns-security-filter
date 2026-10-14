package main

import (
	"regexp"
	"strings"
	"testing"
)

// 版本戳（2026-10-14 部署事故防复发）：
// 生产曾安装"仓库里的旧预编译产物"——源码已含 ecs.go，二进制却是 8 个提交
// 之前编的，客户端 IP 长期为空且从外部无法察觉。现在二进制必须能自证版本，
// 且格式要稳定到可被 install-proxy.sh 用正则解析。

func TestVersionStringDefault(t *testing.T) {
	oldRev, oldTime := buildRev, buildTime
	defer func() { buildRev, buildTime = oldRev, oldTime }()

	buildRev, buildTime = "unknown", "unknown"
	s := versionString()
	if !strings.HasPrefix(s, "dns-proxy rev=") {
		t.Fatalf("前缀不符，部署脚本可能解析失败: %q", s)
	}
	if !strings.Contains(s, "rev=unknown") || !strings.Contains(s, "go=") {
		t.Fatalf("默认值形态不符: %q", s)
	}
}

func TestVersionStringStamped(t *testing.T) {
	oldRev, oldTime := buildRev, buildTime
	defer func() { buildRev, buildTime = oldRev, oldTime }()

	buildRev, buildTime = "49305c0", "2026-09-02T07:49:05Z"
	s := versionString()
	if !strings.Contains(s, "rev=49305c0") {
		t.Fatalf("注入的提交号未出现: %q", s)
	}
	if !strings.Contains(s, "built=2026-09-02T07:49:05Z") {
		t.Fatalf("注入的编译时间未出现: %q", s)
	}
	if !strings.Contains(s, "go=go1.") {
		t.Fatalf("Go 版本未出现: %q", s)
	}
}

func TestVersionStringParsableByScript(t *testing.T) {
	// 与 install-proxy.sh 的解析保持一致：rev=\S+
	re := regexp.MustCompile(`rev=(\S+)`)
	oldRev := buildRev
	defer func() { buildRev = oldRev }()

	buildRev = "deadbee"
	m := re.FindStringSubmatch(versionString())
	if m == nil || m[1] != "deadbee" {
		t.Fatalf("部署脚本解析不到提交号: %q", versionString())
	}
}
