package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config 代理中间件配置，对应 proxy.example.yaml
type Config struct {
	ListenAddr     string `yaml:"listen_addr"`      // 监听地址，默认 0.0.0.0
	ListenPort     int    `yaml:"listen_port"`      // 监听端口，默认 53
	UpstreamAddr   string `yaml:"upstream_addr"`    // 安全过滤平台地址（必填）
	UpstreamPort   int    `yaml:"upstream_port"`    // 平台端口，默认 53
	ForwardTimeout int    `yaml:"forward_timeout"`  // 转发超时（秒），默认 3
	LogEnabled     bool   `yaml:"log_enabled"`      // 代理运行日志开关，默认 false
	EcsEnabled     bool   `yaml:"ecs_enabled"`      // 客户端 IP 注入开关（Task #158），默认 true
}

// DefaultConfig 返回默认配置
func DefaultConfig() *Config {
	return &Config{
		ListenAddr:     "0.0.0.0",
		ListenPort:     53,
		UpstreamAddr:   "",
		UpstreamPort:   53,
		ForwardTimeout: 3,
		LogEnabled:     false,
		EcsEnabled:     true,
	}
}

// LoadConfig 从 YAML 文件加载配置，缺省字段用默认值
func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}

	// 校验
	if cfg.UpstreamAddr == "" {
		return nil, fmt.Errorf("配置缺少 upstream_addr（安全过滤平台地址）")
	}
	if cfg.ListenPort <= 0 || cfg.ListenPort > 65535 {
		return nil, fmt.Errorf("listen_port 非法: %d", cfg.ListenPort)
	}
	if cfg.UpstreamPort <= 0 || cfg.UpstreamPort > 65535 {
		return nil, fmt.Errorf("upstream_port 非法: %d", cfg.UpstreamPort)
	}
	if cfg.ForwardTimeout <= 0 {
		return nil, fmt.Errorf("forward_timeout 必须大于 0")
	}
	return cfg, nil
}

// UpstreamAddr 返回 "ip:port" 形式的平台地址
func (c *Config) Upstream() string {
	return fmt.Sprintf("%s:%d", c.UpstreamAddr, c.UpstreamPort)
}

// ListenAddr 返回 "ip:port" 形式的监听地址
func (c *Config) Listen() string {
	return fmt.Sprintf("%s:%d", c.ListenAddr, c.ListenPort)
}
