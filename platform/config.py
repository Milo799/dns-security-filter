"""安全过滤平台配置加载（YAML + 默认值）。

字段与 PRD「八、配置项清单」保持一致。
"""

from dataclasses import dataclass, field, asdict
import os

import yaml

DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "platform.yaml")


@dataclass
class DnsConfig:
    listen_addr: str = "0.0.0.0"
    listen_port: int = 53


@dataclass
class WebConfig:
    listen_addr: str = "0.0.0.0"
    listen_port: int = 8080
    jwt_secret: str = "please-change-this-secret-to-random-32-bytes"  # 生产环境必须修改
    jwt_expire_minutes: int = 480          # 8 小时


@dataclass
class PlatformConfig:
    dns: DnsConfig = field(default_factory=DnsConfig)
    web: WebConfig = field(default_factory=WebConfig)
    database: str = "./data/platform.db"
    upstream_dns: str = "8.8.8.8"          # 公网 DNS（平台解析外网域名用）
    upstream_timeout_s: int = 3            # 上游单次查询超时（秒，1~10；Task #159 熔断联动）
    upstream_failure_threshold: int = 3    # 上游熔断：连续失败阈值（次，0=禁用；Task #159）
    upstream_open_timeout_s: int = 10      # 上游熔断：窗口时长（秒，窗口内 fast-fail SERVFAIL）
    alert_ip: str = "127.0.0.1"            # 告警 IP（A 记录拦截应答）
    alert_ttl: int = 60                    # 告警应答 TTL（秒）
    fusion_strategy: str = "any"           # 威胁情报融合策略：any / majority / all
    log_retention_days: int = 90           # 过滤日志保留天数
    allow_log_enabled: bool = False        # 放行日志开关
    allow_log_sample_rate: int = 100       # 放行日志采样率（%，0~100；前置项4）
    log_async_enabled: bool = True         # 日志异步批量写入开关（前置项5，排障可关）
    log_flush_interval_s: int = 2          # 异步日志 flush 间隔（秒，1~60）
    log_batch_size: int = 500              # 异步日志单批上限（条，100~50000）
    detection_enabled: bool = True         # 检测总开关
    api_timeout_ms: int = 2000             # 威胁情报源单次调用超时（毫秒）
    domain_cache_ttl_s: int = 300          # 域名检测结论缓存 TTL（秒，1~86400）
    domain_cache_size: int = 1_000_000     # 域名检测结论缓存容量上限（条）
    ip_cache_ttl_s: int = 900              # IP 检测结论缓存 TTL（秒，1~86400；IP 情报变化慢于域名可略长）
    ip_cache_size: int = 200_000           # IP 检测结论缓存容量上限（条）
    failsafe_mode: str = "intercept"       # fail-safe 模式：intercept 拦截 / degrade 降级放行
    cb_failure_threshold: int = 5          # 源级熔断：连续失败阈值（次，0=禁用）
    cb_open_timeout_s: int = 60            # 源级熔断：冷却时长（秒）
    degrade_threshold: int = 3             # 路径级降级：连续 fail-safe 阈值（次，0=禁用）
    degrade_window_s: int = 300            # 路径级降级：降级窗口时长（秒）
    threatlist_auto_update: bool = False   # 离线大名单自动更新开关
    threatlist_auto_interval_hours: int = 24  # 自动更新间隔（小时，1~720）
    http_proxy: str = ""                   # 情报出站代理（http://ip:port；空=直连。在线情报源查询+离线大名单下载统一走此代理；DNSBL 走 DNS 协议不经代理）
    admin_initial_password: str = "admin123"  # 首次初始化管理员密码（生产必须改）
    # --- 登录防爆破（迭代 31，Task #172；均可经 system_config 热生效） ---
    login_lockout_threshold: int = 5      # 账号闸：连续失败 N 次锁定（0=禁用）
    login_lockout_minutes: int = 15       # 账号闸：锁定时长（分钟）
    login_ip_threshold: int = 20          # IP 闸：窗口内累计失败 N 次（0=禁用）
    login_ip_window_minutes: int = 15     # IP 闸：滑动窗口时长（分钟）
    login_ip_block_minutes: int = 30      # IP 闸：封禁时长（分钟）

    def load(self, path: str = DEFAULT_CONFIG_PATH) -> "PlatformConfig":
        if not os.path.exists(path):
            return self
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        for key, value in data.items():
            if value is None:
                continue
            if key == "dns" and isinstance(value, dict):
                self.dns = DnsConfig(**{**asdict(self.dns), **value})
            elif key == "web" and isinstance(value, dict):
                self.web = WebConfig(**{**asdict(self.web), **value})
            elif hasattr(self, key):
                setattr(self, key, value)
        return self


CONFIG = PlatformConfig().load()
