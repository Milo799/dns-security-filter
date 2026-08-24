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
    alert_ip: str = "127.0.0.1"            # 告警 IP（A 记录拦截应答）
    alert_ttl: int = 60                    # 告警应答 TTL（秒）
    fusion_strategy: str = "any"           # 威胁情报融合策略：any / majority / all
    log_retention_days: int = 90           # 过滤日志保留天数
    allow_log_enabled: bool = False        # 放行日志开关
    detection_enabled: bool = True         # 检测总开关
    api_timeout_ms: int = 2000             # 威胁情报源单次调用超时（毫秒）
    admin_initial_password: str = "admin123"  # 首次初始化管理员密码（生产必须改）

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
