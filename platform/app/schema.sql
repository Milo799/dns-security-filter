-- DNS 安全过滤平台 数据模型（PRD 第六章，6 张表）
-- SQLite 语法；AI 开发指引：字段与索引按此建表，业务代码不得改结构，
-- 如需扩展先评审 PRD。

-- 6.1 黑白名单
CREATE TABLE IF NOT EXISTS filter_list (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    list_type  VARCHAR NOT NULL,              -- blacklist / whitelist
    target     VARCHAR NOT NULL,              -- domain / ip
    value      VARCHAR NOT NULL,              -- 域名（含通配符）或 IP/CIDR
    enabled    BOOLEAN NOT NULL DEFAULT 1,
    remark     VARCHAR DEFAULT '',
    created_by VARCHAR DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at DATETIME NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_filter_list ON filter_list (list_type, target, enabled);

-- 6.2 威胁情报源配置
CREATE TABLE IF NOT EXISTS threatintel_api (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       VARCHAR NOT NULL UNIQUE,       -- 适配器名称，如 virustotal
    base_url   VARCHAR NOT NULL,
    api_key    VARCHAR DEFAULT '',            -- 加密存储（TODO: 落库前 AES 加密）
    enabled    BOOLEAN NOT NULL DEFAULT 0,
    timeout_ms INTEGER NOT NULL DEFAULT 2000,
    created_at DATETIME NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at DATETIME NOT NULL DEFAULT (datetime('now','localtime'))
);

-- 6.3 过滤日志（被过滤内容记录，核心；字段见 PRD 5.5）
CREATE TABLE IF NOT EXISTS filter_log (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp      DATETIME NOT NULL DEFAULT (datetime('now','localtime')),
    client_ip      VARCHAR DEFAULT '',        -- 来自 EDNS0 Client Subnet，可能为空
    domain         VARCHAR NOT NULL,
    query_type     VARCHAR NOT NULL,          -- A / AAAA
    filter_reason  VARCHAR NOT NULL,          -- local_blacklist / threatintel:<策略>:<源列表> / ip_filter
    action         VARCHAR NOT NULL,          -- intercept / remove_ip
    malicious_ips  TEXT DEFAULT '',           -- 命中恶意 IP 明细，逗号分隔
    final_result   VARCHAR DEFAULT '',        -- alert_ip:<IP> / empty / remaining_ips:<列表>
    source_api     VARCHAR DEFAULT ''         -- 命中的威胁情报源名称
);
CREATE INDEX IF NOT EXISTS idx_log_timestamp ON filter_log (timestamp);
CREATE INDEX IF NOT EXISTS idx_log_client_ip ON filter_log (client_ip);
CREATE INDEX IF NOT EXISTS idx_log_domain    ON filter_log (domain);
CREATE INDEX IF NOT EXISTS idx_log_action    ON filter_log (action);

-- 6.4 管理员
CREATE TABLE IF NOT EXISTS admin_user (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      VARCHAR NOT NULL UNIQUE,
    password_hash VARCHAR NOT NULL,           -- bcrypt
    created_at    DATETIME NOT NULL DEFAULT (datetime('now','localtime'))
);

-- 6.5 系统配置（Key-Value，运行时可改）
CREATE TABLE IF NOT EXISTS system_config (
    key        VARCHAR PRIMARY KEY,
    value      VARCHAR NOT NULL,
    updated_at DATETIME NOT NULL DEFAULT (datetime('now','localtime'))
);

-- 6.6 操作审计
CREATE TABLE IF NOT EXISTS audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL DEFAULT (datetime('now','localtime')),
    operator  VARCHAR NOT NULL,
    action    VARCHAR NOT NULL,               -- list_create / detection_toggle / ...
    detail    TEXT DEFAULT ''                 -- 变更内容 JSON
);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log (timestamp);
