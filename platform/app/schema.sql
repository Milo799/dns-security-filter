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
-- adapter_type: http（HTTP API） / dnsbl（DNS 黑名单，无 Key 开源源）
-- is_builtin: 1=平台内置开源源（seed 写入，开箱即用，禁止删除）
-- config: JSON 扩展字段（如 dnsbl 的 zone 自定义）
CREATE TABLE IF NOT EXISTS threatintel_api (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         VARCHAR NOT NULL UNIQUE,     -- 适配器名称，如 virustotal / spamhaus_zen
    adapter_type VARCHAR NOT NULL DEFAULT 'http',
    base_url     VARCHAR NOT NULL DEFAULT '',
    api_key      VARCHAR DEFAULT '',          -- 加密存储（TODO: 落库前 AES 加密）
    enabled      BOOLEAN NOT NULL DEFAULT 0,
    timeout_ms   INTEGER NOT NULL DEFAULT 2000,
    is_builtin   BOOLEAN NOT NULL DEFAULT 0,
    config       TEXT DEFAULT '',             -- JSON 扩展配置
    description  VARCHAR DEFAULT '',
    created_at   DATETIME NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at   DATETIME NOT NULL DEFAULT (datetime('now','localtime'))
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
    created_at    DATETIME NOT NULL DEFAULT (datetime('now','localtime')),
    must_change   BOOLEAN NOT NULL DEFAULT 0, -- 首次登录/初始密码强制改密标记（迭代 31）
    password_changed_at DATETIME              -- 最近一次改密时间（审计/展示）
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

-- 6.7 离线大名单（hagezi / StevenBlack 等恶意域名列表，导入本地离线匹配）
-- 与手工黑白名单（filter_list）分离：整源导入/替换/启停，不污染手工条目。
-- source: 来源 key（hagezi_ti / hagezi_ult / stevenblack / 自定义）
-- target: domain（当前主要形态；ip 预留，供未来 IP 大列表扩展）
CREATE TABLE IF NOT EXISTS threat_list (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    source     VARCHAR NOT NULL,              -- 来源 key
    value      VARCHAR NOT NULL,              -- 域名（小写无尾点）或 IP
    target     VARCHAR NOT NULL DEFAULT 'domain',
    enabled    BOOLEAN NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at DATETIME NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_threat_list       ON threat_list (source, enabled);
CREATE INDEX IF NOT EXISTS idx_threat_list_value ON threat_list (value);
-- 统计覆盖索引：source_stats() 的 GROUP BY 与 source_due() 的最近导入时间
-- 全部由该索引覆盖（无需回表），291 万行统计约 0.5s → 配合进程内缓存仅首次执行；
-- source_due 的 ORDER BY updated_at DESC LIMIT 1 直接 seek 索引段尾（毫秒级）。
CREATE INDEX IF NOT EXISTS idx_threat_list_stats ON threat_list (source, updated_at, enabled);

-- 查询量统计（Task #161）：DNS 进程内存计数周期落库（每日本地日期一行）。
-- /api/status 的"今日请求"优先读本表（filter_log 的 allows 受
-- allow_log_enabled 采样限制严重低估，本表为全量口径）。
CREATE TABLE IF NOT EXISTS dns_query_stats (
    date       VARCHAR PRIMARY KEY,            -- 本地日期 YYYY-MM-DD
    total      INTEGER NOT NULL DEFAULT 0,     -- 当日总请求数（全量）
    intercept  INTEGER NOT NULL DEFAULT 0,     -- 拦截（与 filter_log action 口径一致）
    remove_ip  INTEGER NOT NULL DEFAULT 0,     -- 剔除恶意 IP
    allow      INTEGER NOT NULL DEFAULT 0,     -- 放行（含白名单/检测放行/直通）
    updated_at DATETIME NOT NULL DEFAULT (datetime('now','localtime'))
);
