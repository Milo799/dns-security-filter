# DNS 安全过滤中间件 - Harness 工程

基于《Windows DNS 安全过滤中间件 开发PRD V1.2》搭建的开发骨架（monorepo）。
目的：让 AI 开发助手拿到即可开工，**最小可运行闭环已打通，剩余为按 TODO 填空**。

## 架构（三层）

```
Windows DNS（多台，仅配转发器，零安装）
   │ 外网域名请求（含 EDNS0 Client Subnet 透传客户端 IP）
   ▼
DNS 代理中间件（Go，独立部署，纯转发，无检测逻辑）
   │ 标准 DNS 协议（UDP/TCP 53）
   ▼
DNS 安全过滤平台（Python，监听 53）
   ├─ 域名前置检测（本地黑白名单 + 威胁情报多源融合）
   ├─ 公网解析 → IP 后置过滤
   ├─ 被过滤内容记录（filter_log）
   └─ Web 管理（FastAPI :8080）
```

平台故障时：在 Windows DNS 上人工修改转发器地址，改回公网 DNS 绕过（不做自动容错）。

## 目录结构

| 目录 | 内容 | 状态 |
|------|------|------|
| `proxy/` | Go 代理中间件（main/config/forward + 配置模板） | ✅ 已实现，可编译 |
| `platform/` | 平台：dns_server、detectors 主流程骨架、adapters、app(FastAPI+SQLite)、schema.sql、seed | 🟡 骨架 + TODO |
| `web/` | 管理前端 | ⬜ 待 AI 按 PRD 5.6 搭建 |
| `deploy/` | systemd unit ×3 + install.sh 骨架 | 🟡 骨架 |
| `scripts/` | dev.sh（一键启动）、verify.sh（dig 验证） | ✅ 已实现 |
| `tests/` | pytest 锚点（融合策略/拦截应答/建表/认证） | ✅ 通过中 |
| `docs/` | 需求说明书与 PRD（基准文档） | ✅ |

## 快速开始（Linux）

```bash
# 1. 平台依赖
cd platform && pip install -r requirements.txt

# 2. 初始化数据库（建表 + 默认管理员 admin/admin123）
python -m seed

# 3. 启动平台（DNS :53 + Web :8080）—— 生产用 systemd，开发可改端口调试
python dns_server.py &                 # DNS 服务
python -m uvicorn app.main:app --host 0.0.0.0 --port 8080 &   # Web

# 4. 构建并启动代理（Go 1.21+；53 端口需 root 或 CAP_NET_BIND_SERVICE）
cd proxy && cp proxy.example.yaml config.yaml && go build -o ../bin/dns-proxy .
./bin/dns-proxy -config config.yaml

# 5. 验证链路
dig @<代理IP> example.com A

# 6. 配置 Windows DNS 转发器指向 代理IP:53（外网域名），并禁用根提示
```

## 验收基准

| 命令 | 含义 |
|------|------|
| `make verify` | dig 经代理查询成功返回 IP（链路通） |
| `make test` | 全部锚点测试通过 |
| 拦截验证 | 白名单/黑名单/威胁情报配置后，`dig` 恶意域名返回告警 IP，日志可查 |

## 关键约束（开发必须遵守）

- 代理为**纯转发器**：不修改报文、不剥离 EDNS0（含 OPT RR）
- 平台**不缓存** DNS 记录；AAAA 与 A 同等过滤
- 拦截应答：A 返回告警 IP；AAAA 返回空应答（NOERROR）；不返回 NXDOMAIN
- 威胁情报融合：any（默认）/ majority / all；**全部源超时默认拦截**，不自动放行
- 所有威胁情报调用异常/超时返回 None，不抛异常
- 日志必录被拦截/剔除请求（filter_log），放行日志可选（默认关）
- 部署：Linux systemd 为准；Windows 部署仅备用

详见 `AI_AGENTS.md`（AI 开发指引）与 `docs/` 下 PRD。
