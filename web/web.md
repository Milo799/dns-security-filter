# Web 管理前端（待开发）

按 PRD「5.6 Web 管理界面」页面清单搭建，调用平台 REST API（PRD 7.2）：

| 页面 | 对应接口 |
|------|----------|
| 登录 | POST /api/auth/login |
| 仪表盘 | GET /api/status |
| 人工情报源（白/黑名单，页内 Tab 区分） | /api/list*（CRUD + 导入导出） |
| 威胁情报源 | /api/threatintel*（含融合策略） |
| 过滤日志 | /api/logs*（查询 + 导出 CSV） |
| 系统配置 | GET/PUT /api/config、POST /api/detection/toggle |
| 操作审计 | GET /api/audit |

建议：Vue3 + Vite + Element Plus（PRD 技术选型），或原生 HTML + Bootstrap 极简实现。
构建产物放入 `web/dist/`，由平台 Web 服务静态托管或独立 Nginx 部署。
