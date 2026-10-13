"""MCP 服务支撑接口（迭代 50）。

MCP 服务（platform/mcp_server.py）本身不直连数据库，所有写操作都经本
平台的既有 API 执行（复用鉴权/校验/审计/缓存失效）。本路由只补一件事：
**把"这次改动是哪个 Agent 发起、用哪个 MCP 工具"记到平台审计里**——
否则审计里只能看到 admin 账号，无法区分人与 Agent。

安全说明：operator 由调用方声明（需管理员 token）。它只影响审计归属
展示，不改变任何权限——能调用本接口的账号本就有等价写权限。
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.audit import write_audit
from app.auth import get_current_user

router = APIRouter(prefix="/api/mcp", tags=["mcp"])


class McpAuditBody(BaseModel):
    tool: str = Field(min_length=1, max_length=64)
    detail: dict = Field(default_factory=dict)
    operator: str = Field(default="mcp:agent", max_length=64)


@router.post("/audit")
def mcp_audit(body: McpAuditBody, _: str = Depends(get_current_user)):
    """记录一次 MCP 工具操作（供审计追溯：谁、经哪个工具、改了什么）。"""
    tool = body.tool.strip().replace(" ", "_")[:64]
    operator = (body.operator or "mcp:agent").strip()[:64]
    write_audit(operator, "mcp_" + tool, body.detail or {})
    return {"code": 0, "message": "ok",
            "data": {"recorded": True, "operator": operator,
                     "action": "mcp_" + tool}}
