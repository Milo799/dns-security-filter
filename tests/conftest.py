"""pytest 路径配置 + 测试数据库隔离。

- 将 platform 目录加入 sys.path，便于从仓库根运行测试；
- 将平台数据库指向 pytest 专属临时文件，避免测试污染开发库
  platform/data/platform.db（历史教训：残留的黑名单条目会串扰后续测试）。
"""

import os
import sys
import tempfile
import shutil

PLATFORM_DIR = os.path.join(os.path.dirname(__file__), "..", "platform")
sys.path.insert(0, os.path.abspath(PLATFORM_DIR))

from config import CONFIG  # noqa: E402  (必须先于任何 get_conn() 调用)

_TMP_DIR = tempfile.mkdtemp(prefix="dns-filter-test-")
CONFIG.database = os.path.join(_TMP_DIR, "test.db")
# 首次 get_conn() 会自动建表；系统配置键由各测试按需写入

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def flush_async_log():
    """每个测试结束后 flush 异步日志队列（前置项5 改异步写入后，
    拦截日志先入队不立即落库——既有"查库断言"测试需保证队列已清空）。

    无条件 flush：测试内断言前由各测试自行 _flush_once 或
    依赖本 fixture 在下个测试开始前清空（对断言在查询后立即发生的
    测试，由 detectors 断言前置 flush——见各测试内调整）。

    同时失效名单内存缓存：部分测试直接 SQL 插 filter_list（绕过
    API 层的 invalidate 钩子），跨测试残留缓存会串扰名单判定。
    """
    import log_writer
    from app.db import invalidate_list_cache
    yield
    try:
        log_writer._flush_once()
    except Exception:
        pass
    invalidate_list_cache()


def pytest_sessionfinish(session, exitstatus):
    shutil.rmtree(_TMP_DIR, ignore_errors=True)
