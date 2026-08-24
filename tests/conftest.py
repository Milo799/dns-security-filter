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


def pytest_sessionfinish(session, exitstatus):
    shutil.rmtree(_TMP_DIR, ignore_errors=True)
