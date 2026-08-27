"""并发导入回归测试：多来源同时整源导入不得互相干扰。

历史问题：db.py 曾用模块级单例连接（check_same_thread=False）供所有线程
共享，多来源并发导入时多个线程在同一连接上交叉开启事务，报
"cannot start a transaction within a transaction" / "bad parameter
or other API misuse"，导致 hagezi_ti/hagezi_ult/stevenblack 更新失败。

修复：连接按线程隔离（threading.local）+ import_source 入库段加全局写锁。
本测试模拟 3 线程同时整源导入，断言全部成功且互不污染。
"""

import threading

from app import threat_list
from app.db import db_cursor


def _import_worker(results, key, text):
    try:
        n = threat_list.import_source(key, text, enabled=True)
        results[key] = ("ok", n)
    except Exception as e:      # noqa: BLE001 收集异常供断言
        results[key] = ("error", str(e))


def test_concurrent_import_no_interference():
    texts = {
        "src_a": "evil-a1.com\nevil-a2.com\nsub.evil-a1.com\n",
        "src_b": "evil-b1.com\nevil-b2.com\n",
        "src_c": "evil-c1.com\nevil-c2.com\n",
    }
    results = {}
    threads = [
        threading.Thread(target=_import_worker,
                         args=(results, key, text))
        for key, text in texts.items()
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)

    assert all(t[0] == "ok" for t in results.values()), \
        f"存在导入失败: {results}"

    # 各来源条目数正确、互不串扰
    with db_cursor() as cur:
        cur.execute(
            "SELECT source, COUNT(*) AS c FROM threat_list GROUP BY source")
        counts = {r["source"]: r["c"] for r in cur.fetchall()}
    assert counts == {"src_a": 3, "src_b": 2, "src_c": 2}, counts

    # 缓存已失效且新数据可被匹配
    assert threat_list.find_domain("evil-a2.com")[0] == "src_a"
    assert threat_list.find_domain("evil-b1.com")[0] == "src_b"
    assert threat_list.find_domain("evil-c1.com") is not None


def test_concurrent_import_same_source_last_wins():
    """同源并发：整源替换语义下后完成者覆盖，但不得抛事务异常。"""
    results = {}
    threads = [
        threading.Thread(target=_import_worker,
                         args=(results, "dup", "x1.com\nx2.com\n")),
        threading.Thread(target=_import_worker,
                         args=(results, "dup", "y1.com\ny2.com\ny3.com\n")),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)

    assert all(t[0] == "ok" for t in results.values()), results
    with db_cursor() as cur:
        cur.execute(
            "SELECT COUNT(*) AS c FROM threat_list WHERE source='dup'")
        c = cur.fetchone()["c"]
    # 整源替换：最终条数必然等于二者之一（3 或 2），且不可能是 5
    assert c in (2, 3), f"整源替换语义被破坏，条数={c}"
