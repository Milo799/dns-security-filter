#!/usr/bin/env python3
"""DNS 压测脚本 —— 10 万终端前置开发项第 3 项。

对 DNS 入口（代理或平台直连）施加可控 QPS 的 UDP 查询压力，
产出容量报告所需的全部指标：

  - 实测 QPS（发送/接收双向）
  - 延迟分位数 P50 / P90 / P95 / P99 / Max（毫秒）
  - 超时率、丢包率（发送未收到应答）
  - 应答 RCODE 分布（NOERROR / SERVFAIL / 其他）
  - 命中缓存阶段的延迟对比（可选 --report-cache-warmup）

设计要点（对齐部署方案第 3 项验收口径）：
  - 域名池带重复分布：默认 500 个域名按指数"热度"重复访问
    （头部门控 + zipf 近似），模拟真实终端访问局部性——
    缓存命中率是本压测要验证的核心指标，均匀随机分布会显著低估；
  - 阶梯加压：--qps 支持逗号分隔多级（如 100,1000,10000），
    每级独立统计、独立报告，逐级验证容量拐点；
  - 每查询随机 QID + 独立 UDP socket 复用（asyncio DatagramProtocol），
    应答按 DNS ID 匹配回请求，不串扰；
  - 无第三方依赖（标准库 + dnslib 都不用：手写 DNS 查询报文构造与解析，
    与生产协议一致且压测端开销最小）。

用法示例：
  # 单级压测：打 1000 QPS 持续 60 秒
  python tools/loadtest.py --target 127.0.0.1:15353 --qps 1000 --duration 60

  # 阶梯加压：1 千 → 1 万 → 3 万（部署方案容量拐点验证）
  python tools/loadtest.py --target 127.0.0.1:15353 --qps 1000,10000,30000 \
      --duration 600 --domains 2000

  # 冷/热缓存对比（验证缓存收益）
  python tools/loadtest.py --target 127.0.0.1:15353 --qps 500 --duration 30 \
      --report-cache-warmup

输出：控制台表格 + loadtest-report-<时间戳>.json（留存对比基线）。
"""

import argparse
import asyncio
import json
import random
import struct
import time
from collections import Counter
from pathlib import Path

# ---------------------------------------------------------------------------
# DNS 报文构造/解析（最小实现：A 查询，与生产链路同协议）
# ---------------------------------------------------------------------------

def build_query(name: str, qid: int) -> bytes:
    """构造标准 A 查询报文（RD=1）。"""
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    q = b"".join(
        bytes([len(p)]) + p.encode("ascii")
        for p in name.split(".") if p) + b"\x00"
    return header + q + struct.pack(">HH", 1, 1)   # QTYPE=A, QCLASS=IN


def parse_response(data: bytes) -> tuple[int, int]:
    """从应答报文取 (qid, rcode)；malformed 返回 (-1, -1)。"""
    if len(data) < 12:
        return -1, -1
    qid, flags, _, _, _, _ = struct.unpack(">HHHHHH", data[:12])
    return qid, flags & 0x0F


# ---------------------------------------------------------------------------
# 域名池（热度分布）
# ---------------------------------------------------------------------------

def build_domain_pool(n: int) -> list[str]:
    """生成 n 个测试域名，长度/结构与真实域名接近。"""
    labels = ["www", "api", "cdn", "mail", "app", "img", "static",
              "portal", "login", "pay", "shop", "news", "video", "sso"]
    tlds = ["com", "cn", "net", "org", "io"]
    rng = random.Random(20260828)            # 固定种子：报告可复现
    pool = []
    for i in range(n):
        pool.append(f"{rng.choice(labels)}-{i}.{rng.choice(['site', 'svc'])}"
                    f"{i % 7}.{rng.choice(tlds)}")
    return pool


def build_weighted_indices(n: int) -> list[int]:
    """热度权重：头 10% 域名承担 ~55% 流量（zipf 近似）。

    返回展开后的索引序列（长度 = n * 4），随机采样其中元素即得
    带偏分布——热门域名被高频重复访问，冷门域名偶发 miss。
    """
    weights = [1.0 / (i + 1) ** 0.9 for i in range(n)]   # zipf s≈0.9
    total = sum(weights)
    expanded = []
    target = n * 4
    acc = 0.0
    for i, w in enumerate(weights):
        acc += w / total
        take = int(acc * target) - len(expanded)
        expanded.extend([i] * max(0, take))
    while len(expanded) < target:
        expanded.append(0)
    return expanded


# ---------------------------------------------------------------------------
# 压测引擎
# ---------------------------------------------------------------------------

class LoadEngine:
    """asyncio UDP 压测引擎：单事件循环 + 单 socket，QID 匹配应答。"""

    def __init__(self, target: tuple[str, int], qps: int, duration: float,
                 domains: list[str], weighted: list[int], timeout_s: float):
        self.target = target
        self.qps = qps
        self.duration = duration
        self.domains = domains
        self.weighted = weighted
        self.timeout_s = timeout_s
        # 统计
        self.sent = 0
        self.received = 0
        self.rcodes: Counter = Counter()
        self.latencies: list[float] = []      # 毫秒
        self.timeouts = 0
        self._pending: dict[int, tuple[float, object]] = {}   # qid -> (send_t, future)
        self._transport = None
        self._qid = random.randrange(0, 0x8000)

    def _next_qid(self) -> int:
        self._qid = (self._qid + 1) & 0xFFFF
        return self._qid

    def connection_made(self, transport):
        self._transport = transport

    def connection_lost(self, exc):
        # Windows Proactor 关闭 transport 时回调；异常忽略（压测已结束）
        pass

    def datagram_received(self, data: bytes, addr):
        qid, rcode = parse_response(data)
        entry = self._pending.pop(qid, None)
        if entry is None:
            return                                  # 迟到/串扰应答
        send_t, future = entry
        if not future.done():
            future.set_result((time.perf_counter() - send_t) * 1000.0)
        self.received += 1
        self.rcodes[rcode] += 1
        self.latencies.append(
            (time.perf_counter() - send_t) * 1000.0)

    def error_received(self, exc):
        pass

    async def _wait_reply(self, qid: int) -> float | None:
        """异步等待单个查询应答，超时返回 None（预留：单查询诊断用）。"""
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        self._pending[qid] = (time.perf_counter(), future)
        try:
            return await asyncio.wait_for(future, self.timeout_s)
        except asyncio.TimeoutError:
            self._pending.pop(qid, None)
            return None

    async def _sender(self):
        """纯发送协程：严格按目标 QPS 节拍发送，不等待应答。

        发送与回收分离：高延迟目标下（如走完整检测链路的冷查询
        数秒级），单协程"发送→等应答→再发送"永远达不到目标 QPS；
        分离后发送速率只受节拍控制，应答由 datagram_received 异步
        完成对应 future，回收协程只做延迟统计。

        节拍用"批量补发"实现：Windows asyncio.sleep 精度约 15ms，
        高 QPS（如 5000 → 间隔 0.2ms）下逐包 sleep 永远跟不上节拍，
        事件循环被应答洪流拖慢时逐包追赶也会饿死。改为每次唤醒后
        把已到期的节拍一次性补发（受 batch 上限保护），唤醒间隔
        取 min(剩余节拍间隔, 5ms)——平均速率仍严格受节拍约束。
        """
        interval = 1.0 / self.qps
        end_at = time.perf_counter() + self.duration
        rng = random.Random()
        next_at = time.perf_counter()
        BATCH_MAX = 500                       # 单轮补发上限（防长卡后洪泛）
        while True:
            now = time.perf_counter()
            if now >= end_at:
                return
            count = 0
            while next_at <= now and count < BATCH_MAX:
                name = self.domains[rng.choice(self.weighted)]
                qid = self._next_qid()
                self._register(qid)              # 先登记再发送（防应答先到）
                self._transport.sendto(build_query(name, qid), self.target)
                self.sent += 1
                next_at += interval
                count += 1
                if time.perf_counter() >= end_at:
                    return
            # 落后超过 30s：事件循环长卡（如被调试器暂停），放弃追赶防洪泛
            if now - next_at > 30.0:
                next_at = time.perf_counter()
            delay = next_at - time.perf_counter()
            await asyncio.sleep(min(max(delay, 0), 0.005))

    def _register(self, qid: int):
        loop = asyncio.get_running_loop()
        self._pending[qid] = (time.perf_counter(), loop.create_future())

    async def _drain(self, grace_s: float = 1.0):
        """发送结束后等待残余应答（至多 timeout_s + grace）。"""
        deadline = time.perf_counter() + self.timeout_s + grace_s
        while self._pending and time.perf_counter() < deadline:
            await asyncio.sleep(0.05)
        # 超时未回的记为 timeouts
        self.timeouts += len(self._pending)
        for qid, (_, fut) in list(self._pending.items()):
            if not fut.done():
                fut.cancel()
        self._pending.clear()

    async def run(self) -> dict:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: self, remote_addr=self.target)
        try:
            start = time.perf_counter()
            await self._sender()            # 按节拍发送
            await self._drain()             # 等残余应答/超时
            wall = time.perf_counter() - start
        finally:
            transport.close()

        lat = sorted(self.latencies)

        def pct(p: float) -> float:
            if not lat:
                return float("nan")
            return lat[min(int(len(lat) * p), len(lat) - 1)]

        sent = self.sent
        received = self.received
        return {
            "target": f"{self.target[0]}:{self.target[1]}",
            "qps_target": self.qps,
            "duration_s": round(wall, 1),
            "sent": sent,
            "received": received,
            "send_qps": round(sent / wall, 1) if wall else 0,
            "recv_qps": round(received / wall, 1) if wall else 0,
            "latency_ms": {
                "p50": round(pct(0.50), 2),
                "p90": round(pct(0.90), 2),
                "p95": round(pct(0.95), 2),
                "p99": round(pct(0.99), 2),
                "max": round(lat[-1], 2) if lat else None,
                "avg": round(sum(lat) / len(lat), 2) if lat else None,
            },
            "timeouts": self.timeouts,
            "loss_rate": round(1 - received / sent, 4) if sent else None,
            "rcodes": {str(k): v for k, v in sorted(self.rcodes.items())},
        }


# ---------------------------------------------------------------------------
# 报告输出
# ---------------------------------------------------------------------------

RCODE_NAMES = {0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN"}


def print_report(stage: str, r: dict) -> None:
    print(f"\n── 压测结果 [{stage}] ──────────────────────────────")
    print(f"  目标          : {r['target']}")
    print(f"  目标 QPS      : {r['qps_target']:>12,}")
    print(f"  持续时间      : {r['duration_s']:>12} s")
    print(f"  发送 / 接收   : {r['sent']:>10,} / {r['received']:>10,}")
    print(f"  实测 QPS(收)  : {r['recv_qps']:>12,}")
    lat = r["latency_ms"]
    print(f"  延迟 ms  P50  : {lat['p50']:>12}")
    print(f"           P95  : {lat['p95']:>12}")
    print(f"           P99  : {lat['p99']:>12}")
    print(f"           Max  : {str(lat['max']):>12}")
    print(f"  超时 / 丢包率 : {r['timeouts']:>10,} / "
          f"{(r['loss_rate'] or 0) * 100:.2f}%")
    rc = ", ".join(f"{RCODE_NAMES.get(int(k), k)}={v}"
                   for k, v in r["rcodes"].items())
    print(f"  RCODE 分布    : {rc}")
    # 验收线提示（部署方案口径：P95<100ms 无丢包）
    ok_p95 = lat["p95"] < 100 if lat["p95"] == lat["p95"] else False
    ok_loss = (r["loss_rate"] or 0) < 0.001
    verdict = "✅ 达标" if (ok_p95 and ok_loss) else "❌ 未达标"
    print(f"  验收(P95<100ms 且丢包<0.1%) : {verdict}")


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="DNS 入口压测（UDP，异步，零第三方依赖）")
    ap.add_argument("--target", default="127.0.0.1:15353",
                    help="压测目标 host:port（默认 127.0.0.1:15353 平台 DNS）")
    ap.add_argument("--qps", default="1000",
                    help="目标 QPS，逗号分隔多级阶梯（如 1000,10000,30000）")
    ap.add_argument("--duration", type=float, default=60,
                    help="每级持续秒数（默认 60）")
    ap.add_argument("--domains", type=int, default=500,
                    help="域名池大小（默认 500，热度分布）")
    ap.add_argument("--timeout", type=float, default=5.0,
                    help="单查询应答超时秒数（默认 5）")
    ap.add_argument("--report-cache-warmup", action="store_true",
                    help="先打 30 秒预热缓存，再正式压测并对比两段延迟")
    ap.add_argument("--json-out", default="",
                    help="JSON 报告输出路径（默认 loadtest-report-<ts>.json）")
    return ap.parse_args()


async def main() -> None:
    args = parse_args()
    host, _, port = args.target.rpartition(":")
    target = (host or "127.0.0.1", int(port))
    stages = [int(x) for x in str(args.qps).split(",") if x.strip()]

    domains = build_domain_pool(args.domains)
    weighted = build_weighted_indices(args.domains)
    report = {"started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
              "target": f"{target[0]}:{target[1]}",
              "domain_pool": args.domains, "stages": []}

    print(f"DNS 压测：目标 {target[0]}:{target[1]}，"
          f"域名池 {args.domains}（热度分布），超时 {args.timeout}s")

    if args.report_cache_warmup:
        # 预热段：低 QPS 把热门域名灌进缓存
        warm = LoadEngine(target, min(stages[0], 200), 30,
                          domains, weighted, args.timeout)
        print("\n[预热] 30s 低强度灌缓存 …")
        r = await warm.run()
        print_report("cache-warmup", r)
        report["warmup"] = r

    for qps in stages:
        print(f"\n[压测] 目标 {qps:,} QPS × {args.duration:.0f}s …")
        engine = LoadEngine(target, qps, args.duration,
                            domains, weighted, args.timeout)
        r = await engine.run()
        print_report(f"{qps}-qps", r)
        report["stages"].append(r)
        # 级间歇 2 秒，避免上级尾部应答混入下级统计
        await asyncio.sleep(2)

    out = args.json_out or f"loadtest-report-{time.strftime('%Y%m%d-%H%M%S')}.json"
    Path(out).write_text(json.dumps(report, ensure_ascii=False, indent=2),
                         encoding="utf-8")
    print(f"\n报告已保存：{out}")


if __name__ == "__main__":
    # Windows 默认 ProactorEventLoop 对 UDP DatagramProtocol 支持不稳
    # （实际发送速率被钳到远低于目标值）；SelectorEventLoop 行为正常。
    import sys
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
