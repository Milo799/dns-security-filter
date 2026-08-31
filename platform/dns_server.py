"""DNS 安全过滤平台 - DNS 服务入口。

监听 53（UDP/TCP），接收代理转发来的查询，调用 detectors.process_query
执行检测主流程后返回应答。本文件仅负责报文解析/构造与事件循环，
检测逻辑全部在 detectors.py 中实现（骨架，TODO 由 AI 填充）。

使用 dnslib：轻量、便于报文级定制（构造拦截应答等）。
"""

import asyncio
import ipaddress
import logging
import socket

from dnslib import DNSRecord, QTYPE, RR, RCODE

from config import CONFIG
from detectors import process_query

logger = logging.getLogger("platform.dns")


def _skip_name(data: bytes, pos: int) -> int:
    """跳过一个域名（标签序列或压缩指针），返回下一个字段的位置。"""
    while True:
        if pos >= len(data):
            raise IndexError("报文越界")
        length = data[pos]
        if length == 0:            # 根标签结束
            return pos + 1
        if length & 0xC0 == 0xC0:  # 压缩指针（2 字节）
            return pos + 2
        pos += 1 + length


def _parse_ecs_option(opt: bytes) -> str | None:
    """解析单个 ECS option 数据（RFC 7871）：
    family(2B) + src_prefix(1B) + scope_prefix(1B) + address(按前缀截断)
    地址不足整字节长度时右补零还原。
    """
    if len(opt) < 4:
        return None
    family = int.from_bytes(opt[0:2], "big")
    addr_part = opt[4:]
    if family == 1:      # IPv4
        if not addr_part:
            return None
        addr = (addr_part[:4] + b"\x00" * 4)[:4]
        return str(ipaddress.IPv4Address(addr))
    if family == 2:      # IPv6
        if not addr_part:
            return None
        addr = (addr_part[:16] + b"\x00" * 16)[:16]
        return str(ipaddress.IPv6Address(addr))
    return None


def extract_client_ip(data: bytes) -> str | None:
    """从查询报文提取 EDNS0 Client Subnet（RFC 7871, option code 8）中的客户端 IP。

    Windows DNS 转发时附加客户端子网；代理原样透传（含 OPT RR）。
    无 ECS 或解析失败返回 None（日志中 client_ip 记为空，不影响过滤）。

    实现方式：按 RFC 1035 手动遍历报文 additional 段定位 OPT RR
    （type=41），再遍历其 rdata 中的 option 序列 [code(2B)+len(2B)+data]，
    取 code=8（ECS）。不依赖 dnslib 对 EDNS0 的内部表示。
    """
    try:
        if len(data) < 12:
            return None
        qdcount = int.from_bytes(data[4:6], "big")
        ancount = int.from_bytes(data[6:8], "big")
        nscount = int.from_bytes(data[8:10], "big")
        arcount = int.from_bytes(data[10:12], "big")

        pos = 12
        # 跳过 question 段
        for _ in range(qdcount):
            pos = _skip_name(data, pos)
            pos += 4  # qtype + qclass
        # 跳过 answer / authority 段
        for _ in range(ancount + nscount):
            pos = _skip_name(data, pos)
            pos += 8  # type + class + ttl
            rdlen = int.from_bytes(data[pos:pos + 2], "big")
            pos += 2 + rdlen
        # 遍历 additional 段找 OPT RR
        for _ in range(arcount):
            pos = _skip_name(data, pos)
            rtype = int.from_bytes(data[pos:pos + 2], "big")
            pos += 2  # type
            pos += 2  # class（OPT 中为 UDP payload size）
            pos += 4  # ttl（OPT 中为扩展rcode/flags）
            rdlen = int.from_bytes(data[pos:pos + 2], "big")
            pos += 2
            rdata = data[pos:pos + rdlen]
            if rtype == 41:
                # 遍历 rdata 中的 option 序列
                p = 0
                while p + 4 <= len(rdata):
                    code = int.from_bytes(rdata[p:p + 2], "big")
                    olen = int.from_bytes(rdata[p + 2:p + 4], "big")
                    opt = rdata[p + 4:p + 4 + olen]
                    p += 4 + olen
                    if code == 8:
                        ip = _parse_ecs_option(opt)
                        if ip:
                            return ip
            pos += rdlen
        return None
    except Exception:
        return None


async def handle_request(data: bytes, transport, addr: tuple) -> None:
    """处理单个 DNS 查询报文，构造应答并发送。

    process_query 含同步阻塞 IO（在线情报源逐源查询、公网解析），
    用 to_thread 放线程池执行，避免阻塞事件循环导致其他查询无响应。
    """
    try:
        request = DNSRecord.parse(data)
    except Exception as e:
        logger.warning("报文解析失败 from %s: %s", addr, e)
        return

    client_ip = await asyncio.get_running_loop().run_in_executor(
        None, extract_client_ip, data)

    def _process():
        try:
            return process_query(request, client_ip=client_ip)
        except Exception:
            # 检测主流程异常：回 SERVFAIL（不吞异常静默丢包）
            logger.exception("检测主流程异常 from %s: %s", addr, request.q.qname)
            reply = request.reply()
            reply.header.rcode = RCODE.SERVFAIL
            return reply

    reply = await asyncio.get_running_loop().run_in_executor(None, _process)

    try:
        transport.sendto(reply.pack(), addr)
    except Exception as e:
        logger.warning("应答发送失败 to %s: %s", addr, e)


class UdpServer(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        asyncio.create_task(handle_request(data, self.transport, addr))


async def handle_tcp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """TCP 处理：2 字节长度前缀 + 报文。"""
    peer = writer.get_extra_info("peername")
    try:
        while True:
            length_bytes = await reader.readexactly(2)
            length = int.from_bytes(length_bytes, "big")
            data = await reader.readexactly(length)
            request = DNSRecord.parse(data)
            client_ip = extract_client_ip(data)
            # 检测主流程含同步阻塞 IO，放线程池执行避免阻塞事件循环
            reply = await asyncio.get_running_loop().run_in_executor(
                None, process_query, request, client_ip)
            packed = reply.pack()
            writer.write(len(packed).to_bytes(2, "big") + packed)
            await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionError):
        pass
    except Exception as e:
        logger.warning("TCP 处理异常 from %s: %s", peer, e)
    finally:
        writer.close()


async def run_dns_server():
    """启动 UDP/TCP 双栈 DNS 服务。"""
    # 运行时配置同步（DB → CONFIG）+ 异步日志写入线程
    # （前置项5：SQLite 写入削峰，检测线程只入队不写库）
    from app.runtime import sync_config_from_db
    sync_config_from_db()
    import log_writer
    log_writer.start()
    # 日志保留期自动清理（P1-1）：双进程部署时与 Web 进程各起一个
    # 清理线程无害（DELETE 幂等，SQLite 单写者串行），保证单进程
    # 形态（仅 platform-dns）也有清理能力
    import log_retention
    log_retention.start()
    # 跨进程状态轮询：感知 Web 进程的配置修改与名单导入
    # （双进程部署下 system_config 热生效 + 三类名单缓存失效，最长 60s）
    import cross_sync
    cross_sync.start()

    addr = (CONFIG.dns.listen_addr, CONFIG.dns.listen_port)

    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        UdpServer, local_addr=addr
    )
    logger.info("DNS 服务已启动（UDP）: %s", addr)

    tcp_server = await asyncio.start_server(handle_tcp, *addr)
    logger.info("DNS 服务已启动（TCP）: %s", addr)

    await asyncio.gather(
        asyncio.Future(),  # UDP 不结束
        tcp_server.serve_forever(),
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    # Windows ProactorEventLoop 的 UDP transport 存在致命缺陷：
    # 客户端先关闭 socket 后，积压应答发往已关端口触发 ICMP port
    # unreachable，Proactor 会终止 UDP transport 的接收（connection_lost），
    # 服务从此静默失聪（进程存活、端口监听、但不再处理任何查询）。
    # SelectorEventLoop 无此问题（OSError 经 error_received 吞掉继续收包）。
    # Linux（生产部署）用 epoll，不受影响。
    import sys
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(run_dns_server())
