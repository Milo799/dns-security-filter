"""DNS 安全过滤平台 - DNS 服务入口。

监听 53（UDP/TCP），接收代理转发来的查询，调用 detectors.process_query
执行检测主流程后返回应答。本文件仅负责报文解析/构造与事件循环，
检测逻辑全部在 detectors.py 中实现（骨架，TODO 由 AI 填充）。

使用 dnslib：轻量、便于报文级定制（构造拦截应答等）。
"""

import asyncio
import logging
import socket

from dnslib import DNSRecord, QTYPE, RR, RCODE

from config import CONFIG
from detectors import process_query

logger = logging.getLogger("platform.dns")


def extract_client_ip(data: bytes) -> str | None:
    """从查询报文提取 EDNS0 Client Subnet（RFC 7871, option code 8）中的客户端 IP。

    Windows DNS 转发时附加客户端子网；代理原样透传（含 OPT RR）。
    无 ECS 或解析失败返回 None（日志中 client_ip 记为空，不影响过滤）。

    TODO(AI): dnslib 对 ECS option 的原生支持有限，此处按 RFC 7871 手动解析：
      OPT RR (type 41) 的 rdata 中，option 依次为 [code(2B) + length(2B) + data]。
      code=8 时 data 为 [family(2B) + src_prefix(1B) + scope_prefix(1B) + address(NB)]，
      family=1 为 IPv4（address 4B），family=2 为 IPv6（address 16B）。
    当前为占位实现，返回 None；请按上述规范完成并用 tests 中的用例验证。
    """
    try:
        # TODO(AI): 解析 OPT RR 中的 ECS option，返回客户端 IP 字符串
        return None
    except Exception:
        return None


async def handle_request(data: bytes, transport, addr: tuple) -> None:
    """处理单个 DNS 查询报文，构造应答并发送。"""
    try:
        request = DNSRecord.parse(data)
    except Exception as e:
        logger.warning("报文解析失败 from %s: %s", addr, e)
        return

    client_ip = extract_client_ip(data)

    # 检测主流程（骨架）：返回 dnslib.DNSRecord 应答
    reply = process_query(request, client_ip=client_ip)

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
            reply = process_query(request, client_ip=client_ip)
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
    asyncio.run(run_dns_server())
