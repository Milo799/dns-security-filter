"""生产 DNS 链路分段探测（跨机版，可直接 scp 到服务器用）

探测顺序（三段链路：客户端 → 192:53 Go 代理 → 191:15353 检测 → 上游 53）：
  1. 本机 15353 UDP 查询        （在 191 上跑：检测进程自身收发）
  2. 从 192 探 191:15353 UDP    （在 192 上跑：代理→检测的转发段）
  3. 查询上游 223.5.5.5         （公网递归可达性，排除出站被断）

用法：
  192.168.0.191 上: python3 probe_link.py --mode local     # 测本机 15353
  192.168.0.192 上: python3 probe_link.py --mode hop       # 测 191:15353 + 上游
"""
import argparse
import socket
import sys
import time

from dnslib import DNSRecord

UPSTREAM = "223.5.5.5"


def probe_udp(host, port, timeout=5, qname="baidu.com"):
    wire = DNSRecord.question(qname, "A").pack()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.sendto(wire, (host, port))
        data, _ = s.recvfrom(4096)
        dt = (time.time() - t0) * 1000
        r = DNSRecord.parse(data)
        rcode = str(r.header.rcode)
        ans = [str(x.rdata) for x in r.rr]
        return True, "OK rcode=%s ans=%s %.0fms" % (rcode, ans[:3], dt)
    except socket.timeout:
        return False, "TIMEOUT %.0fms" % ((time.time() - t0) * 1000)
    except Exception as e:
        return False, "ERR %s" % e
    finally:
        s.close()


def probe_tcp(host, port, timeout=5):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.connect((host, port))
        return True, "TCP-CONNECT-OK %.0fms（端口有监听）" % ((time.time() - t0) * 1000)
    except ConnectionRefusedError:
        return False, "TCP-REFUSED（端口无监听，进程确定挂了）"
    except socket.timeout:
        return False, "TCP-TIMEOUT（包被丢弃：防火墙/路由）"
    except Exception as e:
        return False, "TCP-ERR %s" % e
    finally:
        s.close()


def section(title):
    print("\n===== %s =====" % title)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["local", "hop"], required=True,
                    help="local=在 191 上测本机 15353；hop=在 192 上测 191:15353")
    ap.add_argument("--target", default="172.16.0.191",
                    help="hop 模式的目标 IP（默认 172.16.0.191）")
    args = ap.parse_args()

    if args.mode == "local":
        section("1. 本机 15353 检测进程（UDP+TCP）")
        ok, r = probe_udp("127.0.0.1", 15353)
        print("  UDP baidu.com ->", r)
        print("  ", probe_tcp("127.0.0.1", 15353)[1])
        if not ok:
            print("  >>> platform-dns 进程问题：systemctl status platform-dns && journalctl -u platform-dns -n 100")
            sys.exit(1)
        section("2. 检测进程出站到上游递归")
        ok, r = probe_udp(UPSTREAM, 53)
        print("  UDP %s -> %s" % (UPSTREAM, r))
        print("  >>> 不通时查出站：ping/防火墙/上联 ACL")
    else:
        section("1. 从本机探检测机 %s:15353（UDP+TCP）" % args.target)
        ok, r = probe_udp(args.target, 15353)
        print("  UDP baidu.com ->", r)
        print("  ", probe_tcp(args.target, 15353)[1])
        if ok:
            print("  >>> 转发段通，问题在 192 本机 53 代理进程")
        else:
            print("  >>> 转发段断：查 191 检测进程 / 中间网络")
    print("\n探测完成。")


if __name__ == "__main__":
    main()
