#!/usr/bin/env python3
"""
ProtonVPN WireGuard 节点活性探测 (UDP 半握手)
============================================
原理: 构造标准 Noise_IKpsk2 handshake initiation (148 字节),
用节点已注册的客户端私钥发送; 收到 handshake response (首字节 0x02)
即判活, 不完成握手 (服务端半开会话几分钟内自然过期, 流量可忽略)。
用途: 过滤已轮换/下线的 Endpoint (免费服务器 IP 会变)。
注意: 只做活性过滤, 不按 RTT 排序 —— 探测跑在 Actions 机房,
测出的延迟对用户本地无参考价值, 选优仍由客户端 url-test 组完成。
退出: 本模块无 main, 由 protonvpn.py 调用 probe_and_filter()。
"""

import hashlib
import random
import socket
import struct
import time
from base64 import b64decode
from concurrent.futures import ThreadPoolExecutor, as_completed

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PROTOCOL_NAME = b"Noise_IKpsk2_ChaChaPoly_BLAKE2s"
ZERO_NONCE = b"\x00" * 12


def _hash(data):
    return hashlib.blake2s(data, digest_size=32).digest()


def _hkdf2(chaining_key, input_material):
    out = HKDF(algorithm=hashes.SHA256(), length=64,
               salt=chaining_key, info=b"").derive(input_material)
    return out[:32], out[32:]


def _aead(key, plaintext, aad):
    return ChaCha20Poly1305(key).encrypt(ZERO_NONCE, plaintext, aad)


def _tai64n_now():
    t = time.time()
    return struct.pack(">QI", 0x4000000000000000 + int(t),
                       int((t % 1) * 1_000_000_000))


def build_initiation(static_priv_b64, server_pub_b64):
    """构造 148 字节 handshake initiation (含 mac1, mac2 置零, PSK 为零不影响发送字节)。"""
    static_priv = X25519PrivateKey.from_private_bytes(b64decode(static_priv_b64))
    static_pub = static_priv.public_key().public_bytes_raw()
    server_pub = b64decode(server_pub_b64)
    server_pubkey = X25519PublicKey.from_public_bytes(server_pub)

    h = _hash(PROTOCOL_NAME)
    ck = h
    h = _hash(h + server_pub)

    eph_priv = X25519PrivateKey.generate()
    eph_pub = eph_priv.public_key().public_bytes_raw()
    h = _hash(h + eph_pub)
    ck, k1 = _hkdf2(ck, eph_priv.exchange(server_pubkey))
    enc_static = _aead(k1, static_pub, h)
    h = _hash(h + enc_static)
    ck, k2 = _hkdf2(ck, static_priv.exchange(server_pubkey))
    enc_ts = _aead(k2, _tai64n_now(), h)

    body = bytearray(b"\x01\x00\x00\x00")
    body += struct.pack("<I", random.getrandbits(32))
    body += eph_pub + enc_static + enc_ts  # 116 字节
    mac_key = _hash(b"mac1----" + server_pub)
    mac1 = hashlib.blake2s(bytes(body), digest_size=16, key=mac_key).digest()
    return bytes(body) + mac1 + b"\x00" * 16  # 148 字节

def _probe_once(node, timeout):
    """发 initiation, 等 response 首字节 0x02。返回 (bool, rtt_ms)。"""
    try:
        pkt = build_initiation(node["private_key"], node["public_key"])
    except Exception:
        return False, None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        t0 = time.monotonic()
        sock.sendto(pkt, (node["server"], node["port"]))
        data, _ = sock.recvfrom(1024)
        rtt = (time.monotonic() - t0) * 1000.0
        return (len(data) >= 92 and data[0] == 0x02), rtt
    except Exception:
        return False, None
    finally:
        try:
            sock.close()
        except Exception:
            pass


def probe_and_filter(nodes, log, concurrency=16, timeout=8.0,
                     cooldown=600.0, min_alive_ratio=0.2):
    """
    逐节点发 1 次半握手; 保留「活」节点。返回 (alive_nodes, dead_count)。
    全灭保护: alive 占比 < min_alive_ratio 则视为探测环境异常 (如 UDP 被封),
    保留全部节点并返回 (nodes, 0) —— 宁可不剔除, 不生成空/残缺结果。
    cooldown: 对同一 server:port 两次探测间隔 (秒); 避免频繁打扰服务端。
    """
    import threading
    now = time.monotonic()
    with getattr(probe_and_filter, "_lock", threading.Lock()) as lock:
        cache = getattr(probe_and_filter, "_cache", {})
        alive, fresh = [], 0
        work = []
        for n in nodes:
            k = (n["server"], n["port"], n["public_key"][:16])
            c = cache.get(k)
            if c and (now - c[0]) < cooldown and c[1]:
                alive.append(n)
                continue
            work.append(n)
        if not work:
            return alive, 0
        with ThreadPoolExecutor(max_workers=concurrency) as ex:
            futs = {ex.submit(_probe_once, n, timeout): n for n in work}
            for f in as_completed(futs):
                n = futs[f]
                ok, _rtt = f.result()
                k = (n["server"], n["port"], n["public_key"][:16])
                if ok:
                    alive.append(n)
                    cache[k] = (now, True)
                    fresh += 1
                else:
                    cache[k] = (now, False)
        setattr(probe_and_filter, "_lock", threading.Lock())
        setattr(probe_and_filter, "_cache", cache)
    log("PROBE", f"存活 {len(alive)}/{len(nodes)} (本轮新测活 {fresh}, 其余命中冷却缓存)")
    if alive and len(alive) / len(nodes) < min_alive_ratio:
        log("PROBE", f"存活率过低 (<{min_alive_ratio}), 视为探测环境异常, 保留全部节点")
        return nodes, 0
    alive.sort(key=lambda n: (n["code"], n["server"]))
    log("PROBE", f"剔除失活 {len(nodes) - len(alive)}, 输出 {len(alive)}")
    return alive, len(nodes) - len(alive)
