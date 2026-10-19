#!/usr/bin/env python3
"""
ProtonVPN WireGuard 节点活性探测 (UDP 半握手)
============================================
原理: 构造标准 Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s handshake initiation (148 字节),
用节点已注册的客户端私钥发送; 收到 handshake response (首字节 0x02)
即判活, 不完成握手 (服务端半开会话几分钟内自然过期, 流量可忽略)。
用途: 过滤已轮换/下线的 Endpoint (免费服务器 IP 会变)。
注意: 只做活性过滤, 不按 RTT 排序 —— 探测跑在 Actions 机房,
测出的延迟对用户本地无参考价值, 选优仍由客户端 url-test 组完成。
退出: 本模块无 main, 由 protonvpn.py 调用 probe_and_filter()。
"""

import hashlib
import hmac
import os
import random
import socket
import struct
import time
from base64 import b64decode
from concurrent.futures import ThreadPoolExecutor, as_completed

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

PROTOCOL_NAME = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
IDENTIFIER = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
LABEL_MAC1 = b"mac1----"
ZERO_NONCE = b"\x00" * 12


def _blake2s(data, key=None, digest_size=32):
    if key is not None:
        return hashlib.blake2s(data, key=key, digest_size=digest_size).digest()
    return hashlib.blake2s(data, digest_size=digest_size).digest()


def _kdf2(ck, input_material):
    """WireGuard KDF2: HMAC-BLAKE2s extract/expand (RFC 5869 语义).

    prk   = HMAC-BLAKE2s(key=ck, msg=input_material)        # extract
    t0    = HMAC-BLAKE2s(key=prk, msg=0x01)                 # expand -> 新 chaining key
    t1    = HMAC-BLAKE2s(key=prk, msg=t0 || 0x02)           # expand -> 加密 key
    """
    prk = hmac.new(ck, input_material, hashlib.blake2s).digest()
    t0 = hmac.new(prk, b"\x01", hashlib.blake2s).digest()
    t1 = hmac.new(prk, t0 + b"\x02", hashlib.blake2s).digest()
    return t0, t1


def _aead(key, plaintext, aad):
    return ChaCha20Poly1305(key).encrypt(ZERO_NONCE, plaintext, aad)


def _tai64n_now():
    t = time.time()
    return struct.pack(">QI", 0x4000000000000000 + int(t),
                       int((t % 1) * 1_000_000_000))


def build_initiation(static_priv_b64, server_pub_b64):
    """构造 148 字节 handshake initiation (含 mac1, mac2 置零, PSK 为零不影响发送字节)。

    流程与 kernel / Go / boringtun 三方实现保持一致:
      1. ck0 = blake2s(PROTOCOL_NAME); h0 = blake2s(ck0 || IDENTIFIER)
      2. h = blake2s(h0 || server_pub)                      # handshake_init: mix remote static
      3. e 步: h = blake2s(h || eph_pub); ck = kdf2(ck, eph_pub)[0]   # mixHash + mixKey
      4. es 步: k1 = kdf2(ck, X25519(eph_priv, server_pub))[1];
         enc_static = ChaCha20Poly1305(k1, static_pub, aad=h);
         h = blake2s(h || enc_static)
      5. ss 步: k2 = kdf2(ck, X25519(static_priv, server_pub))[1];
         enc_ts = ChaCha20Poly1305(k2, timestamp, aad=h);
         h = blake2s(h || enc_ts)
      6. mac1_key = blake2s("mac1----" || server_pub);
         mac1 = blake2s(key=mac1_key, data=前116字节, size=16)
    """
    static_priv = X25519PrivateKey.from_private_bytes(b64decode(static_priv_b64))
    static_pub = static_priv.public_key().public_bytes_raw()
    server_pub = b64decode(server_pub_b64)
    server_pubkey = X25519PublicKey.from_public_bytes(server_pub)

    # Step 1: 初始化 chaining key 和 hash
    ck = _blake2s(PROTOCOL_NAME)          # ck0
    h = _blake2s(ck + IDENTIFIER)         # h0

    # Step 2: handshake_init — mix 远端静态公钥进 hash
    h = _blake2s(h + server_pub)

    # Step 3: 生成 ephemeral 密钥对
    eph_priv = X25519PrivateKey.generate()
    eph_pub = eph_priv.public_key().public_bytes_raw()

    # Step 4: e 步 — mixHash(eph_pub) 且 mixKey(eph_pub) 更新 ck
    h = _blake2s(h + eph_pub)             # mixHash
    ck, _ = _kdf2(ck, eph_pub)            # mixKey — ck 被更新

    # Step 5: es 步 — 从 eph_priv 与 server_pub 派生加密 key, 加密 static_pub
    ss_e = eph_priv.exchange(server_pubkey)
    ck, k1 = _kdf2(ck, ss_e)              # ck 再次更新, k1 = 加密 key
    enc_static = _aead(k1, static_pub, h)
    h = _blake2s(h + enc_static)          # mixHash

    # Step 6: ss 步 — 从 static_priv 与 server_pub 派生加密 key, 加密 timestamp
    ss_s = static_priv.exchange(server_pubkey)
    ck, k2 = _kdf2(ck, ss_s)              # ck 再次更新, k2 = 加密 key
    enc_ts = _aead(k2, _tai64n_now(), h)
    _ = _blake2s(h + enc_ts)              # mixHash（结果因 MAC2=0 而未用，与参考实现保持一致）

    # Step 7: 组装消息体 (前 116 字节)
    body = bytearray(b"\x01\x00\x00\x00")  # Type = 1 (MessageInitiation)
    body += struct.pack("<I", random.getrandbits(32))  # Sender index
    body += eph_pub + enc_static + enc_ts  # 32 + 48 + 28 = 108 字节, 连同 8 字节表头共 116

    # Step 8: 计算 mac1
    mac_key = _blake2s(LABEL_MAC1 + server_pub)   # 32 字节
    mac1 = _blake2s(bytes(body), key=mac_key, digest_size=16)  # 16 字节

    return bytes(body) + mac1 + b"\x00" * 16  # 148 字节 (mac2 置零)

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
    # PROTON_PROBE_RESET=1 时清除缓存，强制全量重测
    if os.environ.get("PROTON_PROBE_RESET", "0").strip().lower() in ("1", "true", "yes"):
        setattr(probe_and_filter, "_cache", {})
        log("PROBE", "缓存已清除 (PROTON_PROBE_RESET=1)")
    now = time.monotonic()
    with getattr(probe_and_filter, "_lock", threading.Lock()) as lock:
        cache = getattr(probe_and_filter, "_cache", {})
        alive, fresh, cache_hits = [], 0, 0
        work = []
        for n in nodes:
            k = (n["server"], n["port"], n["public_key"][:16])
            c = cache.get(k)
            if c and (now - c[0]) < cooldown and c[1]:
                alive.append(n)
                cache_hits += 1
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
    log("PROBE", f"存活 {len(alive)}/{len(nodes)} "
                 f"(实测 {len(work)}, 其中测活 {fresh}; 命中冷却缓存 {cache_hits})")
    if alive and len(alive) / len(nodes) < min_alive_ratio:
        log("PROBE", f"存活率过低 (<{min_alive_ratio}), 视为探测环境异常, 保留全部节点")
        return nodes, 0
    alive.sort(key=lambda n: (n["code"], n["server"]))
    log("PROBE", f"剔除失活 {len(nodes) - len(alive)}, 输出 {len(alive)}")
    return alive, len(nodes) - len(alive)
