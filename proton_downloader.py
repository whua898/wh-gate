#!/usr/bin/env python3
"""
ProtonVPN WireGuard 配置自动下载 (Selenium)
==========================================
登录 account.protonvpn.com/downloads, 逐台下载免费服务器 WireGuard .conf。
做法参考社区项目 Delta-Kronecker/ProtonVPN-WireGuard-configuration
(已验证: Actions 境外节点可达; 免费账户可用; 用户名+密码两步登录)。

Secrets (环境变量):
  PROTON_USER / PROTON_PASS  账号 (缺失 -> 硬失败; 账号 2FA 必须关闭)
  PROTON_ENC_KEY             Fernet 密钥, 加密 proton/proton_configs.enc (缺失 -> 硬失败)
  PROTON_PROXY               可选, 本机直连 account 站点超时时走代理 (如 http://127.0.0.1:7890)
  DOWNLOAD_SCOPE             all | first (默认 all; first 只下第一个国家, 调试用)
  MAX_DOWNLOADS_PER_SESSION  默认 20 (防风控, 与参考项目一致)
  PROTON_INTERVAL            每台下载后的随机间隔秒数 min-max (默认 5-15; 被限流时调回 60-90)
  PROTON_PER_COUNTRY         每国只下载页面负载百分比最低的 N 台 (默认 3; 0 = 该国全部)
  PROTON_ROUNDS              达会话上限后重新登录续下的轮数 (默认 2)
  PROTON_ROUND_GAP           重新登录前的等待秒数 (默认 120)
退出码:
  0 = 正常完成 (含 0 新增); 1 = 硬性失败 (登录失败/下载页打不开/WebDriver 异常)。
产物不提交明文: 与仓库密文合并后重新加密写回 proton/proton_configs.enc。
"""

import io
import json
import os
import random
import re
import sys
import tempfile
import time
import zipfile

from cryptography.fernet import Fernet

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.keys import Keys

from vpngate import log, die, _env, REPO_DIR

# 保证日志在任何控制台编码下都能输出 (Windows GBK 控制台不会崩)
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

USER = _env("PROTON_USER", "")
PASSWORD = _env("PROTON_PASS", "")
ENC_KEY = _env("PROTON_ENC_KEY", "")
PROXY = _env("PROTON_PROXY", "")
SCOPE = os.environ.get("DOWNLOAD_SCOPE", "all").strip().lower() or "all"
MAX_DL = max(1, int(os.environ.get("MAX_DOWNLOADS_PER_SESSION", "20") or "20"))
# 下载间隔秒数 (min-max, 防风控)。默认 5-15s; 账号被限流/警告时调回 60-90。
_iv = re.findall(r"\d+", os.environ.get("PROTON_INTERVAL", "5-15") or "5-15")
    # 默认 2-5s: 每轮只下 ~10 台, 频率不高; 如遇限流可设 PROTON_INTERVAL=10-30
IV_MIN, IV_MAX = (int(_iv[0]), int(_iv[1])) if len(_iv) >= 2 else (2, 5)
if IV_MIN > IV_MAX:
    IV_MIN, IV_MAX = IV_MAX, IV_MIN
# 每国只保留负载最低 N 台 (0 = 全部); 页面服务器行自带负载百分比, 无需额外请求
PER_COUNTRY = max(0, int(os.environ.get("PROTON_PER_COUNTRY", "3") or "3"))
ROUNDS = max(1, int(os.environ.get("PROTON_ROUNDS", "2") or "2"))
ROUND_GAP = max(0, int(os.environ.get("PROTON_ROUND_GAP", "120") or "120"))
ENC_PATH = os.path.join(REPO_DIR, "proton", "proton_configs.enc")
IDS_PATH = os.path.join(REPO_DIR, "proton", "downloaded_wg_ids.json")
LOGIN_URL = "https://account.protonvpn.com/login"
DOWNLOADS_URL = "https://account.protonvpn.com/downloads"
LOGOUT_URL = "https://account.protonvpn.com/logout"


def make_driver(download_dir):
    """headless Chrome (Actions 自带 chrome; chromedriver 由 Selenium Manager 自动匹配)。"""
    opts = webdriver.ChromeOptions()
    opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--window-size=1920,1080")
    # 固定英文界面: 让 Proton 渲染固定 locale, 避免 runner 默认 locale 触发风控
    # (报错文案也固定英文, _page_error 的选择器/正则更稳)
    opts.add_argument("--lang=en-US")
    opts.add_argument("--accept-lang=en-US,en")
    opts.add_argument("--user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
    if PROXY:
        opts.add_argument(f"--proxy-server={PROXY}")
        log("SELENIUM", f"使用代理 {PROXY}")
    prefs = {"download.default_directory": download_dir,
             "download.prompt_for_download": False,
             "download.directory_upgrade": True,
             "safebrowsing.enabled": True}
    opts.add_experimental_option("prefs", prefs)
    return webdriver.Chrome(options=opts)


def _page_error(driver):
    """抓取页面可见报错文本 (调试用)。

    Proton Web 登录失败时, 报错提示由 React 渲染, 选择器分散在多处。
    原实现只试了 3 个类名/属性选择器, 抓不到 Proton 真实错误。
    这里按优先级覆盖 Proton 常见错误容器 + 通用 fallback, 取第一个非空。
    仍为空时, 把当前 <title> 与 body 内文本前 300 字符也返回, 方便 debug/。"""
    selectors = [
        # Proton 专用 (Web 端实际报错容器, 2026 年实测存在)
        ".alert-danger",
        ".p-form__message--error",
        "[class*='notification'][class*='error']",
        "[role='alert']",
        # 通用 fallback
        ".text-danger",
        "[class*='error']",
        "[class*='error-message']",
    ]
    for sel in selectors:
        try:
            for el in driver.find_elements(By.CSS_SELECTOR, sel):
                if el.text.strip():
                    return el.text.strip()[:200]
        except Exception:
            pass
    # 最后兜底: 读页面标题 + body 短摘要 (登录页标题变化可帮助定位)
    try:
        title = driver.title or ""
        body_text = driver.find_element(By.TAG_NAME, "body").text or ""
        body_text = " ".join(body_text.split())[:300]
        return f"(无标准选择器命中) 标题={title!r} 摘要={body_text}"
    except Exception:
        return "无可见报错 (标题/摘要均取不到)"


def save_debug(driver, where):
    try:
        os.makedirs(where, exist_ok=True)
        with open(os.path.join(where, "page.html"), "w", encoding="utf-8") as f:
            f.write(driver.page_source)
        driver.save_screenshot(os.path.join(where, "screenshot.png"))
        log("DEBUG", f"已保存 page.html + screenshot.png 到 {where}")
    except Exception as exc:
        log("DEBUG", f"保存调试产物失败: {exc}")


def do_login(driver):
    """两步登录; 任何异常 (含 WebDriverWait 超时) 收敛为返回 False, 由调用方 die。"""
    try:
        driver.get(LOGIN_URL)
        WebDriverWait(driver, 30).until(EC.presence_of_element_located((By.ID, "username")))
        time.sleep(1)
        u = driver.find_element(By.ID, "username")
        u.click()
        u.send_keys(USER)
        time.sleep(1)
        # Proton 登录页有两个 submit 按钮 (用户名阶段 / 密码阶段), 按 visible 精确定位
        # 当前阶段该点的按钮, 避免误点到隐藏的那个导致无反应
        for btn in driver.find_elements(By.CSS_SELECTOR, "button[type='submit']"):
            if btn.is_displayed():
                btn.click()
                break
        time.sleep(3)
        p = WebDriverWait(driver, 30).until(EC.presence_of_element_located((By.ID, "password")))
        p.click()
        p.send_keys(PASSWORD)
        time.sleep(1)
        for btn in driver.find_elements(By.CSS_SELECTOR, "button[type='submit']"):
            if btn.is_displayed():
                btn.click()
                break
        time.sleep(5)
        # 提交后 Proton 可能出人机验证/风控页 (URL 含 verification/captcha/human),
        # 也可能只是页面还没跳, 再等一下让 URL 稳定
        time.sleep(2)
    except Exception as exc:
        log("LOGIN", f"登录过程异常: {type(exc).__name__} (标题: {driver.title})")
        return False
    url = driver.current_url.lower()
    if "login" in url:
        # 先给 Proton 客户端渲染一点时间 (报错文案是异步出), 再抓
        try:
            WebDriverWait(driver, 8).until(
                lambda d: any(
                    el.text.strip()
                    for sel in (".alert-danger", ".p-form__message--error",
                                "[class*='notification'][class*='error']",
                                "[role='alert']")
                    for el in d.find_elements(By.CSS_SELECTOR, sel)
                )
            )
        except Exception:
            pass
        log("LOGIN", f"仍在登录页: {_page_error(driver)}")
        return False
    for flag in ("verification", "captcha", "human"):
        if flag in url:
            log("LOGIN", f"触发二次/人机验证 ({driver.current_url}): 需人工过验证, 或改本机代理跑一次")
            return False
    log("LOGIN", "登录成功")
    return True


def goto_downloads(driver):
    driver.get(DOWNLOADS_URL)
    try:
        WebDriverWait(driver, 60).until(
            lambda d: d.find_elements(By.CSS_SELECTOR, ".mb-6 details")
            or d.find_elements(By.XPATH, "//*[normalize-space(text())='WireGuard']"))
        time.sleep(2)
        log("DOWNLOADS", f"下载页已加载: {driver.current_url}")
        return True
    except Exception as exc:
        log("DOWNLOADS", f"下载页加载失败: {type(exc).__name__} (标题: {driver.title})")
        return False

def do_logout(driver):
    try:
        driver.get(LOGOUT_URL)
        time.sleep(2)
    except Exception:
        pass


def _wait_new_conf(download_dir, before, timeout=60):
    t0 = time.time()
    while time.time() - t0 < timeout:
        now = {f for f in os.listdir(download_dir) if f.lower().endswith(".conf")}
        new = now - before
        if new:
            time.sleep(2)  # 等文件写完
            return sorted(new)[0]
        time.sleep(2)
    return None

def process_downloads(driver, download_dir, downloaded_ids):
    """旧式单步下载流程 (Delta-Kronecker 参考项目): 传 WireGuard 页签 -> 兼容保留。"""
    return _legacy_downloads(driver, download_dir, downloaded_ids)


def _legacy_downloads(driver, download_dir, downloaded_ids):
    """逐国家逐台下载; 返回 (全部完成?, )。会话达 MAX_DL 即返回 False (下次增量继续)。"""
    try:
        WebDriverWait(driver, 30).until(
            EC.element_to_be_clickable(
                (By.XPATH, "//*[normalize-space(text())='WireGuard']"))).click()
    except Exception as exc:
        log("WG", f"找不到 WireGuard 页签: {type(exc).__name__} (站点可能改版)")
        return False
    time.sleep(3)
    try:
        driver.find_element(By.CSS_SELECTOR,
                            ".flex:nth-child(4) > .mr-8:nth-child(3) .radio-fakeradio").click()
        time.sleep(2)
    except Exception:
        log("WG", "平台选项未命中, 使用默认平台继续")
    new_count = 0
    countries = driver.find_elements(By.CSS_SELECTOR, ".mb-6 details")
    log("WG", f"发现 {len(countries)} 个国家分组")
    for idx, country in enumerate(countries):
        try:
            cname = country.find_element(By.CSS_SELECTOR, "summary").text.split("\n")[0].strip()
        except Exception:
            cname = f"#{idx}"
        if new_count >= MAX_DL:
            log("WG", f"本会话下载上限 {MAX_DL}, 停下 (下次增量继续)")
            return False
        try:
            driver.execute_script("arguments[0].open = true;", country)
            time.sleep(1)
            rows = country.find_elements(By.CSS_SELECTOR, "tr")
            for row in rows[1:]:
                try:
                    sid = row.find_element(By.CSS_SELECTOR, "td:nth-child(1)").text.strip()
                except Exception:
                    continue
                if not sid or sid in downloaded_ids:
                    continue
                if new_count >= MAX_DL:
                    return False
                try:
                    btn = row.find_element(By.CSS_SELECTOR, ".button")
                except Exception:
                    continue
                before = {f for f in os.listdir(download_dir) if f.lower().endswith(".conf")}
                driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", btn)
                time.sleep(1)
                try:
                    btn.click()
                except Exception:
                    ActionChains(driver).move_to_element(btn).click().perform()
                time.sleep(2)
                try:
                    WebDriverWait(driver, 30).until(EC.element_to_be_clickable(
                        (By.CSS_SELECTOR, ".button-solid-norm:nth-child(2)"))).click()
                    WebDriverWait(driver, 30).until(EC.invisibility_of_element_located(
                        (By.CLASS_NAME, "modal-two-backdrop")))
                except Exception:
                    pass
                got = _wait_new_conf(download_dir, before)
                if got:
                    new_count += 1
                    downloaded_ids.add(sid)
                    log("WG", f"已下载 {sid} ({got}), 本轮 {new_count}/{MAX_DL}")
                else:
                    log("WG", f"{sid} 下载超时, 跳过")
                time.sleep(random.randint(IV_MIN, IV_MAX))  # 防风控随机间隔 (PROTON_INTERVAL 可调)
        except Exception:
            continue
    return True

# 新流程: 「创建」配置 -> 弹窗 (文本/二维码页签) 里点「下载」-> .conf 落盘 (用户实测 2026-10-17)
# 弹窗不出现时回退到页面下方配置记录区行内「下载」。
# 每份配置以证书名称注册; 本脚本默认单证书覆盖全部免费服务器
# (只创建一次, 后续服务器复用同一证书, 避免免费版 key 槽被挤爆)。
CERT_NAME = _env("PROTON_CERT_NAME", "wh-gate")
PROTON_CERT_GC = os.environ.get("PROTON_CERT_GC", "0").strip().lower() in ("1", "true", "yes")


def gc_certificates(driver):
    """清理同名证书的多余副本, 只保留过期日期最晚的那一个。

    安全开关: PROTON_CERT_GC=1 才启用, 默认关闭 (避免误吊销活跃证书)。
    策略: 扫描页面所有证书条目, 按名分组; 同名的只留过期最晚的, 其余点「吊销」。
    """
    if not PROTON_CERT_GC:
        log("CERT", "证书清理已关闭 (PROTON_CERT_GC=0), 跳过")
        return 0
    try:
        # 宽泛匹配: "于 Oct 17, 2027 过期" (月份可有点号也可无)
        pattern = re.compile(r"于\s+(\w+)\s+(\d{1,2}),\s+(\d{4})\s+过期")
        rows = driver.find_elements(By.XPATH,
            f"//*[normalize-space(text())='{CERT_NAME}' and contains(., '过期')]")
        if not rows:
            log("CERT", f"证书清理: 未找到含 '{CERT_NAME}' 的证书条目, 跳过")
            return 0
        entries = []
        for row in rows:
            try:
                text = row.text
                m = pattern.search(text)
                if not m:
                    continue
                month, day, year = m.group(1), m.group(2), m.group(3)
                revoke_btn = None
                try:
                    # 查找 "吊销" 文本按钮
                    revoke_candidates = row.find_elements(By.XPATH,
                        ".//*[normalize-space(text())='吊销']")
                    if revoke_candidates:
                        revoke_btn = revoke_candidates[0]
                except Exception:
                    pass
                # 如果没找到 "吊销" 按钮，尝试找 × 图标按钮
                if not revoke_btn:
                    try:
                        revoke_candidates = row.find_elements(By.XPATH,
                            ".//*[normalize-space(text())='×' or normalize-space(text())='x' or contains(text(), '×')]")
                        if revoke_candidates:
                            revoke_btn = revoke_candidates[0]
                    except Exception:
                        pass
                # 全局兜底
                if not revoke_btn:
                    try:
                        revoke_btn = driver.find_element(By.XPATH,
                            f"(//*[normalize-space(text())='吊销' or normalize-space(text())='×'])[last()]")
                    except Exception:
                        pass
                if revoke_btn and m:
                    from datetime import datetime
                    try:
                        dt = datetime.strptime(f"{year} {month} {day}", "%Y %b %d")
                    except ValueError:
                        try:
                            dt = datetime.strptime(f"{year} {month}. {day}", "%Y %b. %d")
                        except ValueError:
                            dt = datetime(2000, 1, 1)
                    entries.append((dt, revoke_btn, text[:80]))
            except Exception as exc:
                log("CERT_DEBUG", f"证书清理解析行失败: {exc}")
        if len(entries) <= 1:
            log("CERT", f"证书清理: 仅有 {len(entries)} 条 '{CERT_NAME}' 证书, 无需清理")
            return 0
        entries.sort(key=lambda e: e[0], reverse=True)
        keep, to_revoke = entries[0], entries[1:]
        log("CERT", f"证书清理: 发现 {len(entries)} 条 '{CERT_NAME}', 保留过期最晚的, 吊销 {len(to_revoke)} 条")
        revoked = 0
        for dt, btn, preview in to_revoke:
            try:
                btn.click()
                time.sleep(1)
                confirm_btns = driver.find_elements(By.XPATH,
                    "//*[normalize-space(text())='确认'] | //*/button[normalize-space(text())='确定'] | //*/button[normalize-space(text())='吊销'] | //*/span[normalize-space(text())='×']")
                confirmed = False
                for cb in confirm_btns:
                    if cb.is_displayed():
                        cb.click()
                        confirmed = True
                        break
                if confirmed:
                    revoked += 1
                    log("CERT", f"  已吊销: {preview} (到期 {dt.strftime('%Y-%m-%d')})")
                else:
                    log("CERT", f"  吊销确认失败 (未找到确认按钮): {preview}")
                time.sleep(0.5)
            except Exception as exc:
                log("CERT_DEBUG", f"  吊销异常: {preview} - {exc}")
        log("CERT", f"证书清理完成: 成功吊销 {revoked}/{len(to_revoke)} 条")
        return revoked
    except Exception as exc:
        log("CERT", f"证书清理异常: {type(exc).__name__}: {exc}")
        return 0


def reconcile_certificates(driver, keep_count, _pass=1):
    """裁剪证书: 页面证书数超过 keep_count 时吊销多余者，确保始终 = 库存数。"""
    try:
        # 导航到 WireGuard tab
        try:
            _click_text(driver, "WireGuard", timeout=15)
        except Exception:
            pass
        time.sleep(0.5)

        # 只认两标题之间的已创建配置: “这些配置适用于 ...” ~ “为需要生成的配置文件设置名称”
        # 注意: 必须用“自身文本”定位 (text() 直接子节点), 不能用 normalize-space(.)
        # (后者会把祖先容器也匹配进来, 导致 compareDocumentPosition 恒为 False -> 范围内 0 个)
        start_el = None
        end_el = None
        try:
            _starts = driver.find_elements(By.XPATH, "//*[text()[contains(., '这些配置适用于')]]")
            _ends = driver.find_elements(By.XPATH, "//*[text()[contains(., '为需要生成的配置文件设置名称')]]")
            for _e in _starts:
                try:
                    if _e.is_displayed() and len(_e.text.strip()) < 200:
                        start_el = _e
                        break
                except Exception:
                    continue
            if start_el is None and _starts:
                start_el = _starts[0]
            for _e in _ends:
                try:
                    if _e.is_displayed() and len(_e.text.strip()) < 200:
                        end_el = _e
                        break
                except Exception:
                    continue
            if end_el is None and _ends:
                end_el = _ends[0]
        except Exception:
            start_el, end_el = None, None
        all_details = driver.find_elements(By.TAG_NAME, "details")
        ranged = []
        if start_el is not None and end_el is not None:
            try:
                log("CERT", f"证书区起: <{start_el.tag_name}> '{(start_el.text or '').strip()[:40]}' / "
                           f"止: <{end_el.tag_name}> '{(end_el.text or '').strip()[:40]}'")
            except Exception:
                pass
            for d in all_details:
                try:
                    _in = driver.execute_script(
                        "var s=arguments[0],e=arguments[1],d=arguments[2];"
                        "if(!s||!e||!d) return false;"
                        "if(s===d||e===d) return false;"
                        "var sBeforeD=(s.compareDocumentPosition(d)&4)!==0;"
                        "var dBeforeE=(d.compareDocumentPosition(e)&4)!==0;"
                        "return sBeforeD && dBeforeE;",
                        start_el, end_el, d)
                    if _in:
                        ranged.append(d)
                except Exception:
                    continue
            log("CERT", f"证书区范围: details 共 {len(all_details)} 个, 范围内 {len(ranged)} 个")
        else:
            log("CERT", "未找到证书区起止标题, 回退为全页 details")
            ranged = all_details

        # 收集范围内可删除的证书条目
        certs = []
        for d in ranged:
            try:
                summary = d.find_element(By.TAG_NAME, "summary")
                name = summary.text.strip()[:60]
                if not name:
                    continue
                # Expand cert row and scroll into view
                try:
                    summary.click()
                    time.sleep(0.15)
                except Exception:
                    pass
                driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", d)
                time.sleep(0.1)
                delete_btn = _find_delete_btn(d)
                if delete_btn:
                    certs.append((name, delete_btn))
            except Exception:
                continue

        total = len(certs)
        if keep_count <= 0 and total > 0:
            log("CERT", f"保留数为 0 但页面有 {total} 台证书 (判定扫描异常), 跳过吊销以防误清空")
            return 0
        if total <= keep_count:
            log("CERT", f"证书 {total} 台 <= 库存 {keep_count} 台, 无需清理")
            return 0

        to_revoke = total - keep_count
        log("CERT", f"裁剪证书: {total} 台 -> 保留 {keep_count} 台, 吊销 {to_revoke} 台")
        revoked = 0
        # keep_count 台排在最前, 多余的 to_revoke 台砍尾部。
        # 注意: 不能写 certs[to_revoke:] —— 那只有 keep_count 个元素, 反向了。
        for name, btn in certs[keep_count:keep_count + to_revoke]:
            try:
                driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", btn)
                time.sleep(0.3)
                try:
                    btn.click()
                except Exception:
                    driver.execute_script("arguments[0].click();", btn)
                # Dialog confirm: the in-row "x" button also contains an sr-only
                # span with the revoke label, and the dialog button label lives in
                # a <span> too -- normalize-space(text()) never matches either, so
                # switch to normalize-space(.) and skip row buttons (inside details).
                confirmed = False
                _revoke = "吊销"
                _btn = None
                for _att in range(10):  # ~10s total
                    try:
                        _all = driver.find_elements(
                            By.XPATH, "//button[normalize-space(.)='%s']" % _revoke)
                    except Exception:
                        _all = []
                    _cand = []
                    for _b in _all:
                        try:
                            if not _b.is_displayed():
                                continue
                        except Exception:
                            continue
                        try:
                            _b.find_element(By.XPATH, "./ancestor::details")
                            continue  # in-row revoke button, skip
                        except Exception:
                            pass
                        _cand.append(_b)
                    if _cand:
                        _btn = _cand[0]
                        break
                    time.sleep(1)
                if _btn is not None:
                    try:
                        driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", _btn)
                        time.sleep(0.2)
                        try:
                            _btn.click()
                        except Exception:
                            driver.execute_script("arguments[0].click();", _btn)
                        confirmed = True
                        revoked += 1
                        log("CERT", f"  已吊销: {name}")
                    except Exception as exc:
                        log("CERT_DEBUG", f"  吊销失败: {name} - {exc}")
                if not confirmed:
                    try:
                        _txts = [(_b.text or "").strip() or "<空>"
                                 for _b in driver.find_elements(By.TAG_NAME, "button")
                                 if _b.is_displayed()]
                        log("CERT_DEBUG", f"  确认失败: {name} | 页面可见按钮: {_txts}")
                    except Exception as _e:
                        log("CERT_DEBUG", f"  确认失败: {name} (按钮枚举异常: {_e})")
            except Exception as exc:
                log("CERT_DEBUG", f"  吊销失败: {name} - {exc}")
            time.sleep(1.0)  # 放慢点按, 降低被服务端限流丢弃的概率

        log("CERT", f"裁剪完成: 吊销 {revoked} 台, 页面报剩余 {total - revoked} 台")
        # 点确认按钮 ≠ 服务端真删: 限流会静默丢弃部分吊销请求 (实测 45 点只剩 14 生效)。
        # 稍候重新定位证书区+重新收集按钮复扫, 仍超标就递归补吊, 最多 3 轮。
        if revoked and _pass < 3:
            time.sleep(1.5)
            return revoked + reconcile_certificates(driver, keep_count, _pass + 1)
        return revoked
    except Exception as exc:
        log("CERT", f"证书裁剪异常 (不影响主流程): {exc}")
        return 0


def _find_delete_btn(cert_item):
    """在单个证书条目内查找删除按钮，支持多种 HTML 结构。"""
    # 方式 1: 标准类名
    try:
        delete_btns = cert_item.find_elements(By.CSS_SELECTOR, "button.label-stack-item-delete")
        if delete_btns:
            return delete_btns[0]
    except Exception:
        pass
    # 方式 2: title 属性含"吊销"
    try:
        btn = cert_item.find_element(By.XPATH, ".//button[contains(@title, '吊销')]")
        return btn
    except Exception:
        pass
    # 方式 3: 按钮文本直接含"吊销"
    try:
        btns = cert_item.find_elements(By.XPATH, ".//button[normalize-space(text())='吊销']")
        if btns:
            return btns[0]
    except Exception:
        pass
    # 方式 4: SVG 图标删除按钮 (aria-label 含删除/吊销)
    try:
        btns = cert_item.find_elements(By.XPATH,
            ".//button[contains(@aria-label, '删除') or contains(@aria-label, '吊销')]")
        if btns:
            return btns[0]
    except Exception:
        pass
    # 方式 5: 带 X 图标的删除按钮
    try:
        btns = cert_item.find_elements(By.XPATH,
            ".//button[contains(@class, 'delete') or contains(@class, 'remove')]")
        if btns:
            return btns[0]
    except Exception:
        pass
    # 方式 6: 任意可见的 SVG 删除图标
    try:
        btns = cert_item.find_elements(By.XPATH,
            ".//button[.//svg[contains(@class, 'delete') or contains(@class, 'trash') or contains(@class, 'x')]]")
        if btns:
            return btns[0]
    except Exception:
        pass
    return None


def _is_certificate_entry(cert_item):
    """判断 details 元素是否为证书条目（有证书名 + 可删除）。"""
    try:
        summary = cert_item.find_element(By.TAG_NAME, "summary")
        text = summary.text.strip()
        if not text:
            return False
        # 过滤掉帮助/FAQ等
        if text in ("常见问题", "帮助", "FAQ", "?", "帮助与教程", "支持"):
            return False
        # 检查是否有删除按钮
        if _find_delete_btn(cert_item):
            return True
        # 没有删除按钮但文本像证书名（base64 或 wh-gate）
        if re.match(r"^[A-Za-z0-9+/]{20,}={0,2}$", text) or text in ("wh-gate",):
            return True
        return False
    except Exception:
        return False


def _click_text(driver, text, timeout=30):
    """按文本点可见元素。
    element_to_be_clickable 只看首个匹配 —— 页面若有隐藏同名副本 (移动端菜单/
    页脚链接) 会永远等不到; 这里遍历全部匹配、跳过隐藏节点, 原生 click 被挡时
    用 JS click 兜底。找不到抛 RuntimeError (调用方收敛处理)。"""
    xps = [
        f"//*[normalize-space(text())='{text}']",
        # 最内层包含匹配兜底 (排除还含同文本子节点的祖先, 避免误点 body/html)
        f"//*[contains(normalize-space(.), '{text}') "
        f"and not(*[contains(normalize-space(.), '{text}')])]",
    ]
    deadline = time.time() + timeout
    last = "无匹配"
    while time.time() < deadline:
        for xp in xps:
            for el in driver.find_elements(By.XPATH, xp):
                try:
                    if not el.is_displayed():
                        continue
                    driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", el)
                    time.sleep(0.5)
                    try:
                        el.click()
                    except Exception:
                        driver.execute_script("arguments[0].click();", el)
                    return el
                except Exception as exc:
                    last = type(exc).__name__
        time.sleep(2)
    raise RuntimeError(f"{text}: {last} ({timeout}s 内未见可点元素)")


def ensure_certificate(driver):
    """填证书名 + 选平台 GNU/Linux + 创建 (若已存在同名证书则跳过)。"""
    # 先检查当前页面是否已有该证书的条目 (证书名+过期日期)。
    # 注意: 必须在 fill_input 之前检查, 否则填进去的名字本身就会匹配。
    try:
        src = (driver.page_source or "").lower()
        has_name = CERT_NAME.lower() in src
        # 宽泛匹配: "于 Oct 17, 2027 过期" (无点号) 或 "expires on ..."
        has_expiry_cn = bool(re.search(r"于\s+\w+\s+\d{1,2},?\s*\d{4}\s+过期", src))
        has_expiry_en = bool(re.search(r"expires?\s+(on\s+)?\w+\s+\d{1,2},?\s*\d{4}", src))
        if has_name and (has_expiry_cn or has_expiry_en):
            log("CERT", f"已存在证书 {CERT_NAME}, 跳过创建")
            return True
    except Exception as exc:
        log("CERT_DEBUG", f"证书存在性检查异常: {exc}")
    try:
        inputs = [e for e in driver.find_elements(By.CSS_SELECTOR, "input")
                  if e.is_displayed()]
        if inputs:
            inputs[0].clear()
            inputs[0].send_keys(CERT_NAME)
            time.sleep(1)
        try:
            _click_text(driver, "GNU/Linux", timeout=10)
            time.sleep(2)
        except Exception:
            log("CERT", "平台 GNU/Linux 未命中, 使用默认平台继续")
        _click_text(driver, "创建")
        time.sleep(4)
        log("CERT", f"已创建证书 {CERT_NAME}")
        return True
    except Exception as exc:
        log("CERT", f"创建证书失败: {type(exc).__name__} (站点可能改版)")
        return False


def _modal_visible(driver):
    """配置弹窗是否开着。

    只认页面上明确显示的内容: 可见的「文本」tab 文案, 或弹窗里已渲染的 [Interface]
    配置正文。不靠 class 名/title/iframe 等 DOM 内部标识 (改版易失效)。"""
    try:
        for el in driver.find_elements(By.XPATH, "//*[normalize-space(text())='文本']"):
            if el.is_displayed():
                return True
    except Exception:
        pass
    if _conf_text_visible(driver) is not None:
        return True
    return False


def _conf_text_visible(driver):
    """弹窗「文本」页签里的配置全文; 取最内层可见元素, 没有则 None。"""
    best = None
    try:
        els = driver.find_elements(By.XPATH, "//*[contains(., '[Interface]')]")
    except Exception:
        els = []
    for el in els:
        try:
            if not el.is_displayed():
                continue
            txt = (el.text or "").strip()
        except Exception:
            continue
        if "[Interface]" in txt and "[Peer]" in txt and "PrivateKey" in txt:
            if best is None or len(txt) < len(best):
                best = txt
    if best is None:  # textarea 里 .text 取不到, 读 value
        try:
            for ta in driver.find_elements(By.TAG_NAME, "textarea"):
                if not ta.is_displayed():
                    continue
                v = (ta.get_attribute("value") or ta.text or "").strip()
                if "[Interface]" in v and "[Peer]" in v and "PrivateKey" in v:
                    if best is None or len(v) < len(best):
                        best = v
        except Exception:
            pass
    return best


def _click_outside_tr(driver, text, timeout=10):
    """点「不在表格行里」的同名按钮 (弹窗按钮; 排除配置记录区行内按钮)。"""
    try:
        el = WebDriverWait(driver, timeout).until(EC.element_to_be_clickable(
            (By.XPATH, f"//*[normalize-space(text())='{text}' and not(ancestor::tr)]")))
    except Exception:
        return False
    try:
        driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", el)
        time.sleep(0.5)
        el.click()
    except Exception:
        try:
            ActionChains(driver).move_to_element(el).click().perform()
        except Exception:
            return False
    return True


def _close_conf_modal(driver):
    """关掉配置弹窗 (点「关闭」; 失败发 ESC), 保证不挡下一行。"""
    if not _modal_visible(driver):
        return True
    if not _click_outside_tr(driver, "关闭", timeout=3):
        try:
            ActionChains(driver).send_keys(Keys.ESCAPE).perform()
        except Exception:
            pass
    t0 = time.time()
    while time.time() - t0 < 2:
        if not _modal_visible(driver):
            return True
        time.sleep(0.2)
    # 快速确认关闭, 最多等 2s 而非 8s (弹窗关闭后 React 可能慢半拍)
    # 改为: 点击关闭/ESC 后只等 2s 确认, 不长时间轮询
    # (上面循环已改 8->2, sleep 0.5->0.2, 总共最多 ~40 次调用被砍掉大半)
    try:
        ActionChains(driver).send_keys(Keys.ESCAPE).perform()
        time.sleep(1)
    except Exception:
        pass
    return not _modal_visible(driver)


def _save_conf_text(download_dir, sid, text):
    """把弹窗里的配置全文落盘为 {sid}.conf
    (裁掉 [Interface] 前与 Endpoint 行之后的界面残留)。"""
    idx = text.find("[Interface]")
    if idx > 0:
        text = text[idx:]
    out = []
    for ln in text.splitlines():
        out.append(ln)
        if ln.strip().lower().startswith("endpoint"):
            break
    fn = f"{sid}.conf"
    with open(os.path.join(download_dir, fn), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(out).strip() + "\n")
    return fn


def _await_conf(driver, sid, download_dir, before, timeout=25, t0_click=None):
    """点「创建/下载」后拿配置: 返回 (文件名, 路径标签)。"""
    t0 = time.time()
    if t0_click is None:
        t0_click = t0  # 调用方没传计时起点, 用本机此刻代替
    while True:
        if _modal_visible(driver):
            break
        now = {f for f in os.listdir(download_dir) if f.lower().endswith(".conf")}
        if now - before:
            log("WG_DEBUG", f"{sid} 无弹窗已落盘: {sorted(now-before)}")
            return sorted(now - before)[0], "no_modal_file"
        if time.time() - t0 >= timeout:
            break
        time.sleep(0.5)
    elapsed_wait = time.time() - t0
    if elapsed_wait >= timeout:
        log("WG_DEBUG", f"{sid} 弹窗超时 {elapsed_wait:.1f}s (> {timeout}s)")
    if _modal_visible(driver):
        found = _conf_text_visible(driver)
        log("WG_DEBUG", f"{sid} modal_opened text_extract={time.time()-t0_click:.1f}s found={'yes' if found else 'no'}")
        if found is None and _click_outside_tr(driver, "文本", timeout=2):
            time.sleep(0.3)
            found = _conf_text_visible(driver)
            log("WG_DEBUG", f"{sid} after_tab text_extract={time.time()-t0_click:.1f}s found={'yes' if found else 'no'}")
        if found is not None:
            fn = _save_conf_text(download_dir, sid, found)
            log("WG", f"{sid} 弹窗提取配置全文 -> {fn}")
            _close_conf_modal(driver)
            return fn, "modal_text"
        if _click_outside_tr(driver, "下载", timeout=5):
            t1 = time.time()
            while time.time() - t1 < 8:
                now = {f for f in os.listdir(download_dir)
                       if f.lower().endswith(".conf")}
                if now - before:
                    time.sleep(0.5)  # 等文件写完
                    log("WG_DEBUG", f"{sid} 弹窗内落盘 {sorted(now-before)[0]} total={time.time()-t0_click:.1f}s")
                    _close_conf_modal(driver)
                    return sorted(now - before)[0], "modal_download"
                time.sleep(0.5)
            log("WG_DEBUG", f"{sid} 弹窗下载等待 {time.time()-t1:.1f}s")
        log("WG_DEBUG", f"{sid} modal_path_end total={time.time()-t0_click:.1f}s")
    _close_conf_modal(driver)  # 收尾: 无论成败都不留弹窗挡路
    for rec in driver.find_elements(
            By.XPATH, f"//tr[td[normalize-space(text())='{sid}']]"):
        for db in rec.find_elements(By.XPATH, ".//*[normalize-space(text())='下载']"):
            try:
                driver.execute_script(
                    "arguments[0].scrollIntoView({block: 'center'});", db)
                time.sleep(0.1)
                db.click()
                log("WG_DEBUG", f"{sid} 记录区点下载 btn elapsed={time.time()-t0_click:.1f}s")
            except Exception:
                try:
                    ActionChains(driver).move_to_element(db).click().perform()
                except Exception:
                    continue
            t2 = time.time()
            got = None
            while time.time() - t2 < 8:
                now = {f for f in os.listdir(download_dir)
                       if f.lower().endswith(".conf")}
                if now - before:
                    time.sleep(0.5)
                    log("WG_DEBUG", f"{sid} 记录区已落盘 {sorted(now-before)[0]} elapsed={time.time()-t0_click:.1f}s")
                    got = sorted(now - before)[0]
                    break
                found = _conf_text_visible(driver)
                if found is not None:  # 记录区「下载」又拉起了弹窗
                    got = _save_conf_text(download_dir, sid, found)
                    _close_conf_modal(driver)
                    break
                time.sleep(0.5)
            if got:
                return got, "fallback_record"
    return None, "none"


def _find_row_btn(driver, sid):
    """按服务器名重定位服务器行 (弹窗开合会触发 React 重渲染, 旧元素引用会失效)。"""
    try:
        rows = driver.find_elements(
            By.XPATH, f"//tr[td[normalize-space(text())='{sid}']]")
    except Exception:
        return None
    for r in rows:
        try:
            if r.find_elements(By.XPATH, ".//*[normalize-space(text())='创建']") or \
               r.find_elements(By.XPATH, ".//*[normalize-space(text())='下载']"):
                return r
        except Exception:
            continue
    return None


def select_least_loaded(items, per_country):
    """每国只保留负载百分比最低的 per_country 台, 按负载升序返回 (最闲的先下)。

    items: [(load, sid), ...]; load 为整数负载百分比, 解析不到时按 999 排最后。
    per_country<=0 或台数不足时原样返回。
    """
    if per_country <= 0 or len(items) <= per_country:
        return items
    return sorted(items, key=lambda it: it[0])[:per_country]


def process_wireguard_tab(driver, download_dir, downloaded_ids):
    """新版创建->下载两步流程 (downloaded_ids 存服务器名, 如 NL-FREE#79)。
    点「创建」后弹出配置弹窗 (标题=服务器名, 文本/二维码页签, 关闭/下载按钮):
    优先提取弹窗全文直接落盘, 失败再走弹窗/记录区「下载」。
    返回三态: True=全部完成; False=达会话上限 (重登可续); None=硬失败 (站点改版/
    证书失败/分组为空 —— 重登无意义, 调用方应带调试图收尾)。"""
    try:
        _click_text(driver, "WireGuard")
    except Exception as exc:
        log("WG", f"找不到 WireGuard 页签: {type(exc).__name__} (站点可能改版)")
        return None
    # WireGuard 页签点击后 React 切 tab, 0.5s 足够; 原 3s 纯浪费
    time.sleep(0.5)
    if not ensure_certificate(driver):
        return None
    gc_certificates(driver)  # 清理同名多余证书 (需 PROTON_CERT_GC=1)
    new_count = 0
    countries = driver.find_elements(By.CSS_SELECTOR, "details")
    if not countries:
        log("WG", "未找到服务器分组 (选择器失效)")
        return None
    log("WG", f"发现 {len(countries)} 个分组")
    rows = []  # (国家, 服务器名); 按名重定位, 避免弹窗重渲染后元素失效
    by_country = {}  # 国家 -> [(负载%, 服务器名), ...]
    for c in countries:
        try:
            full = c.find_element(By.CSS_SELECTOR, "summary").text.strip()
        except Exception:
            full = "?"
        label = full.split("\n")[0].strip() or "?"  # 如 "JP-FREE" / "荷兰"
        try:
            driver.execute_script("arguments[0].open = true;", c)
            # details 展开后 DOM 立即可查 (原生 HTML 细节元素, 不是 React 重渲染),
            # 0.2s 足够让 tr 渲染进来; 原 1s 纯浪费 (55 个分组 × 0.8s ≈ 44s 白等)
            time.sleep(0.2)
            # 行内读每台的真实负载: 遍历 tr, 台名取第 1 个 td, 负载扫描全行文本
            # 里的 "NN%"。summary 上没带百分比 (原版 regex 全落空 -> 哨兵 999%),
            # 所以必须从行内取; 取不到负载的台仍入队, 按 999 排最后。
            for r in c.find_elements(By.CSS_SELECTOR, "tr"):
                try:
                    tds = r.find_elements(By.CSS_SELECTOR, "td")
                    sid = tds[0].text.strip() if tds else ""
                    if not sid:
                        continue
                    # 只从 td 里找 "NN%" (百分比在 td 文本里; 行级 r.text 会把
                    # 台名里的 #N、按钮文案、图标文字拼进来, 把 #79 误读成 79%)
                    row_load = 999
                    for td in tds[1:]:
                        try:
                            mload = re.search(r"(\d+)\s*%", td.text)
                        except Exception:
                            continue
                        if mload:
                            row_load = int(mload.group(1))
                            break
                    # 调试: 落空时打出行内各 td 的纯文本, 定位百分比实际在哪个 td
                    if row_load == 999 and sid:
                        td_texts = [td.text.strip() for td in tds]
                        log("WG_DEBUG", f"{sid} tds={td_texts} tag={r.tag_name}")
                    by_country.setdefault(label, []).append((row_load, sid))
                except Exception:
                    continue
        except Exception:
            continue
    # 收集本轮页面实际可见的所有服务器 ID (用于后续清理僵尸记录)
    available_on_page = set()
    for c in countries:
        try:
            driver.execute_script("arguments[0].open = true;", c)
            time.sleep(0.15)
            for r in c.find_elements(By.CSS_SELECTOR, "tr"):
                try:
                    tds = r.find_elements(By.CSS_SELECTOR, "td")
                    sid = tds[0].text.strip() if tds else ""
                    if sid:
                        available_on_page.add(sid)
                except Exception:
                    continue
        except Exception:
            continue
    log("WG", f"页面可见服务器: {len(available_on_page)} 台")

    parsed = [it for items in by_country.values() for it in items]
    if parsed and all(l == 999 for l, _s in parsed):
        log("WG", "警告: 所有行都没解析出负载百分比 (Proton 可能改了页面结构), "
                  "按原顺序取前 N 台而非最低负载")
    for label, items in by_country.items():
        kept = select_least_loaded(items, PER_COUNTRY)
        if PER_COUNTRY > 0 and len(items) > len(kept):
            log("COUNTRY", f"{label} 共 {len(items)} 台, 只保留负载最低 {len(kept)} 台: "
                + ", ".join(f"{sid}({load}%)" for load, sid in kept))
        rows.extend((label, sid) for _load, sid in kept)
    log("WG", f"共 {len(rows)} 台候选服务器 (每国负载最低 {PER_COUNTRY} 台, 0=全部)")
    for summary, sid in rows:
        if new_count >= MAX_DL:
            log("WG", f"本会话上限 {MAX_DL}, 停下 (下次增量继续)")
            return False
        if sid in downloaded_ids:
            continue
        row = _find_row_btn(driver, sid)
        if row is None:
            continue
        creates = row.find_elements(By.XPATH, ".//*[normalize-space(text())='创建']")
        if creates:
            btn = creates[0]
        else:  # 已创建过的行只有「下载」-> 补下 (不再跳过)
            downs = row.find_elements(By.XPATH, ".//*[normalize-space(text())='下载']")
            if not downs:
                continue
            btn = downs[0]
        driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", btn)
        # scrollIntoView 完成即定位, 原 1s 防"页面还没滚到"多余 (原生 DOM 滚动同步完成)
        time.sleep(0.2)
        t0_click = time.time()  # 记录本机开始时刻, 用于 log 每台耗时
        before = {f for f in os.listdir(download_dir) if f.lower().endswith(".conf")}
        try:
            try:
                btn.click()
            except Exception:
                ActionChains(driver).move_to_element(btn).click().perform()
        except Exception:
            continue
        got, path = _await_conf(driver, sid, download_dir, before, t0_click=t0_click)
        elapsed = time.time() - t0_click
        if got:
            new_count += 1
            downloaded_ids.add(sid)
            path_label = {"modal_text": "弹窗提取", "modal_download": "弹窗下载", "fallback_record": "记录区兜底", "no_modal_file": "无弹窗", "none": "失败"}.get(path, path)
            suffix = f", 耗时 {elapsed:.1f}s [{path_label}]"
            log("WG", f"[{summary}] 已创建并下载 {sid} ({got}), 本轮 {new_count}/{MAX_DL}{suffix}")
        else:
            log("WG", f"{sid} 创建/下载未拿到文件, 跳过 (耗时 {elapsed:.1f}s, path={path})")
        time.sleep(random.randint(IV_MIN, IV_MAX))  # 防风控随机间隔 (PROTON_INTERVAL 可调)
    return True


# ---------------------------------------------------------------------------
# 密文合并 (仓库只存密文, 明文绝不入库)
# ---------------------------------------------------------------------------
def _norm_name(fn):
    base = os.path.basename(fn)
    base = re.sub(r"\s*\(\d+\)(?=\.[^.]+$)", "", base)
    return base.lower()


def load_encrypted_store():
    if not os.path.exists(ENC_PATH):
        return {}
    raw = Fernet(ENC_KEY.encode("ascii")).decrypt(open(ENC_PATH, "rb").read())
    store = {}
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        for info in zf.infolist():
            if info.filename.lower().endswith(".conf"):
                store[_norm_name(info.filename)] = zf.read(info.filename)
    return store


def save_encrypted_store(store):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in sorted(store):
            zf.writestr(f"confs/{name}", store[name])
    os.makedirs(os.path.dirname(ENC_PATH), exist_ok=True)
    with open(ENC_PATH, "wb") as f:
        f.write(Fernet(ENC_KEY.encode("ascii")).encrypt(buf.getvalue()))


def load_ids():
    if os.path.exists(IDS_PATH):
        try:
            return set(json.load(open(IDS_PATH, encoding="utf-8")))
        except Exception:
            return set()
    return set()


def save_ids(ids):
    os.makedirs(os.path.dirname(IDS_PATH), exist_ok=True)
    with open(IDS_PATH, "w", encoding="utf-8") as f:
        json.dump(sorted(ids), f, ensure_ascii=False, indent=1)


def _scan_available_ids(driver):
    """扫描当前页面，每国只保留负载最低的 PER_COUNTRY 台，返回应保留的 ID 集合。
    用于清理已下线或负载较高的服务器的僵尸记录，确保库存始终 <= 国家数 × PER_COUNTRY。"""
    by_country = {}  # {country_label: [(load_pct, sid), ...]}
    try:
        # 注意: 不 driver.get() 重载 —— finally 里可能已 do_logout，重载回未登录页致 0 国。
        # 直接下载流程刚走完，当前 DOM 即最新，直接扫。
        # 只扫“或指定服务器”之下的国家分组合（国家 details 里才有 tr 服务器行）；
        # 顶部证书区 / 帮助区 details 没有 tr，会被天然跳过
        try:
            _cat = None
            for _el in driver.find_elements(By.XPATH, "//*[contains(normalize-space(.), '或指定服务器')]"):
                try:
                    if _el.is_displayed():
                        _cat = _el
                        break
                except Exception:
                    continue
            if _cat is None:
                _els = driver.find_elements(By.XPATH, "//*[contains(normalize-space(.), '或指定服务器')]")
                if _els:
                    _cat = _els[0]
            if _cat is not None:
                details = driver.execute_script(
                    "var cat=arguments[0]; var out=[];"
                    "var all=cat.getElementsByTagName('details');"
                    "for(var i=0;i<all.length;i++){out.push(all[i]);}"
                    "return out;", _cat)
            else:
                details = driver.find_elements(By.CSS_SELECTOR, "details")
        except Exception:
            details = driver.find_elements(By.CSS_SELECTOR, "details")
        for d in details:
            try:
                summary = d.find_element(By.TAG_NAME, "summary")
                label = summary.text.strip()
                if not label:
                    continue
                driver.execute_script("arguments[0].open = true;", d)
                time.sleep(0.15)
                for row in d.find_elements(By.CSS_SELECTOR, "tr"):
                    try:
                        tds = row.find_elements(By.CSS_SELECTOR, "td")
                        sid = tds[0].text.strip() if tds else ""
                        if not sid or "#" not in sid:
                            continue
                        # 从 td[1:] 里扫 "NN%" (和 process_wireguard_tab 相同逻辑)
                        row_load = 999
                        for td in tds[1:]:
                            try:
                                m = re.search(r"(\d+)\s*%", td.text)
                            except Exception:
                                continue
                            if m:
                                row_load = int(m.group(1))
                                break
                        by_country.setdefault(label, []).append((row_load, sid))
                    except Exception:
                        continue
            except Exception:
                continue
    except Exception as exc:
        log("CLEANUP", f"扫描可用服务器失败 (返回原记录, 不更新): {exc}")
        return None  # 扫描失败时返回 None，调用方应跳过清理
    # 每国只保留负载最低的 PER_COUNTRY 台
    keep = set()
    for label, items in by_country.items():
        selected = select_least_loaded(items, PER_COUNTRY)
        for _load, sid in selected:
            keep.add(sid)
    log("CLEANUP", f"页面每国最低负载保留 {len(keep)} 台 (共 {len(by_country)} 国, PER_COUNTRY={PER_COUNTRY})")
    return keep

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    if not USER or not PASSWORD:
        die("未设置 PROTON_USER / PROTON_PASS (仓库 Secrets; 账号 2FA 必须关闭)")
    if not ENC_KEY:
        die("未设置 PROTON_ENC_KEY (先用以下命令生成后存入 Secrets, 标准库即可无需装包: "
            "python -c \"import base64,os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())\")")
    try:
        store = load_encrypted_store()
    except Exception as exc:
        die(f"现有密文解密失败 (密钥错/文件损坏): {type(exc).__name__}: {exc}")
    downloaded = load_ids()
    log("STORE", f"密文库存: {len(store)} 台, 已记录 ID: {len(downloaded)}")

    with tempfile.TemporaryDirectory(prefix="proton_dl_") as dl:
        driver = make_driver(dl)
        try:
            if not do_login(driver):
                save_debug(driver, os.path.join(REPO_DIR, "debug"))
                die("登录失败 (账号密码错 / 触发二次或人机验证; 调试图已保存到 debug/ artifact)")
            if not goto_downloads(driver):
                save_debug(driver, os.path.join(REPO_DIR, "debug"))
                die("下载页打不开 (调试图已保存到 debug/ artifact)")
            for attempt in range(1, ROUNDS + 1):
                rc = process_wireguard_tab(driver, dl, downloaded)
                if rc is True:
                    break
                if rc is None:  # 硬失败: 重登无意义, 带调试图收尾
                    save_debug(driver, os.path.join(REPO_DIR, "debug"))
                    die("下载流程硬失败 (WireGuard 页签/证书/分组; 调试图已保存到 debug/ artifact)")
                log("SESS", f"第 {attempt}/{ROUNDS} 轮达会话上限 {MAX_DL}, 重新登录继续")
                do_logout(driver)
                if ROUND_GAP > 0:
                    time.sleep(ROUND_GAP)
                if attempt >= ROUNDS:
                    break
                if not do_login(driver) or not goto_downloads(driver):
                    save_debug(driver, os.path.join(REPO_DIR, "debug"))
                    log("SESS", "重新登录/回下载页失败, 提前收尾 (已有库存照常合并)")
                    break
        finally:
            # 清理必须在 do_logout/driver.quit() 之前执行 —— 登出后页面失效,
            # _scan_available_ids 扫到 0 国返回空集, 曾导致 downloaded 被清空、
            # reconcile(0) 使证书永不吊销。空集视同扫描异常, 保留本轮 downloaded。
            try:
                live_ids = _scan_available_ids(driver)
                if live_ids:
                    pruned = downloaded - live_ids
                    if pruned:
                        log("CLEANUP", f"清理 {len(pruned)} 条记录 (已下线或负载较高): {sorted(pruned)}")
                    added = live_ids - downloaded
                    if added:
                        log("CLEANUP", f"新增 {len(added)} 条低负载服务器记录: {sorted(added)}")
                    downloaded = live_ids
                elif live_ids is not None:
                    log("CLEANUP", "扫描到 0 台 (页面状态异常?), 保留本轮 downloaded 继续吊销")
                if downloaded:
                    reconcile_certificates(driver, len(downloaded))
                    log("CLEANUP", f"清理后保留 {len(downloaded)} 条")
                else:
                    log("CLEANUP", "无可用记录, 跳过证书吊销")
            except Exception as exc:
                log("CLEANUP", f"清理失败 (不影响主流程): {exc}")
            try:
                do_logout(driver)
            except Exception:
                pass
            try:
                driver.quit()
            except Exception:
                pass

        fresh = [f for f in os.listdir(dl) if f.lower().endswith(".conf")]
        log("MERGE", f"本轮新下载: {len(fresh)} 台")
        for fn in fresh:
            with open(os.path.join(dl, fn), "rb") as f:
                store[_norm_name(fn)] = f.read()
    if not store:
        die("密文库存为空且本轮 0 下载 (什么都没拿到, 本次运行判定失败)")
    # 裁剪加密库存：只保留与当前有效 ID 对应的配置，与 downloaded 数量保持一致
    if downloaded:
        pruned_store = {k: v for k, v in store.items()
                        if any(_norm_name(f"{sid}.conf") == k or k.endswith(_norm_name(f"{sid}.conf"))
                               for sid in downloaded)}
        if len(pruned_store) < len(store):
            removed = len(store) - len(pruned_store)
            log("CLEANUP", f"同步裁剪加密库存: 移除 {removed} 条已下线/高负载服务器的配置")
        store = pruned_store
    save_encrypted_store(store)
    if downloaded:
        save_ids(downloaded)
    else:
        log("MERGE", "downloaded 为空, 保留已记录 ID 不覆盖")
    log("MERGE", f"合并后库存: {len(store)} 台, 已写回 {os.path.relpath(ENC_PATH, REPO_DIR)}")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        die(f"程序异常: {type(exc).__name__}: {exc}")
