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
    """抓取页面可见报错文本 (调试用)。"""
    for sel in ("[role='alert']", ".text-danger", "[class*='error']"):
        try:
            for el in driver.find_elements(By.CSS_SELECTOR, sel):
                if el.text.strip():
                    return el.text.strip()[:200]
        except Exception:
            pass
    return "无可见报错"


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
    """两步登录; 仍在登录页 / 出现验证页则返回 False (调用方 die)。"""
    driver.get(LOGIN_URL)
    WebDriverWait(driver, 30).until(EC.presence_of_element_located((By.ID, "username")))
    time.sleep(1)
    u = driver.find_element(By.ID, "username")
    u.click()
    u.send_keys(USER)
    time.sleep(1)
    driver.find_element(By.CSS_SELECTOR, "button[type='submit']").click()
    time.sleep(2)
    p = WebDriverWait(driver, 30).until(EC.presence_of_element_located((By.ID, "password")))
    p.click()
    p.send_keys(PASSWORD)
    time.sleep(1)
    driver.find_element(By.CSS_SELECTOR, "button[type='submit']").click()
    time.sleep(4)
    url = driver.current_url.lower()
    if "login" in url:
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
                time.sleep(random.randint(60, 90))  # 防风控随机间隔 (与参考项目一致)
        except Exception:
            continue
    return True

# 新流程: 「创建」配置 -> 页面下方配置记录 -> 「下载」.conf (用户实测 2026-10-17)
# 每份配置以证书名称注册; 本脚本默认单证书覆盖全部免费服务器
# (只创建一次, 后续服务器复用同一证书, 避免免费版 key 槽被挤爆)。
CERT_NAME = _env("PROTON_CERT_NAME", "wh-gate")


def _click_text(driver, text, timeout=20):
    el = WebDriverWait(driver, timeout).until(EC.element_to_be_clickable(
        (By.XPATH, f"//*[normalize-space(text())='{text}']")))
    driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", el)
    time.sleep(1)
    try:
        el.click()
    except Exception:
        ActionChains(driver).move_to_element(el).click().perform()
    return el


def ensure_certificate(driver):
    """填证书名 + 选平台 GNU/Linux + 创建 (若已存在同名证书则跳过)。"""
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
        if CERT_NAME in (driver.page_source or ""):
            log("CERT", f"已存在证书 {CERT_NAME}, 跳过创建")
            return True
        _click_text(driver, "创建")
        time.sleep(4)
        log("CERT", f"已创建证书 {CERT_NAME}")
        return True
    except Exception as exc:
        log("CERT", f"创建证书失败: {type(exc).__name__} (站点可能改版)")
        return False


def process_wireguard_tab(driver, download_dir, downloaded_ids):
    """新版创建->下载两步流程 (downloaded_ids 存服务器名, 如 NL-FREE#79)。"""
    try:
        _click_text(driver, "WireGuard")
    except Exception as exc:
        log("WG", f"找不到 WireGuard 页签: {type(exc).__name__} (站点可能改版)")
        return False
    time.sleep(3)
    if not ensure_certificate(driver):
        return False
    new_count = 0
    countries = driver.find_elements(By.CSS_SELECTOR, "details")
    if not countries:
        log("WG", "未找到服务器分组 (选择器失效, 截图已备查)")
        return False
    log("WG", f"发现 {len(countries)} 个分组")
    rows = []
    for c in countries:
        try:
            summary = c.find_element(By.CSS_SELECTOR, "summary").text.strip().split("\n")[0]
        except Exception:
            summary = "?"
        try:
            driver.execute_script("arguments[0].open = true;", c)
            time.sleep(1)
            for r in c.find_elements(By.CSS_SELECTOR, "tr"):
                rows.append((summary, r))
        except Exception:
            continue
    log("WG", f"共 {len(rows)} 台候选服务器")
    for summary, row in rows:
        if new_count >= MAX_DL:
            log("WG", f"本会话上限 {MAX_DL}, 停下 (下次增量继续)")
            return False
        try:
            tds = row.find_elements(By.CSS_SELECTOR, "td")
            sid = tds[0].text.strip() if tds else ""
        except Exception:
            continue
        if not sid or sid in downloaded_ids:
            continue
        creates = row.find_elements(By.XPATH, ".//*[normalize-space(text())='创建']")
        if not creates:
            continue  # 已创建过的行只有「下载」; 本轮只走创建逻辑
        btn = creates[0]
        driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", btn)
        time.sleep(1)
        before = {f for f in os.listdir(download_dir) if f.lower().endswith(".conf")}
        try:
            try:
                btn.click()
            except Exception:
                ActionChains(driver).move_to_element(btn).click().perform()
        except Exception:
            continue
        time.sleep(5)  # 等配置记录生成 (下方列表出现「下载」)
        got = None
        for rec in driver.find_elements(
                By.XPATH, f"//tr[td[normalize-space(text())='{sid}']]"):
            for db in rec.find_elements(By.XPATH, ".//*[normalize-space(text())='下载']"):
                try:
                    db.click()
                    time.sleep(2)
                    got = _wait_new_conf(download_dir, before)
                    break
                except Exception:
                    continue
            if got:
                break
        if got:
            new_count += 1
            downloaded_ids.add(sid)
            log("WG", f"[{summary}] 已创建并下载 {sid} ({got}), 本轮 {new_count}/{MAX_DL}")
        else:
            log("WG", f"{sid} 创建/下载未拿到文件, 跳过")
        time.sleep(random.randint(60, 90))  # 防风控随机间隔 (与参考项目一致)
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

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    if not USER or not PASSWORD:
        die("未设置 PROTON_USER / PROTON_PASS (仓库 Secrets; 账号 2FA 必须关闭)")
    if not ENC_KEY:
        die("未设置 PROTON_ENC_KEY (先用以下命令生成后存入 Secrets: "
            "python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\")")
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
            done = False
            for attempt in (1, 2):
                done = process_wireguard_tab(driver, dl, downloaded)
                if done:
                    break
                log("SESS", f"第 {attempt} 轮达会话上限 {MAX_DL}, 重新登录继续")
                do_logout(driver)
                time.sleep(120)
                if not do_login(driver) or not goto_downloads(driver):
                    break
            do_logout(driver)
        finally:
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
    save_encrypted_store(store)
    save_ids(downloaded)
    log("MERGE", f"合并后库存: {len(store)} 台, 已写回 {os.path.relpath(ENC_PATH, REPO_DIR)}")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        die(f"程序异常: {type(exc).__name__}: {exc}")
