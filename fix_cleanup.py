with open('D:/Users/wh898/PycharmProjects/wh-gate/proton_downloader.py', 'r', encoding='utf-8') as f:
    content = f.read()

old = '''            do_logout(driver)
            # 清理僵尸 ID: 每国只保留负载最低的 PER_COUNTRY 台，多余的全部剔除
            # 必须在 driver.quit() 之前执行，driver 关闭后无法访问页面
            try:
                live_ids = _scan_available_ids(driver)
                if live_ids is None:
                    log("CLEANUP", "扫描失败, 跳过清理, 保留现有记录")
                else:
                    pruned = downloaded - live_ids
                    if pruned:
                        log("CLEANUP", f"清理 {len(pruned)} 条记录 (已下线或负载较高): {sorted(pruned)}")
                    added = live_ids - downloaded
                    if added:
                        log("CLEANUP", f"新增 {len(added)} 条低负载服务器记录: {sorted(added)}")
                    downloaded = live_ids  # 直接用页面当前最低负载名单，确保库存始终 = 国家数 x PER_COUNTRY
                    log("CLEANUP", f"清理后保留 {len(downloaded)} 条, 原记录 {len(download)} 条")
            except Exception as exc:
                log("CLEANUP", f"清理失败 (不影响主流程): {exc}")
        finally:
            try:
                driver.quit()
            except Exception:
                pass'''

new = '''            do_logout(driver)
        finally:
            # 清理必须在 driver.quit() 之前执行
            try:
                live_ids = _scan_available_ids(driver)
                if live_ids is not None:
                    pruned = downloaded - live_ids
                    if pruned:
                        log("CLEANUP", f"清理 {len(pruned)} 条记录 (已下线或负载较高): {sorted(pruned)}")
                    added = live_ids - downloaded
                    if added:
                        log("CLEANUP", f"新增 {len(added)} 条低负载服务器记录: {sorted(added)}")
                    downloaded = live_ids
                    log("CLEANUP", f"清理后保留 {len(downloaded)} 条")
                else:
                    log("CLEANUP", "扫描失败, 跳过清理")
            except Exception as exc:
                log("CLEANUP", f"清理失败 (不影响主流程): {exc}")
            try:
                driver.quit()
            except Exception:
                pass'''

if old in content:
    content = content.replace(old, new)
    with open('D:/Users/wh898/PycharmProjects/wh-gate/proton_downloader.py', 'w', encoding='utf-8') as f:
        f.write(content)
    print('OK: moved cleanup into finally block')
else:
    print('ERROR: pattern not found')
    # debug
    import re
    m = re.search(r'do_logout\(driver\).*?driver\.quit\(\)', content, re.DOTALL)
    if m:
        print('Found:', repr(m.group()[:300]))
