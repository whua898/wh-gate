with open('D:/Users/wh898/PycharmProjects/wh-gate/proton_downloader.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

new_func = '''def reconcile_certificates(driver, keep_count):
    """裁剪证书: 页面证书数超过 keep_count 时吊销多余者，确保始终 = 库存数。"""
    try:
        # 导航到 WireGuard tab
        try:
            _click_text(driver, "WireGuard", timeout=15)
        except Exception:
            pass
        time.sleep(0.5)

        # 收集所有可删除的证书条目
        certs = []
        for d in driver.find_elements(By.TAG_NAME, "details"):
            try:
                if _is_certificate_entry(d):
                    summary = d.find_element(By.TAG_NAME, "summary")
                    name = summary.text.strip()[:60]
                    delete_btn = _find_delete_btn(d)
                    if delete_btn:
                        certs.append((name, delete_btn))
            except Exception:
                continue

        total = len(certs)
        if total <= keep_count:
            log("CERT", f"证书 {total} 台 <= 库存 {keep_count} 台, 无需清理")
            return 0

        to_revoke = total - keep_count
        log("CERT", f"裁剪证书: {total} 台 -> 保留 {keep_count} 台, 吊销 {to_revoke} 台")
        revoked = 0
        for name, btn in certs[to_revoke:]:
            try:
                driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", btn)
                time.sleep(0.3)
                try:
                    btn.click()
                except Exception:
                    driver.execute_script("arguments[0].click();", btn)
                # 等待确认对话框
                try:
                    confirm = WebDriverWait(driver, 5).until(
                        EC.element_to_be_clickable((By.XPATH,
                            "//button[contains(text(), '吊销') or normalize-space(text())='吊销']")))
                    confirm.click()
                    revoked += 1
                    log("CERT", f"  已吊销: {name}")
                except Exception:
                    log("CERT_DEBUG", f"  未找到确认按钮，跳过: {name}")
            except Exception as exc:
                log("CERT_DEBUG", f"  吊销失败: {name} - {exc}")
            time.sleep(0.5)

        log("CERT", f"裁剪完成: 吊销 {revoked} 台, 剩余 {total - revoked} 台")
        return revoked
    except Exception as exc:
        log("CERT", f"证书裁剪异常 (不影响主流程): {exc}")
        return 0


'''

# 在 _find_delete_btn (line 414, 0-indexed 413) 之前插入
insert_pos = None
for i, line in enumerate(lines):
    if 'def _find_delete_btn(cert_item):' in line:
        insert_pos = i
        break

if insert_pos is None:
    print("ERROR: could not find _find_delete_btn")
else:
    lines.insert(insert_pos, new_func)
    with open('D:/Users/wh898/PycharmProjects/wh-gate/proton_downloader.py', 'w', encoding='utf-8') as f:
        f.writelines(lines)
    print(f"Inserted at line {insert_pos + 1}")
