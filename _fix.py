with open('D:/Users/wh898/PycharmProjects/wh-gate/proton_downloader.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Lines 462-471 (1-indexed) = indices 461-470 (0-indexed)
# Replace with retry logic
new_block = [
    '                # Retry 3 times for revoke confirmation dialog\n',
    '                confirmed = False\n',
    '                for _att in range(3):\n',
    '                    try:\n',
    "                        btns = driver.find_elements(By.XPATH, \"//button[normalize-space(text())='鍚婇攢']\")\n",
    '                        if btns:\n',
    '                            b = btns[-1]\n',
    "                            driver.execute_script(\"arguments[0].scrollIntoView({block: 'center'});\", b)\n",
    '                            time.sleep(0.2)\n',
    '                            try:\n',
    '                                b.click()\n',
    '                            except Exception:\n',
    "                                driver.execute_script(\"arguments[0].click();\", b)\n",
    '                            confirmed = True\n',
    '                            revoked += 1\n',
    '                            log("CERT", f"  宸插悐閿€: {name}")\n',
    '                            break\n',
    '                    except Exception:\n',
    '                        pass\n',
    '                    time.sleep(1)\n',
    '                if not confirmed:\n',
    '                    log("CERT_DEBUG", f"  鏈湡埌纭��轰箻閽�紝璺宠繃: {name}")\n',
]

lines[461:471] = new_block

with open('D:/Users/wh898/PycharmProjects/wh-gate/proton_downloader.py', 'w', encoding='utf-8') as f:
    f.writelines(lines)
print('Done')
