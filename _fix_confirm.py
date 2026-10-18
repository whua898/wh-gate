with open('D:/Users/wh898/PycharmProjects/wh-gate/proton_downloader.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Find and replace the confirm block
for i in range(len(lines)):
    if '绛夊緟纭��轰箅' in lines[i] and 'WebDriverWait' in lines[i+1]:
        print(f"Found at line {i+1}")
        # Find end
        for j in range(i, min(i+15, len(lines))):
            if '璺宠繃: {name}' in lines[j] and 'CERT_DEBUG' in lines[j]:
                print(f"End at line {j+1}")
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
                lines[i:j+1] = new_block
                with open('D:/Users/wh898/PycharmProjects/wh-gate/proton_downloader.py', 'w', encoding='utf-8') as f:
                    f.writelines(lines)
                print('Done')
                break
        break
else:
    print('Confirm block not found')
