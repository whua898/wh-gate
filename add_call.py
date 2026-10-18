with open('D:/Users/wh898/PycharmProjects/wh-gate/proton_downloader.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# 在 downloaded = live_ids 之后插入 reconcile_certificates 调用
for i, line in enumerate(lines):
    if 'downloaded = live_ids' in line and 'reconcile' not in line:
        # 插入调用行
        indent = '                    '
        call_line = indent + 'reconcile_certificates(driver, len(downloaded))\n'
        lines.insert(i + 1, call_line)
        print(f"Inserted reconcile call after line {i+1}")
        break

with open('D:/Users/wh898/PycharmProjects/wh-gate/proton_downloader.py', 'w', encoding='utf-8') as f:
    f.writelines(lines)
print('Done')
