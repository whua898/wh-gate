#!/usr/bin/env python3
import re, os

def _norm_name(fn):
    base = os.path.basename(fn)
    base = re.sub(r'\s*\(\d+\)(?=\.[^.]+$)', '', base)
    return base.lower()

# 模拟完整流程
store = {}
for i in range(25, 30):
    store['confs/ca-free#' + str(i) + '.conf'] = b'data'
for sid in ['mx-free#11', 'nl-free#123', 'jp-free#20', 'us-free#89', 'ch-free#7', 'no-free#6', 'ro-free#24', 'sg-free#28']:
    store['confs/' + _norm_name(sid + '.conf')] = b'data'

downloaded = {'ca-free#25', 'ca-free#26', 'mx-free#11', 'nl-free#123', 
              'jp-free#20', 'us-free#89', 'ch-free#7', 'no-free#6', 'ro-free#24', 'sg-free#28'}

print('初始: store=%d, downloaded=%d' % (len(store), len(download)))

# 本次下载了 CA-FREE#27 和 NL-FREE#121
for sid in ['ca-free#27', 'nl-free#121']:
    store['confs/' + _norm_name(sid + '.conf')] = b'data'
    downloaded.add(sid)

print('下载后: store=%d, downloaded=%d' % (len(store), len(download)))

# 页面扫描保留每国最低负载的 1 台
live_ids = {'ca-free#27', 'mx-free#11', 'no-free#6', 'sg-free#28', 
            'jp-free#20', 'pl-free#13', 'ch-free#7', 'ro-free#24', 
            'us-free#89', 'nl-free#121'}

downloaded = downloaded & live_ids
print('清理后 downloaded: %d 条 -> %s' % (len(download), sorted(download)))

pruned_store = {k: v for k, v in store.items()
                if any(_norm_name(sid + '.conf') == k or k.endswith(_norm_name(sid + '.conf'))
                       for sid in downloaded)}
print('裁剪后 store: %d 条 -> %d 条' % (len(store), len(pruned_store)))
print('最终: %d 台配置, %d 条 ID' % (len(pruned_store), len(download)))
