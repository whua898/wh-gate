import re, os

def _norm_name(fn):
    base = os.path.basename(fn)
    base = re.sub(r"\\s*\\(\\d+\\)(?=\\.[^.]+$)", "", base)
    return base.lower()

store = {}
for i in range(25, 30):
    store["confs/ca-free#" + str(i) + ".conf"] = b"data"
for sid in ["mx-free#11", "nl-free#123", "jp-free#20", "us-free#89", "ch-free#7", "no-free#6", "ro-free#24", "sg-free#28"]:
    store["confs/" + _norm_name(sid + ".conf")] = b"data"

downloaded = {"ca-free#25", "ca-free#26", "mx-free#11", "nl-free#123", "jp-free#20", "us-free#89", "ch-free#7", "no-free#6", "ro-free#24", "sg-free#28"}

print("INIT: store=%d, downloaded=%d" % (len(store), len(downloaded)))

for sid in ["ca-free#27", "nl-free#121"]:
    store["confs/" + _norm_name(sid + ".conf")] = b"data"
    downloaded.add(sid)

print("AFTER_DL: store=%d, downloaded=%d" % (len(store), len(downloaded)))

live_ids = {"ca-free#27", "mx-free#11", "no-free#6", "sg-free#28", "jp-free#20", "pl-free#13", "ch-free#7", "ro-free#24", "us-free#89", "nl-free#121"}

downloaded = live_ids
print("AFTER_CLEANUP_IDS: %d -> %s" % (len(downloaded), sorted(downloaded)))

pruned_store = {k: v for k, v in store.items() if any(_norm_name(sid + ".conf") == k or k.endswith(_norm_name(sid + ".conf")) for sid in downloaded)}
print("AFTER_CLEANUP_STORE: %d -> %d" % (len(store), len(pruned_store)))
print("FINAL: %d configs, %d IDs" % (len(pruned_store), len(downloaded)))
