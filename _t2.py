p = "tests/test_bugbox.py"
lines = open(p).read().splitlines(keepends=True)
# reorder lines 649/650 region: prune before the rejection assert
i = next(i for i, l in enumerate(lines) if "expired -> rejected" in l)
assert i >= 1
lines[i] = "    rows = store.prune_expired_sessions()\n"
lines[i + 1] = "    assert rows >= 1\n"
# remove the now-duplicated later prune lines
out = "".join(lines)
dup = """    rows = store.prune_expired_sessions()
    assert rows >= 1
    assert store.session_user(token) is None   # expired -> rejected
"""
if dup in out:
    out = out.replace(dup, """    rows = store.prune_expired_sessions()
    assert rows >= 1
    assert store.session_user(token) is None   # expired -> rejected
""")
open(p, "w").write(out)
print(out.count("prune_expired_sessions()"), out.count("assert rows >= 1"))
