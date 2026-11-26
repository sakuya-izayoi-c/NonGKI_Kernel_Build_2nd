#!/usr/bin/env python3
"""给 SUSFS 的 sus_path uid filter 补上 old_bitmap 的 NULL 判断。

背景：fs/susfs.c 里 sus_path uid filter 首次发布位图时，old_bitmap 必然为
NULL（该指针是 static，初始为 NULL）。但两处 kfree_rcu() 都没做判空：

    kfree_rcu(old_bitmap, rcu);            // susfs_set_sus_path_uid_filter
    kfree_rcu(old_bitmap, rcu);            // susfs_sus_path_app_strings_worker

kfree_rcu(ptr, member) 展开成 kfree_call_rcu(&ptr->member, offset)，ptr 为
NULL 时取址仍是 NULL，于是 __call_rcu(NULL) 通过 8 字节对齐检查后直接
`stp xzr, x1, [NULL]`，内核模式写 0 地址 → 无法恢复 → 卡死重启。

同一个文件里的 priority uid filter 两处都写了 `if (old_bitmap)`，只有
sus_path 这组漏了，属于疏漏而非设计。

修法：在两处 sus_path 的 kfree_rcu 前补 `if (old_bitmap)`。语义不变，
只是首次发布时不再调用 kfree_rcu(NULL)。幂等。
"""
import pathlib
import sys

MARKER = "// First publish: old_bitmap is NULL, so never call kfree_rcu(NULL)."

TARGETS = (
    # (锚点：区分两处的上下文, 说明)
    ("\tif (!is_uid_filter_set_before)\n\t\tis_uid_filter_set_before = true;\n\tmutex_unlock(&susfs_mutex_lock_sus_path_uid_filter);\n\tsynchronize_rcu();\n\tkfree_rcu(old_bitmap, rcu);",
     "susfs_set_sus_path_uid_filter"),
    ("\trcu_assign_pointer(sus_path_uid_filter_bitmap, new_bitmap);\n\tnew_bitmap = NULL;\n\tmutex_unlock(&susfs_mutex_lock_sus_path_uid_filter);\n\tsynchronize_rcu();\n\tkfree_rcu(old_bitmap, rcu);",
     "susfs_sus_path_app_strings_worker"),
)

FIXED = (
    "\tif (!is_uid_filter_set_before)\n\t\tis_uid_filter_set_before = true;\n\tmutex_unlock(&susfs_mutex_lock_sus_path_uid_filter);\n\tsynchronize_rcu();\n\t// First publish: old_bitmap is NULL, so never call kfree_rcu(NULL).\n\tif (old_bitmap)\n\t\tkfree_rcu(old_bitmap, rcu);",
    "\trcu_assign_pointer(sus_path_uid_filter_bitmap, new_bitmap);\n\tnew_bitmap = NULL;\n\tmutex_unlock(&susfs_mutex_lock_sus_path_uid_filter);\n\tsynchronize_rcu();\n\t// First publish: old_bitmap is NULL, so never call kfree_rcu(NULL).\n\tif (old_bitmap)\n\t\tkfree_rcu(old_bitmap, rcu);",
)


def patch_text(s: str, name: str) -> str:
    if MARKER in s:
        print(f"[=] 已打过补丁：{name}")
        return s
    for (old, label), new in zip(TARGETS, FIXED):
        n = s.count(old)
        if n != 1:
            raise SystemExit(f"[-] {name}: {label} 锚点命中 {n} 次（期望 1），SUSFS 可能改过")
    for old, new in zip((t[0] for t in TARGETS), FIXED):
        s = s.replace(old, new, 1)
    # 不变式：sus_path 的两处必须都已判空，priority 的两处保持原样
    if s.count("if (old_bitmap)\n\t\tkfree_rcu(old_bitmap, rcu);") != 4:
        raise SystemExit(f"[-] {name}: 判空后的调用点数量不是 4，改动不完整")
    if s.count("kfree_rcu(old_bitmap, rcu);") != 4:
        raise SystemExit(f"[-] {name}: kfree_rcu(old_bitmap) 总数不是 4")
    print(f"[+] patched {name}")
    return s


def main() -> int:
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    targets = [p for p in root.rglob("susfs.c") if p.parent.name in ("fs",)]
    if not targets:
        print("[-] 没找到 fs/susfs.c")
        return 1
    for p in targets:
        s = p.read_text()
        new = patch_text(s, str(p))
        if new != s:
            p.write_text(new)
    return 0


if __name__ == "__main__":
    sys.exit(main())
