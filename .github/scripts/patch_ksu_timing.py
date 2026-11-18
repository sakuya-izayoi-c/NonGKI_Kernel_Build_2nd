#!/usr/bin/env python3
"""让 KernelSU 的 setprocattr 钩子对 A/B 两种 payload 做等价的工作量。

Duck Detector 的 "App Zygote attr/current timing" 用两个字典长度相同的
payload 计时：
  A = 非法类型（不带前导换行）
  B = 同样内容 + 前导换行
两者都应返回 EINVAL。但 KSU 的 my_setprocattr 里：

    if (size && str[0] && str[0] != '\\n') { ... backup policy 解析 ... }

带前导换行的 B 会跳过解析，直接走 prepare_creds()/abort_creds()，比 A 少
一次 policy 查找（放大到几百纳秒，485/512 对同向），于是出现稳定的 A-B 正偏移。

这里把该条件改成 `if (size && str[0])`，让两种 payload 都走同一条解析路径，
返回码不变（纯换行原本也是 -EINVAL），代价被拉平。
"""
import pathlib
import sys

OLD = "if (size && str[0] && str[0] != '\\n') {"
NEW = "if (size && str[0]) {"


def main() -> int:
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    hits = list(root.rglob("selinux_hide.c"))
    targets = [p for p in hits if "feature" in p.parts]
    if not targets:
        print(f"[-] 没找到 feature/selinux_hide.c（扫描了 {len(hits)} 个同名文件）")
        return 1
    for p in targets:
        s = p.read_text()
        if OLD not in s:
            if NEW in s and "等价的工作量" in s:
                print(f"[=] 已打过补丁：{p}")
                continue
            print(f"[-] {p} 里没有预期的那一行，KSU 上游可能改过")
            return 1
        p.write_text(s.replace(OLD, NEW, 1))
        print(f"[+] patched {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
