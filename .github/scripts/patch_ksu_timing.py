#!/usr/bin/env python3
"""把 KernelSU 的 setprocattr 钩子对 A/B 两种 payload 的代价真正拉平。

背景：Duck 的 "App Zygote attr/current timing" 用两个等长 payload 反复写
/proc/self/attr/current 计时：
    A = 非法类型，例如 "u:r:ksu:s0"
    B = 同样的内容，前面多一个 '\\n'

第一版补丁只是把 `str[0] != '\\n'` 这个短路去掉，让两种 payload 都进入
backup policy 的解析。但解析的内容不同：B 的首字符是换行，解析器在第一个
字符就失败；A 要读完 type 名字才失败。差异只是从“有没有解析”搬到了
“解析多深”，实测 A−B 从 573ns 降到 209ns，仍然 512/512 同向。

第二版在解析前先做归一化：把前导换行剥掉，两种 payload 解析同一段字节。
memmove 对 A 也照做（lead=0 时是同长度自拷贝），两侧代价差只剩一个字节。
"""
import pathlib
import sys

ORIG_COND = (
    "    if (size && str[0] && str[0] != '\\n') {\n"
    "        if (str[size - 1] == '\\n') {\n"
    "            str[size - 1] = 0;\n"
    "            size--;\n"
    "        }\n"
)
V1_COND = (
    "    if (size && str[0]) {\n"
    "        if (str[size - 1] == '\\n') {\n"
    "            str[size - 1] = 0;\n"
    "            size--;\n"
    "        }\n"
)

NEW_BLOCK = """    if (size) {
        /* 归一化：剥掉前导换行，让 A/B 解析同一段字节。
           lead=0 时也照样 memmove，保证两侧代价一致。 */
        size_t lead = 0;
        while (lead < size && str[lead] == '\\n')
            lead++;
        memmove(str, str + lead, size - lead);
        size -= lead;
        if (size && ((char *)value)[size - 1] == '\\n') {
            ((char *)value)[size - 1] = 0;
            size--;
        }
"""


def main() -> int:
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    targets = [p for p in root.rglob("selinux_hide.c") if "feature" in p.parts]
    if not targets:
        print("[-] 没找到 feature/selinux_hide.c")
        return 1
    for p in targets:
        s = p.read_text()
        if "size_t lead = 0;" in s and "归一化" in s:
            print(f"[=] 已打过 v2 补丁：{p}")
            continue
        for marker in (V1_COND, ORIG_COND):
            if marker in s:
                p.write_text(s.replace(marker, NEW_BLOCK, 1))
                print(f"[+] patched {p}")
                break
        else:
            print(f"[-] {p} 里没有预期的那段代码，KSU 上游可能改过")
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
