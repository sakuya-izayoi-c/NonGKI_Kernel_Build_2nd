#!/usr/bin/env python3
"""按 KernelSU 上游 #3981 的思路，给 BakaSU 的 setprocattr 补上 stock 形状的快速拒绝。

背景：Duck 的 attr/current 计时用两个等长 payload，A 是 live policy 里不存在的
类型，B 是同样的串前面加一个换行。stock 的 security_context_to_sid() 在类型
查表那一步就失败返回 EINVAL，只做一次解析、一次分配。

BakaSU 的 ksu_security_context_to_sid() 为了同时查 backup policy，会把 payload
复制两份并逐字段比对两套策略，失败前已经付出两次 kmemdup_nul 和两轮符号表
查找。于是 A 比 B 贵出几百纳秒，配对计时就是正的。

上游 #3981 的做法是「先在 live policy 上解析一次，type 查不到就立刻 EINVAL」。
这里用更小的一步做同一件事：在两个 kmemdup_nul 之前，先把 user/role/type 三个
字段在栈上切出来，用 orig_policydb（调用方传入的 live policy）查一次 type；
查不到就直接返回 -EINVAL。行为与之前一致（这类 context 本来就该 EINVAL），
只是代价回到 stock 的水平。

只改 < 5.10 / 非 selinux_policy 结构体的那条分支——那条分支的函数签名里
orig_policydb 就是 live policy；5.10+ 的变体在函数体里重新赋值该名字，保持原样。
"""
import pathlib
import sys

ANCHOR_FN = "static int ksu_security_context_to_sid(struct policydb *orig_policydb, struct sidtab *orig_sidtab,"

ANCHOR_BODY = """    /* An empty security context is never valid. */
    if (!scontext_len)
        return -EINVAL;
"""

HELPER = '''
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0) && !defined(KSU_COMPAT_HAS_SELINUX_POLICY_STRUCT)
#define KSU_CONTEXT_TYPE_SCAN_MAX 128

/*
 * Caveat:  Does not mutate scontext; scans a bounded copy.
 *
 * Returns true when the live policy does not define the context's type, which is
 * exactly where stock security_context_to_sid() fails. Rejecting it here keeps an
 * invalid type as cheap as stock instead of paying for the dual-policy parse and
 * its two string copies.
 */
static bool ksu_context_type_is_missing(struct policydb *orig_policydb, const char *scontext, u32 scontext_len)
{
    char buf[KSU_CONTEXT_TYPE_SCAN_MAX];
    char *p = buf, *type;
    int i;

    if (!scontext_len || scontext_len >= sizeof(buf))
        return false;

    memcpy(buf, scontext, scontext_len);
    buf[scontext_len] = 0;

    for (i = 0; i < 2; i++) {
        while (*p && *p != ':')
            p++;
        if (!*p)
            return false;
        *p++ = 0;
    }

    type = p;
    while (*p && *p != ':')
        p++;
    if (!*p)
        return false;
    *p = 0;

    return symtab_search(&orig_policydb->p_types, type) == NULL;
}
#endif

'''

FAST_PATH = """    /* An empty security context is never valid. */
    if (!scontext_len)
        return -EINVAL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0) && !defined(KSU_COMPAT_HAS_SELINUX_POLICY_STRUCT)
    /* Stock-shaped fast reject: an unknown type costs one lookup, not a dual parse. */
    if (ksu_context_type_is_missing(orig_policydb, scontext, scontext_len))
        return -EINVAL;
#endif
"""


def main() -> int:
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    targets = [p for p in root.rglob("selinux_hide.c") if "feature" in p.parts]
    if not targets:
        print("[-] 没找到 feature/selinux_hide.c")
        return 1

    for p in targets:
        s = p.read_text()
        if "ksu_context_type_is_missing" in s:
            print(f"[=] 已打过补丁：{p}")
            continue
        if ANCHOR_FN not in s or ANCHOR_BODY not in s:
            print(f"[-] {p} 里没找到预期锚点，BakaSU 上游可能改过")
            return 1
        s = s.replace(ANCHOR_FN, HELPER.lstrip("\n") + ANCHOR_FN, 1)
        s = s.replace(ANCHOR_BODY, FAST_PATH, 1)
        p.write_text(s)
        print(f"[+] patched {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
