#!/usr/bin/env python3
"""让 BakaSU 4.9 的 setprocattr 在分配和整段解析之前拒掉未知 type。

背景：Polaris（4.9，KSU_COMPAT_USE_SELINUX_STATE）里，写 attr/current 的未知 type
会走 security_context_to_sid_live()：先 kmemdup_nul 一份堆内存，再取策略读锁，
然后 backup_string_to_context_struct() 依次查 user / role / type。type 查不到时
这些代价已经付完。而换行开头的 payload 在 my_setprocattr 里就跳过解析，只付
prepare_creds/abort_creds。检测器对同一长度的 A（未知 type）与 B（首字节换行）
做配对计时，A 会稳定偏贵。

这里在 kmemdup_nul 之前加一次"type 是否存在于 live 策略"的检查：查不到直接
-EINVAL。返回值语义不变（原本也是 -EINVAL），KSU 注入的类型仍在 live 表里，
照旧进入完整解析并由原始符号校验拒绝。只在 <5.10 且非 selinux_policy 结构体的
旧内核路径生效；5.10+ 分支不动。

幂等：已打过补丁时直接跳过。
"""
import pathlib
import sys

ANCHOR_SIG = "static int security_context_to_sid_live(const char *scontext, u32 scontext_len, u32 *sid)\n{"

ANCHOR_BODY = """    /* An empty security context is never valid. */
    if (!scontext_len)
        return -EINVAL;

    /* Copy the string to allow changes and ensure a NUL terminator */
    scontext2 = kmemdup_nul(scontext, scontext_len, GFP_KERNEL);"""

HELPER = '''
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0) && !defined(KSU_COMPAT_HAS_SELINUX_POLICY_STRUCT)
#define KSU_CONTEXT_TYPE_SCAN_MAX 128

/*
 * Does not mutate scontext; scans a bounded stack copy. Returns true when the live
 * policy does not define the context's type, which is exactly where stock's
 * security_context_to_sid() fails. Rejecting it there keeps an unknown type as
 * cheap as stock instead of paying a heap copy, the policy lock and the parse.
 */
static bool ksu_context_type_is_missing(struct policydb *live_pol, const char *scontext, u32 scontext_len)
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

    return symtab_search(&live_pol->p_types, type) == NULL;
}

static struct policydb *ksu_legacy_live_policydb(void)
{
#if defined(KSU_COMPAT_USE_SELINUX_STATE)
    return &selinux_state.ss->policydb;
#else
    return &policydb;
#endif
}
#endif

'''

FAST_PATH = """    /* An empty security context is never valid. */
    if (!scontext_len)
        return -EINVAL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0) && !defined(KSU_COMPAT_HAS_SELINUX_POLICY_STRUCT)
    /* Stock fails an unknown type before allocating; keep that shape. */
    {
        bool type_missing;

        ksu_lock_sepolicy_legacy();
        type_missing = ksu_context_type_is_missing(ksu_legacy_live_policydb(), scontext, scontext_len);
        ksu_unlock_sepolicy_legacy();
        if (type_missing)
            return -EINVAL;
    }
#endif

    /* Copy the string to allow changes and ensure a NUL terminator */
    scontext2 = kmemdup_nul(scontext, scontext_len, GFP_KERNEL);"""

MARKER = "Stock fails an unknown type before allocating"


def patch_text(s: str, name: str) -> str:
    if MARKER in s:
        print(f"[=] 已打过补丁：{name}")
        return s
    if s.count(ANCHOR_SIG) != 1:
        raise SystemExit(f"[-] {name} 里 security_context_to_sid_live 定义锚点不唯一，BakaSU 可能改过")
    if s.count(ANCHOR_BODY) != 1:
        raise SystemExit(f"[-] {name} 里 kmemdup_nul 之前的空上下文判断锚点不唯一")
    for need in ("ksu_lock_sepolicy_legacy();", "symtab_search(", "ksu_type_is_original("):
        if need not in s:
            raise SystemExit(f"[-] {name} 缺少 {need}，不是预期的 4.9 布局")
    s = s.replace(ANCHOR_SIG, HELPER.lstrip("\n") + ANCHOR_SIG, 1)
    s = s.replace(ANCHOR_BODY, FAST_PATH, 1)
    # 顺序不变式：快速拒绝必须在唯一一次 kmemdup_nul 之前，且 helper 定义在使用点之前
    i_def = s.index("static bool ksu_context_type_is_missing(")
    i_use = s.index("type_missing = ksu_context_type_is_missing(")
    i_dup = s.index("scontext2 = kmemdup_nul(scontext, scontext_len, GFP_KERNEL);", i_use)
    if not i_def < i_use < i_dup:
        raise SystemExit(f"[-] {name} 顺序校验失败")
    if s.count("scontext2 = kmemdup_nul(scontext, scontext_len, GFP_KERNEL);") != 1:
        raise SystemExit(f"[-] {name} 出现多处 kmemdup_nul，锚点可能串到了别的函数")
    print(f"[+] patched {name}")
    return s


def main() -> int:
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    targets = sorted(root.rglob("selinux_hide_auto.c"))
    if not targets:
        print("[-] 没找到 feature/selinux_hide/selinux_hide_auto.c")
        return 1
    for p in targets:
        s = p.read_text()
        new = patch_text(s, str(p))
        if new != s:
            p.write_text(new)
    return 0


if __name__ == "__main__":
    sys.exit(main())
