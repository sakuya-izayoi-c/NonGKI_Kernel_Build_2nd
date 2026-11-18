#!/usr/bin/env python3
"""给 4.9 的 shmem 补上 F_SEAL_FUTURE_WRITE（Linux 5.1 引入），让 ART 走 memfd 而非 ashmem。

背景：ART 的 JitMemoryRegion::CreateZygoteMemory() 先用 IsSealFutureWriteSupported()
探测内核认不认 F_SEAL_FUTURE_WRITE，认就用 memfd_create("jit-zygote-cache",
MFD_ALLOW_SEALING)，不认就打一行 "Falling back to ashmem implementation for JIT
zygote mapping" 退回 ashmem。

4.9 只有到 F_SEAL_WRITE(0x0008) 的四个 seal，于是 zygote 的 JIT 共享区变成
/dev/ashmem，被 Duck 当成 "Executable ashmem mapping" 判 High。补上 0x10 之后
ART 改用 memfd，映射名是 /memfd:jit-zygote-cache，落在它自己的 JIT 白名单里。

移植自 v5.1 mm/shmem.c：seal 位、mmap 拦截、write_begin 与 punch-hole 的写检查。
"""
import pathlib
import re
import sys

UAPI_OLD = "#define F_SEAL_WRITE\t0x0008\t/* prevent writes */"
UAPI_NEW = (
    "#define F_SEAL_WRITE\t0x0008\t/* prevent writes */\n"
    "#define F_SEAL_FUTURE_WRITE\t0x0010\t/* prevent future writes while mapped */"
)

ALL_SEALS_RE = re.compile(
    r"#define F_ALL_SEALS \(F_SEAL_SEAL \| \\\s*\n\s*F_SEAL_SHRINK \| \\\s*\n\s*F_SEAL_GROW \| \\\s*\n\s*F_SEAL_WRITE\)"
)
ALL_SEALS_NEW = (
    "#define F_ALL_SEALS (F_SEAL_SEAL | \\\n"
    "\t\t     F_SEAL_SHRINK | \\\n"
    "\t\t     F_SEAL_GROW | \\\n"
    "\t\t     F_SEAL_WRITE | \\\n"
    "\t\t     F_SEAL_FUTURE_WRITE)"
)

MMAP_OLD = """static int shmem_mmap(struct file *file, struct vm_area_struct *vma)
{
\tfile_accessed(file);
"""
MMAP_NEW = """static int shmem_mmap(struct file *file, struct vm_area_struct *vma)
{
\tstruct shmem_inode_info *info = SHMEM_I(file_inode(file));

\tif (info->seals & F_SEAL_FUTURE_WRITE) {
\t\t/*
\t\t * New PROT_WRITE and MAP_SHARED mmaps are not allowed when
\t\t * the "future write" seal is active.
\t\t */
\t\tif ((vma->vm_flags & VM_SHARED) && (vma->vm_flags & VM_WRITE))
\t\t\treturn -EPERM;

\t\t/*
\t\t * A MAP_SHARED read-only mapping is still allowed, so make sure
\t\t * mprotect() cannot turn it writable later.
\t\t */
\t\tvma->vm_flags &= ~VM_MAYWRITE;
\t}

\tfile_accessed(file);
"""

WRITE_BEGIN_OLD = "\tif (info->seals & F_SEAL_WRITE)\n\t\t\treturn -EPERM;"
WRITE_BEGIN_NEW = "\tif (info->seals & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE))\n\t\t\treturn -EPERM;"

PUNCH_OLD = "\t\tif (info->seals & F_SEAL_WRITE) {"
PUNCH_NEW = "\t\tif (info->seals & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE)) {"


def patch_file(path: pathlib.Path, edits) -> bool:
    s = path.read_text()
    orig = s
    for old, new, count in edits:
        if new in s:
            continue
        n = s.count(old)
        if n != count:
            print(f"[-] {path}: 期望 {count} 处锚点，实际 {n} 处：{old.splitlines()[0][:60]}")
            return False
        s = s.replace(old, new)
    if s == orig:
        print(f"[=] 已打过补丁：{path}")
        return True
    path.write_text(s)
    print(f"[+] patched {path}")
    return True


def main() -> int:
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    shmem = root / "mm/shmem.c"
    uapi = root / "include/uapi/linux/fcntl.h"
    for p in (shmem, uapi):
        if not p.is_file():
            print(f"[-] 找不到 {p}")
            return 1

    ok = patch_file(uapi, [(UAPI_OLD, UAPI_NEW, 1)])

    s = shmem.read_text()
    if "F_SEAL_FUTURE_WRITE" not in s:
        if len(ALL_SEALS_RE.findall(s)) != 1:
            print("[-] mm/shmem.c: F_ALL_SEALS 锚点不唯一")
            return 1
        s = ALL_SEALS_RE.sub(ALL_SEALS_NEW, s)
        shmem.write_text(s)
        print("[+] mm/shmem.c: F_ALL_SEALS 已扩")

    ok = patch_file(shmem, [
        (MMAP_OLD, MMAP_NEW, 1),
        (WRITE_BEGIN_OLD, WRITE_BEGIN_NEW, 1),
        (PUNCH_OLD, PUNCH_NEW, 1),
    ]) and ok

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
