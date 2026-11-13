#!/usr/bin/env python3
"""TEMPORARY macOS diagnostic (PR #342): which call sets a directory's times
under which Seatbelt rules. Removed once the cause is known.

usage: python3 tmp-times-probe.py <label> <base dir>
"""

import ctypes
import os
import sys

libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)


class Timeval(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_int32)]


class Timespec(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_nsec", ctypes.c_long)]


class Attrlist(ctypes.Structure):
    _fields_ = [
        ("bitmapcount", ctypes.c_ushort),
        ("reserved", ctypes.c_uint16),
        ("commonattr", ctypes.c_uint32),
        ("volattr", ctypes.c_uint32),
        ("dirattr", ctypes.c_uint32),
        ("fileattr", ctypes.c_uint32),
        ("forkattr", ctypes.c_uint32),
    ]


ATTR_CMN_MODTIME = 0x00000400
ATTR_CMN_ACCTIME = 0x00001000
AT_FDCWD = -2
SEC = 1_700_000_000


def res(rc):
    if rc == 0:
        return "ok"
    e = ctypes.get_errno()
    return f"E{e}"


def tv2():
    return (Timeval * 2)(Timeval(SEC, 5000), Timeval(SEC, 5000))


def ts2():
    return (Timespec * 2)(Timespec(SEC, 5_000_000), Timespec(SEC, 5_000_000))


def attrs(bits):
    a = Attrlist()
    a.bitmapcount = 5
    a.commonattr = bits
    n = bin(bits).count("1")
    buf = (Timespec * n)(*[Timespec(SEC, 5_000_000) for _ in range(n)])
    return a, buf


def methods(path):
    out = {}
    p = path.encode()
    out["utimes_explicit"] = res(libc.utimes(p, tv2()))
    out["utimes_null"] = res(libc.utimes(p, None))
    out["utimensat_explicit"] = res(libc.utimensat(AT_FDCWD, p, ts2(), 0))
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError as e:
        out["open"] = f"E{e.errno}"
        fd = None
    if fd is not None:
        out["futimes_explicit"] = res(libc.futimes(fd, tv2()))
        out["futimes_null"] = res(libc.futimes(fd, None))
        out["futimens_explicit"] = res(libc.futimens(fd, ts2()))
        for name, bits in [
            ("fsetattrlist_mod", ATTR_CMN_MODTIME),
            ("fsetattrlist_acc", ATTR_CMN_ACCTIME),
        ]:
            a, buf = attrs(bits)
            out[name] = res(
                libc.fsetattrlist(fd, ctypes.byref(a), buf, ctypes.sizeof(buf), 0)
            )
        os.close(fd)
    for name, bits in [
        ("setattrlist_mod", ATTR_CMN_MODTIME),
        ("setattrlist_acc", ATTR_CMN_ACCTIME),
        ("setattrlist_both", ATTR_CMN_MODTIME | ATTR_CMN_ACCTIME),
    ]:
        a, buf = attrs(bits)
        out[name] = res(libc.setattrlist(p, ctypes.byref(a), buf, ctypes.sizeof(buf), 0))
    return out


def main():
    label, base = sys.argv[1], sys.argv[2]
    d = os.path.join(base, f"{label}-dir")
    f = os.path.join(base, f"{label}-file")
    try:
        os.mkdir(d)
        mk = "ok"
    except OSError as e:
        mk = f"E{e.errno}"
    try:
        with open(f, "w") as fh:
            fh.write("x")
        mf = "ok"
    except OSError as e:
        mf = f"E{e.errno}"
    print(f"[{label}] mkdir={mk} mkfile={mf}")
    for target, path in [("dir", d), ("file", f)]:
        if os.path.exists(path):
            r = methods(path)
            print(f"[{label}] {target}: " + " ".join(f"{k}={v}" for k, v in r.items()))
    sys.stdout.flush()


main()
