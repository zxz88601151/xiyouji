# -*- coding: utf-8 -*-
"""reset_admin.js 离线维护工具测试 (G4: owner 忘记密码时的恢复入口)

覆盖: dry-run 不落盘 / 重置密码+吊销会话 / 服务运行中拒绝改盘 / 备份生成 /
      改登录名 / 新建 owner / 参数与错误路径 / 新凭据能真登录。

隔离: 全程用临时数据目录 + 独立端口, 不碰真实 server/data。
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import http.cookiejar
import urllib.request
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCRIPT = os.path.join(ROOT, "server", "reset_admin.js")
SERVER = os.path.join(ROOT, "server", "server.js")
NODE = os.environ.get("HZ_NODE", "node")
PORT = int(os.environ.get("HZ_TEST_PORT", "3013"))
BASE = "http://127.0.0.1:%d" % PORT

PASS, FAIL = [], []
DATA = None
_srv = None

# 让中文结果在 GBK 控制台上也能读
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def check(name, ok, extra=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            ("- " + str(extra)) if extra else ""))


def post(path, body=None, jar=None, timeout=8):
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar)) \
        if jar is not None else urllib.request.build_opener()
    req = urllib.request.Request(BASE + path, data=json.dumps(body or {}).encode("utf-8"),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8") or "{}")
        except Exception:
            return e.code, {}
    except Exception as e:
        return 0, {"msg": str(e)}


def wait_up(sec=20):
    for _ in range(sec * 5):
        st, _ = post("/api/ping", {}, None, 2)
        if st == 200:
            return True
        time.sleep(0.2)
    return False


def start_server():
    global _srv
    env = dict(os.environ, PORT=str(PORT), HZ_DATA_DIR=DATA)
    _srv = subprocess.Popen([NODE, SERVER], env=env, cwd=os.path.join(ROOT, "server"),
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    assert wait_up(), "测试服务启动失败"


def stop_server():
    global _srv
    if _srv:
        _srv.terminate()
        try:
            _srv.wait(10)
        except Exception:
            _srv.kill()
        _srv = None
    time.sleep(0.4)


def run_cli(*args, expect_ok=True):
    """跑 reset_admin.js, 返回 (returncode, stdout+stderr)

    Node 输出是 UTF-8, Windows 上 text=True 会按 GBK 解码成乱码,
    中文断言和从输出里提取密码的正则都会失配, 所以显式按 utf-8 解。
    """
    env = dict(os.environ, HZ_DATA_DIR=DATA)
    p = subprocess.run([NODE, SCRIPT] + list(args), env=env, cwd=os.path.join(ROOT, "server"),
                       capture_output=True, timeout=30)
    out = ((p.stdout or b"") + (p.stderr or b"")).decode("utf-8", "replace")
    if expect_ok is not None:
        check("CLI %s 退出码=%s" % (" ".join(args), p.returncode),
              (p.returncode == 0) == bool(expect_ok), out.strip()[-160:])
    return p.returncode, out


def read_admins():
    with open(os.path.join(DATA, "admins.json"), encoding="utf-8") as f:
        return json.load(f)


def read_sessions():
    p = os.path.join(DATA, "sessions.json")
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def initial_password():
    with open(os.path.join(DATA, "owner_password.txt"), encoding="utf-8") as f:
        for line in f:
            if line.startswith("初始密码:"):
                return line.split(":", 1)[1].strip()
    raise RuntimeError("没有 owner_password.txt")


def pw_of(out):
    m = re.search(r"密码=(\S+)", out)
    return m.group(1) if m else ""


def main():
    global DATA
    if not shutil.which(NODE):
        print("找不到 node (可设 HZ_NODE 指定), 跳过")
        sys.exit(2)
    DATA = tempfile.mkdtemp(prefix="hz_reset_cli_")
    print("reset_admin.js 测试  数据目录=%s  端口=%d\n" % (DATA, PORT))
    try:
        # ---------- 1. 首次启动生成 owner ----------
        print("[1] 首次启动生成 owner")
        start_server()
        pw0 = initial_password()
        jar = http.cookiejar.CookieJar()
        st, d = post("/api/admin/login", {"username": "admin", "password": pw0}, jar)
        check("初始 owner 可登录", st == 200 and d.get("ok"), d)
        st, d = post("/api/admin/keys", {}, jar)
        check("未改密前业务 API 被拒", st == 403, d.get("msg"))

        # ---------- 2. 服务运行中必须拒绝改盘 ----------
        print("[2] 服务运行中拒绝改盘 (防止内存回写覆盖)")
        pidp = os.path.join(DATA, "hzkey.pid")
        with open(pidp, "w") as f:
            f.write(str(_srv.pid))
        before = open(os.path.join(DATA, "admins.json"), "rb").read()
        rc, out = run_cli("--reset", "--user", "admin", "--generate", expect_ok=None)
        check("运行中拒绝执行 (退出码非 0)", rc != 0, out.strip()[-120:])
        check("拒绝原因是检测到 pidfile", "服务正在运行" in out, out.strip()[-80:])
        check("运行中未改动盘", open(os.path.join(DATA, "admins.json"), "rb").read() == before)
        os.remove(pidp)

        stop_server()

        # ---------- 3. dry-run ----------
        print("[3] dry-run 不落盘")
        before = open(os.path.join(DATA, "admins.json"), "rb").read()
        rc, out = run_cli("--dry-run", "--reset", "--user", "admin", "--generate")
        check("dry-run 不写入", open(os.path.join(DATA, "admins.json"), "rb").read() == before)
        check("dry-run 提示未写入", "dry-run" in out, out.strip()[-80:])

        # ---------- 4. 列出账号 ----------
        print("[4] --list")
        rc, out = run_cli("--list")
        check("list 显示 admin 与 owner 角色", "admin" in out and "owner" in out, out.strip()[:120])

        # ---------- 5. 重置密码 + 吊销会话 ----------
        print("[5] --reset --generate")
        n_sess_before = len(read_sessions())
        rc, out = run_cli("--reset", "--user", "admin", "--generate")
        newpw = pw_of(out)
        check("生成了符合强度规则的密码",
              len(newpw) >= 8 and bool(re.search(r"[A-Za-z]", newpw)) and bool(re.search(r"\d", newpw)),
              newpw)
        check("admin 密码哈希已更新", read_admins()["admin"]["hash"] != "" and
              out.find("已落盘") > 0)
        check("重置后该账号会话被清空", len(read_sessions()) == 0,
              "%d -> %d" % (n_sess_before, len(read_sessions())))
        baks = [f for f in os.listdir(DATA) if "pre-reset" in f]
        check("改动前已自动备份 admins/sessions", len(baks) >= 1, baks)

        start_server()
        st, d = post("/api/admin/login", {"username": "admin", "password": newpw},
                     http.cookiejar.CookieJar())
        check("新密码可登录 (G4 恢复成功)", st == 200 and d.get("ok"), d)
        check("命令行重置后不再强制改密", not d.get("must_change"), d)
        st, d = post("/api/admin/login", {"username": "admin", "password": pw0},
                     http.cookiejar.CookieJar())
        check("旧初始密码失效 401", st == 401, d.get("msg"))
        stop_server()

        # ---------- 6. --password 指定 + 强度校验 ----------
        print("[6] --password 强度校验")
        rc, out = run_cli("--reset", "--user", "admin", "--password", "12345678", expect_ok=None)
        check("纯数字被拒", rc != 0 and "字母和数字" in out, out.strip()[-80:])
        rc, out = run_cli("--reset", "--user", "admin", "--password", "abcdefg", expect_ok=None)
        check("长度不足被拒", rc != 0 and "至少" in out, out.strip()[-80:])
        rc, out = run_cli("--reset", "--user", "nosuch", "--generate", expect_ok=None)
        check("重置不存在账号被拒", rc != 0 and "不存在" in out, out.strip()[-80:])
        rc, out = run_cli("--reset", "--user", "admin", "--password", "Ops@Fix2026x")
        start_server()
        st, d = post("/api/admin/login", {"username": "admin", "password": "Ops@Fix2026x"},
                     http.cookiejar.CookieJar())
        check("指定密码生效", st == 200 and d.get("ok"), d)
        stop_server()

        # ---------- 7. 改登录名 ----------
        print("[7] --rename")
        rc, out = run_cli("--rename", "--user", "admin", "--to", "axin")
        adm = read_admins()
        check("改名后键换成新名", "axin" in adm and "admin" not in adm, list(adm))
        check("改名保留 owner 角色与备注",
              adm["axin"]["role"] == "owner" and adm["axin"]["note"] == "初始管理员", adm["axin"].get("role"))
        rc, out = run_cli("--rename", "--user", "axin", "--to", "axin2", "--dry-run")
        start_server()
        st, d = post("/api/admin/login", {"username": "axin", "password": "Ops@Fix2026x"},
                     http.cookiejar.CookieJar())
        check("用新登录名可登录", st == 200 and d.get("ok"), d)
        st, d = post("/api/admin/login", {"username": "admin", "password": "Ops@Fix2026x"},
                     http.cookiejar.CookieJar())
        check("旧登录名不再可用 401", st == 401, d.get("msg"))
        stop_server()

        # ---------- 8. 新建第二个 owner ----------
        print("[8] --create owner")
        rc, out = run_cli("--create", "--user", "backup_owner", "--role", "owner", "--generate")
        adm = read_admins()
        check("新 owner 建出且唯一 owner 不再是单点",
              len([a for a in adm.values() if a["role"] == "owner"]) == 2, list(adm))
        check("新建账号首次登录需改密", adm["backup_owner"]["must_change"] is True)
        pw2 = pw_of(out)
        start_server()
        st, d = post("/api/admin/login", {"username": "backup_owner", "password": pw2},
                     http.cookiejar.CookieJar())
        check("新 owner 可登录", st == 200 and d.get("ok") and d.get("must_change"), d)
        st, d = post("/api/admin/keys", {}, http.cookiejar.CookieJar())
        check("未登录访问管理 API 仍被拒", st == 401, d.get("msg"))
        stop_server()

        # ---------- 9. 错误路径与非法角色 ----------
        print("[9] 错误路径")
        rc, out = run_cli("--create", "--user", "backup_owner", "--role", "owner",
                          "--generate", expect_ok=None)
        check("重名创建被拒", rc != 0 and "已存在" in out, out.strip()[-80:])
        rc, out = run_cli("--create", "--user", "roletest", "--role", "god",
                          "--password", "Good@2026x", expect_ok=None)
        check("非法角色被拒", rc != 0 and "--role" in out, out.strip()[-80:])
        rc, out = run_cli("--create", "--user", "x", "--role", "viewer",
                          "--password", "Good@2026x", expect_ok=None)
        check("非法登录名被拒", rc != 0 and "3-24" in out, out.strip()[-80:])
        rc, out = run_cli("--list", "--reset", "--user", "axin", expect_ok=None)
        check("多操作互斥被拒", rc != 0 and "只能选一个" in out, out.strip()[-80:])
        rc, out = run_cli(expect_ok=None)
        check("无参数时给出用法并失败", rc != 0 and "用法" in out, out.strip()[-80:])

        # ---------- 10. 禁用账号: 光改密码登不上, --enable 才能 ----------
        print("[10] 禁用账号恢复")
        adm = read_admins()
        adm["backup_owner"]["disabled"] = True
        with open(os.path.join(DATA, "admins.json"), "w", encoding="utf-8") as f:
            json.dump(adm, f)
        rc, out = run_cli("--reset", "--user", "backup_owner", "--password", "Back@2026y")
        check("禁用账号重置时给出提示", "禁用状态" in out, out.strip()[-100:])
        start_server()
        st, d = post("/api/admin/login", {"username": "backup_owner", "password": "Back@2026y"},
                     http.cookiejar.CookieJar())
        check("禁用状态下新密码也登不上", st == 401, d.get("msg"))
        stop_server()
        rc, out = run_cli("--reset", "--user", "backup_owner", "--password", "Back@2026z",
                          "--enable")
        check("--enable 解除禁用", read_admins()["backup_owner"]["disabled"] is False)

        print("\n" + "=" * 60)
        print("结果: %d 通过 / %d 失败" % (len(PASS), len(FAIL)))
        if FAIL:
            print("失败项: " + ", ".join(FAIL))
            sys.exit(1)
    finally:
        stop_server()
        shutil.rmtree(DATA, ignore_errors=True)


if __name__ == "__main__":
    main()
