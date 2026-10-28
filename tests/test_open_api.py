# -*- coding: utf-8 -*-
"""开放接口 /api/open/v1 集成测试 (服务端到服务端, HMAC 签名)

覆盖: 签名校验 (未知应用/错密钥/改报文/时间戳/nonce 重放/格式) /
      代注册 (幂等 / 用户名冲突 / 自动用户名 / 初始密码) / 状态查询 /
      加时长 / 令牌校验 / 登录 (与客户端共用一套会话) / 审计 / 未启用 501。

隔离: 临时数据目录 + 独立端口 (默认 3014), 自己起停服务, 不碰真实 server/data。
"""
import hashlib
import hmac
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SERVER = os.path.join(ROOT, "server", "server.js")
NODE = os.environ.get("HZ_NODE", "node")
PORT = int(os.environ.get("HZ_OPEN_TEST_PORT", "3014"))
BASE = "http://127.0.0.1:%d" % PORT
APP_ID = "apptest"
APP_SEC = "0123456789abcdefSECRET"
APP2_ID = "apptwo"
APP2_SEC = "fedcba9876543210SECRET"

PASS, FAIL = [], []
DATA = None
_srv = None
_nonce_seq = 0

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def check(name, ok, extra=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            ("- " + str(extra)) if extra else ""))


def _sign(path, raw, app_id, ts, nonce, secret):
    canon = "\n".join([
        "POST", path, app_id, ts, nonce,
        hashlib.sha256(raw.encode("utf-8")).hexdigest(),
    ])
    return hmac.new(secret.encode("utf-8"), canon.encode("utf-8"), hashlib.sha256).hexdigest()


def call(path, body=None, app_id=APP_ID, secret=APP_SEC, ts=None, nonce=None,
         raw_override=None, sign_raw=None):
    """调用开放接口。raw_override = 实际发送的报文, sign_raw = 参与签名的报文
    (两者不同 = 篡改报文但沿用旧签名)。"""
    global _nonce_seq
    raw = json.dumps(body or {}, separators=(",", ":"))
    if raw_override is not None:
        raw = raw_override
    ts = str(ts if ts is not None else int(time.time() * 1000))
    if nonce is None:
        _nonce_seq += 1
        nonce = "n%04d%s" % (_nonce_seq, hashlib.md5(os.urandom(8)).hexdigest()[:10])
    sig = _sign(path, sign_raw if sign_raw is not None else raw, app_id, ts, nonce, secret)
    req = urllib.request.Request(
        BASE + path, data=raw.encode("utf-8"), method="POST",
        headers={
            "Content-Type": "application/json",
            "x-app-id": app_id, "x-timestamp": ts,
            "x-nonce": nonce, "x-signature": sig,
        })
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status, json.loads(r.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8") or "{}")
        except Exception:
            return e.code, {}
    except Exception as e:
        return 0, {"msg": str(e)}


def plain_post(path, body):
    """不带签名的普通调用 (客户端 API)"""
    req = urllib.request.Request(BASE + path, data=json.dumps(body).encode("utf-8"),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status, json.loads(r.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as e:
        return e.code, {}


def port_free():
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", PORT))
        return True
    except Exception:
        return False
    finally:
        s.close()


def wait_up(sec=20):
    for _ in range(sec * 5):
        st, _ = plain_post("/api/ping", {})
        if st == 200:
            return True
        time.sleep(0.2)
    return False


def start_server(open_apps=True):
    global _srv
    env = dict(os.environ, PORT=str(PORT), HZ_DATA_DIR=DATA)
    env.pop("HZ_OPEN_APPS", None)
    if open_apps:
        env["HZ_OPEN_APPS"] = "%s:%s,%s:%s" % (APP_ID, APP_SEC, APP2_ID, APP2_SEC)
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


def main():
    global DATA
    DATA = tempfile.mkdtemp(prefix="hz_open_test_")
    try:
        if not port_free():
            print("端口 %d 被占用, 换一个 (HZ_OPEN_TEST_PORT)" % PORT)
            sys.exit(2)
        start_server(True)
        run_all()
    finally:
        stop_server()
        shutil.rmtree(DATA, ignore_errors=True)
    print("-" * 46)
    print("总计: %d 项, 通过 %d, 失败 %d"
          % (len(PASS) + len(FAIL), len(PASS), len(FAIL)))
    if FAIL:
        print("失败项: " + ", ".join(FAIL))
        sys.exit(1)


def run_all():
    # ---------- 1. 签名校验 ----------
    print("[1] 签名与防重放")
    st, d = call("/api/open/v1/ping", {}, secret="wrong-secret-000000000")
    check("错误密钥被拒", st == 401 and d.get("code") == "SIGN_BAD", d.get("code"))
    st, d = call("/api/open/v1/ping", {}, app_id="ghost")
    check("未知应用被拒", st == 401 and d.get("code") == "APP_UNKNOWN", d.get("code"))
    st, d = call("/api/open/v1/ping", {"a": 1}, sign_raw='{"a":2}')
    check("篡改报文签名失效", st == 401 and d.get("code") == "SIGN_BAD", d.get("code"))
    st, d = call("/api/open/v1/ping", {}, ts=int(time.time() * 1000) - 3600 * 1000)
    check("过期时间戳被拒", st == 401 and d.get("code") == "TS_INVALID", d.get("code"))
    st, d = call("/api/open/v1/ping", {}, nonce="bad nonce!")
    check("非法 nonce 被拒", st == 401 and d.get("code") == "NONCE_INVALID", d.get("code"))
    st1, d1 = call("/api/open/v1/ping", {}, nonce="replaynonce01")
    st2, d2 = call("/api/open/v1/ping", {}, nonce="replaynonce01")
    check("nonce 重放被拒", st1 == 200 and st2 == 401 and d2.get("code") == "NONCE_REPLAY",
          "%s → %s" % (d1.get("ok"), d2.get("code")))
    st, d = call("/api/open/v1/nope", {})
    check("未知接口 404", st == 404 and d.get("code") == "NO_SUCH_ENDPOINT", d.get("code"))

    st, d = call("/api/open/v1/ping", {})
    check("握手 ping 成功", st == 200 and d.get("ok") and d.get("app_id") == APP_ID, str(d.get("endpoints")))

    # ---------- 2. 代注册 ----------
    print("[2] 代注册 (external_id 幂等)")
    st, d = call("/api/open/v1/users/register",
                 {"external_id": "ext-1001", "username": "openuser1",
                  "password": "OpenUser123", "recovery": "OpenRC123"})
    check("创建账号成功", st == 200 and d.get("created") and d.get("user") == "openuser1", d.get("msg"))
    check("  返回账号状态字段", d.get("state") in ("active", "expired") and "remaining" in d,
          "%s/%s" % (d.get("state"), d.get("remaining")))
    check("  安全码已随账号建立", d.get("rc_set") is True, str(d.get("rc_set")))

    st, d = call("/api/open/v1/users/register", {"external_id": "ext-1001", "username": "other_name"})
    check("同 external_id 幂等 (不重复建号)", st == 200 and d.get("created") is False
          and d.get("user") == "openuser1", str(d.get("user")))

    st, d = call("/api/open/v1/users/register",
                 {"external_id": "ext-1002", "username": "openuser1", "password": "Another123"})
    check("用户名冲突返回 409", st == 409 and d.get("code") == "USERNAME_TAKEN", d.get("code"))

    st, d = call("/api/open/v1/users/register", {"external_id": "ext-1003"})
    ok = st == 200 and d.get("created") and d.get("user", "").startswith("u_") \
        and len(d.get("initial_password") or "") >= 12
    check("不给用户名/密码 → 自动生成 + 首登密码", ok,
          "%s / %s" % (d.get("user"), d.get("initial_password")))

    st, d = call("/api/open/v1/users/register", {"external_id": "ext-1004", "password": "short"})
    check("弱密码被拒", st == 400, d.get("msg"))
    st, d = call("/api/open/v1/users/register", {"external_id": "ext-1005", "recovery": "12345678"})
    check("弱安全码被拒", st == 400 and "安全码" in (d.get("msg") or ""), d.get("msg"))
    st, d = call("/api/open/v1/users/register", {"username": "no_ext"})
    check("缺 external_id 被拒", st == 400, d.get("msg"))
    st, d = call("/api/open/v1/users/register", {"external_id": "ext|1006"})
    check("external_id 含 | 被拒 (键分隔符冲突)", st == 400 and "|" in (d.get("msg") or ""),
          d.get("msg"))

    # ---------- 3. 状态与加时长 ----------
    print("[3] 状态 / 加时长")
    st, d = call("/api/open/v1/users/status", {"external_id": "ext-1001"})
    check("按 external_id 查状态", st == 200 and d.get("user") == "openuser1", d.get("msg"))
    st, d = call("/api/open/v1/users/status", {"external_id": "ext-404"})
    check("不存在的账号 → NOT_FOUND", st == 200 and d.get("code") == "NOT_FOUND", d.get("code"))

    st, d = call("/api/open/v1/users/extend", {"external_id": "ext-1001", "seconds": 3600})
    check("加时长 1 小时", st == 200 and 3595 <= (d.get("remaining") or 0) <= 3600,
          str(d.get("remaining")))
    st, d = call("/api/open/v1/users/extend", {"external_id": "ext-1001", "seconds": 0})
    check("seconds=0 被拒", st == 400, d.get("msg"))

    m = plain_post("/api/admin/members", {})  # 未鉴权 → 401, 只确认接口还在
    check("管理接口仍要求鉴权", m[0] == 401, m[0])

    # ---------- 4. 登录 / 令牌校验 ----------
    print("[4] 登录与令牌校验")
    st, d = call("/api/open/v1/auth/login",
                 {"username": "openuser1", "password": "OpenUser123", "machine": "OPENMACHINE001"})
    check("开放接口登录成功", st == 200 and d.get("ok") and d.get("token"), d.get("msg"))
    tok = d.get("token")
    check("  回填 external_id", d.get("external_id") == "ext-1001", str(d.get("external_id")))

    st, d2 = plain_post("/api/auth/me", {"token": tok, "machine": "OPENMACHINE001"})
    check("该令牌可直接用于客户端接口 (同一套登录)",
          st == 200 and d2.get("ok") and d2.get("user") == "openuser1", d2.get("msg"))

    st, d = call("/api/open/v1/auth/verify", {"token": tok, "machine": "OPENMACHINE001"})
    check("令牌校验通过", st == 200 and d.get("ok") and d.get("user") == "openuser1", d.get("code"))
    st, d = call("/api/open/v1/auth/verify", {"token": tok, "machine": "OTHERMACHINE01"})
    check("令牌与机器不符被拒", st == 200 and d.get("code") == "MACHINE_MISMATCH", d.get("code"))
    st, d = call("/api/open/v1/auth/verify", {"token": "0" * 64})
    check("伪造令牌被拒", st == 200 and d.get("code") == "TOKEN_INVALID", d.get("code"))

    st, d = call("/api/open/v1/auth/login",
                 {"username": "openuser1", "password": "WrongPass1", "machine": "OPENMACHINE001"})
    check("密码错误被拒", st == 200 and not d.get("ok"), d.get("msg"))

    # 平台隔离: 另一个应用查不到 apptest 的 external_id
    st, d = call("/api/open/v1/users/status", {"external_id": "ext-1001"},
                 app_id=APP2_ID, secret=APP2_SEC)
    check("不同应用的外部ID互不可见", d.get("ok") is False, d.get("code"))
    st, d = call("/api/open/v1/ping", {}, app_id=APP2_ID, secret=APP2_SEC)
    check("第二个应用也能握手", st == 200 and d.get("app_id") == APP2_ID, d.get("app_id"))

    # ---------- 5. 审计 ----------
    print("[5] 审计日志")
    audit_path = os.path.join(DATA, "audit.log")
    try:
        with open(audit_path, encoding="utf-8") as f:
            log = f.read()
    except Exception:
        log = ""
    for act in ("OPEN_REGISTER", "OPEN_EXTEND", "OPEN_LOGIN_OK", "OPEN_BADSIGN"):
        check("审计包含 %s" % act, act in log, "")
    check("审计里不含应用密钥", APP_SEC not in log, "")

    # ---------- 6. 未启用 ----------
    print("[6] 未配置 HZ_OPEN_APPS")
    stop_server()
    start_server(False)
    st, d = call("/api/open/v1/ping", {})
    check("未启用时返回 501", st == 501 and d.get("code") == "OPEN_API_DISABLED", d.get("code"))
    st, d = plain_post("/api/auth/login", {})
    check("普通客户端接口不受影响", st == 400, st)


if __name__ == "__main__":
    main()
