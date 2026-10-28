# -*- coding: utf-8 -*-
"""生产环境冒烟测试 (部署后必跑)
用法: python test_prod_smoke.py <API_BASE> <初始密码> <新密码>
例:   python test_prod_smoke.py http://192.168.3.123:3010 55sUlGZr HzAdmin@2026
"""
import json
import sys
import http.cookiejar
import urllib.request
import urllib.error

PASS, FAIL = [], []


def check(name, ok, extra=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name, ("- " + str(extra)) if extra else ""))


def post(base, path, body=None, jar=None):
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar)) \
        if jar is not None else urllib.request.build_opener()
    req = urllib.request.Request(base + path, data=json.dumps(body or {}).encode("utf-8"),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with opener.open(req, timeout=8) as r:
            return r.status, json.loads(r.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8") or "{}")
        except Exception:
            return e.code, {}
    except Exception as e:
        return 0, {"msg": str(e)}


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(2)
    base, pw0, pw1 = sys.argv[1], sys.argv[2], sys.argv[3]
    print("生产冒烟 -> %s\n" % base)

    st, d = post(base, "/api/ping")
    check("服务在线 (v2)", st == 200 and d.get("v") == 2, d)

    jar = http.cookiejar.CookieJar()
    st, d = post(base, "/api/admin/login", {"username": "admin", "password": pw0}, jar)
    check("初始密码登录", st == 200 and d.get("ok"), d)
    st, d = post(base, "/api/admin/change_password",
                 {"old_password": pw0, "new_password": pw1}, jar)
    check("修改为正式密码", st == 200 and d.get("ok"), d.get("msg"))

    st, d = post(base, "/api/admin/keys/generate",
                 {"type": "day", "count": 1, "note": "部署冒烟测试"}, jar)
    check("生成日卡", st == 200 and len(d.get("keys", [])) == 1, d.get("msg"))
    k = d["keys"][0]

    M = "SMOKETEST0000AA"
    st, d = post(base, "/api/activate", {"key": k, "machine": M})
    check("客户端激活", st == 200 and d.get("ok"), d)
    r0 = d.get("remaining", 0)

    st, d = post(base, "/api/admin/keys/extend", {"key": k, "amount": 1, "unit": "day"}, jar)
    check("加时长 +1天", st == 200 and d.get("ok"), d.get("msg"))
    st, d = post(base, "/api/verify", {"key": k, "machine": M})
    check("续期生效 (剩余增加 1 天)", st == 200 and d.get("ok") and
          d.get("remaining", 0) - r0 >= 86300, "%d -> %d" % (r0, d.get("remaining", 0)))

    st, d = post(base, "/api/admin/ban", {"key": k, "banned": True}, jar)
    check("封禁生效", st == 200 and d.get("banned") is True, d)
    st, d = post(base, "/api/verify", {"key": k, "machine": M})
    check("封禁后客户端失效", st == 200 and not d.get("ok"), d.get("msg"))
    st, d = post(base, "/api/admin/ban", {"key": k, "banned": False}, jar)
    check("解封恢复", st == 200 and d.get("banned") is False, d)

    st, d = post(base, "/api/admin/audit", {"limit": 20}, jar)
    acts = {x.get("action") for x in d.get("logs", [])}
    check("审计日志已记录全套操作",
          st == 200 and {"LOGIN_OK", "GENERATE", "EXTEND", "BAN"}.issubset(acts), sorted(acts))

    st, d = post(base, "/api/admin/stats", {}, jar)
    check("统计可用", st == 200 and d.get("ok"), d.get("stats"))

    st, d = post(base, "/api/trial", {"machine": "SMOKETRIAL0001"})
    check("客户端试用可用", st == 200 and d.get("ok"), d)

    st, d = post(base, "/api/admin/logout", {}, jar)
    st, d = post(base, "/api/admin/keys", {}, jar)
    check("登出后会话失效", st == 401, d.get("msg"))

    print("\n测试卡密: %s (可在管理台封禁或删除)" % k)
    print("结果: %d 通过 / %d 失败" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项: " + ", ".join(FAIL))
        sys.exit(1)


if __name__ == "__main__":
    main()
