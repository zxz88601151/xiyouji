# -*- coding: utf-8 -*-
"""旧卡密接口兼容性测试。

v4 把卡密降级成"充值码", 但**老客户端 EXE 仍在用 /api/activate + /api/verify**。
这个测试保证: 老装机用户升级前那段时间, 卡密授权链路不能断。

运行前提:
  1) 本地起服务: PORT=3010 HZ_DATA_DIR=<隔离目录> node server.js
  2) 传入管理员令牌: HZ_ADMIN_TOKEN=<该目录下 admin_token.txt>

只做服务端 HTTP 校验, 不碰任何本地授权文件。
"""
import json
import os
import sys
import urllib.request

API = "http://127.0.0.1:3010"
TOKEN = os.environ.get("HZ_ADMIN_TOKEN", "")
RESULTS = []


def call(path, payload, headers=None):
    req = urllib.request.Request(
        API + path,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode("utf-8"))
        except Exception:
            return {"ok": False, "msg": "HTTP %d" % e.code}


def check(name, cond, extra=""):
    RESULTS.append(bool(cond))
    print("[%s] %s %s" % ("PASS" if cond else "FAIL", name, extra))


def main():
    if not TOKEN:
        print("缺少 HZ_ADMIN_TOKEN")
        return 1

    adm = {"x-admin-token": TOKEN}

    g = call("/api/admin/keys/generate", {"type": "week", "count": 1, "note": "legacy-test"}, adm)
    check("生成一张周卡", g.get("ok") and g.get("keys"), str(g.get("keys")))
    key = (g.get("keys") or [""])[0]

    m1 = "LEGACY0MACHINE01"
    m2 = "LEGACY0MACHINE02"

    a1 = call("/api/activate", {"key": key, "machine": m1})
    check("首次激活成功", a1.get("ok"), a1.get("msg", ""))
    check("  返回剩余时长", (a1.get("remaining") or 0) > 6.5 * 86400,
          "%.1f 天" % ((a1.get("remaining") or 0) / 86400.0))

    v1 = call("/api/verify", {"key": key, "machine": m1})
    check("同机校验通过", v1.get("ok"), v1.get("msg", ""))

    a2 = call("/api/activate", {"key": key, "machine": m2})
    check("换机重绑成功", a2.get("ok") and a2.get("rebound"), a2.get("msg", ""))
    check("  换机扣 6 小时", abs((a2.get("cost_seconds") or 0) - 6 * 3600) < 5,
          "cost=%.0fs" % (a2.get("cost_seconds") or 0))

    v2 = call("/api/verify", {"key": key, "machine": m1})
    check("旧机器被拒绝", not v2.get("ok"), v2.get("msg", ""))

    bad = call("/api/activate", {"key": "HZ-0000-0000-0000", "machine": m1})
    check("格式非法的卡密被拒绝", not bad.get("ok"), bad.get("msg", ""))
    bad2 = call("/api/activate", {"key": "HZ-ZZZZ-ZZZZ-ZZZZ", "machine": m1})
    check("不存在的卡密被拒绝", not bad2.get("ok"), bad2.get("msg", ""))

    r = call("/api/redeem", {"token": "x", "machine": m1, "key": key})
    check("无令牌不能兑换进账号", not r.get("ok"), r.get("msg", ""))

    print("-" * 40)
    ok = sum(1 for x in RESULTS if x)
    print("总计: %d 项, 通过 %d, 失败 %d" % (len(RESULTS), ok, len(RESULTS) - ok))
    print("LEGACY_KEY_TEST_PASS" if ok == len(RESULTS) else "LEGACY_KEY_TEST_FAIL")
    return 0 if ok == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
