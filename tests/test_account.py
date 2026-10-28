# -*- coding: utf-8 -*-
"""账号体系集成测试 (v4): 注册 → 登录 → 下单 → 支付 → 开通 → 兑换 → 换机。

运行前提:
  1) 本地起服务:
       PORT=3010 HZ_DATA_DIR=<隔离数据目录> HZ_REG_PER_MIN=60 node server.js
     (本文件注册次数远超 6 次/分钟的生产限流, 故用 HZ_REG_PER_MIN 放宽;
      生产不要设这个变量, 保持默认 6。)
  2) 传入管理员令牌: HZ_ADMIN_TOKEN=<该数据目录下的 admin_token.txt 内容>

隔离: APPDATA 指向临时目录, 不碰真实 %APPDATA%\\HzWindowSyncer\\account.json。
"""
import os
import sys
import json
import time
import shutil
import tempfile

os.environ["HZ_API_BASE"] = "http://127.0.0.1:3010"

_REAL = os.path.join(os.environ.get("APPDATA") or "", "HzWindowSyncer", "account.json")
_REAL_BEFORE = None
try:
    with open(_REAL, "rb") as f:
        _REAL_BEFORE = f.read()
except Exception:
    pass

_TMP_APPDATA = tempfile.mkdtemp(prefix="hz_acct_test_")
os.environ["APPDATA"] = _TMP_APPDATA

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import urllib.request

from license_client import AccountClient, _token_path

RESULTS = []
API = "http://127.0.0.1:3010"


def check(name, ok, detail=""):
    RESULTS.append(bool(ok))
    print("[%s] %s %s" % ("PASS" if ok else "FAIL", name, detail))


def admin(path, body, token):
    req = urllib.request.Request(API + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json",
                                          "x-admin-token": token})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read().decode())


TOKEN = (os.environ.get("HZ_ADMIN_TOKEN")
         or open(os.path.join("server", "data", "admin_token.txt")).read()).strip()

HOUR = 3600
UNAME = "tester%02d" % (int(time.time()) % 100)
PW = "abc12345"


def hrs(s):
    return round((s or 0) / HOUR, 2)


# ---------------- 1. 套餐表 ----------------
c = AccountClient()
plans = c.plans()
check("拉取套餐表", len(plans) >= 4, "%d 个套餐" % len(plans))
check("  价格由服务端下发", all("price_yuan" in p for p in plans),
      str([(p["id"], p["price_yuan"]) for p in plans]))

# ---------------- 2. 注册 ----------------
c.machine = "TESTMACHINE000001"
ok, txt = c.register(UNAME, "123")
check("弱密码被拒绝", not ok and "密码" in txt, txt)

ok, txt = c.register(UNAME, PW)
check("注册成功", ok, txt)
check("  注册即送体验时长", c.remaining > 0, "剩余 %s h" % hrs(c.remaining))
check("  本地令牌已落盘", os.path.exists(_token_path()), _token_path())

ok, txt = c.register(UNAME, PW)
check("重复用户名被拒绝", not ok, txt)

# ---------------- 3. 免密进入 ----------------
c2 = AccountClient()
c2.machine = "TESTMACHINE000001"
ok, txt = c2.load_local()
check("重启后免密进入", ok and c2.user == UNAME, txt)
check("  剩余时间已同步", c2.remaining > 0, "%s h" % hrs(c2.remaining))

# ---------------- 4. 密码错误锁定 ----------------
c3 = AccountClient()
c3.machine = "TESTMACHINE000001"
for i in range(8):
    c3.login(UNAME, "wrongpass1")
ok, txt = c3.login(UNAME, "wrongpass1")
check("连续错误后锁定", (not ok) and "秒后再试" in txt, txt)

# ---------------- 5. 正确登录 ----------------
c4 = AccountClient()
c4.machine = "TESTMACHINE000001"
ok, txt = c4.login(UNAME, PW)
# 注意: 上一步已锁定 15 分钟, 同一账号再登录应当仍被锁
check("锁定期间正确密码也进不去", (not ok) and "秒后再试" in txt, txt)

# 用管理员解锁 (直接清 failMap 不可行, 这里改走"等锁"太长, 故用另一账号验证主流程)
UNAME2 = UNAME + "b"
c5 = AccountClient()
c5.machine = "TESTMACHINE000002"
ok, txt = c5.register(UNAME2, PW)
check("备用账号注册", ok, txt)

# ---------------- 6. 下单 → 支付 → 开通 ----------------
before = c5.remaining
ok, txt, order = c5.create_order("month")
check("创建月卡订单", ok, txt)
check("  金额=6900分 (服务端定价)", order.get("amount") == 6900,
      "amount=%s" % order.get("amount"))
check("  通道为 mock (未接真实支付)", (order.get("pay") or {}).get("provider") == "mock",
      str(order.get("pay")))

ok, txt = c5.mock_pay(order.get("order_id"))
check("模拟支付成功", ok, txt)
check("  月卡时长已到账 (30天)",
      29.9 <= hrs(c5.remaining - before) / 24 <= 30.1,
      "增加 %s 天" % round(hrs(c5.remaining - before) / 24, 2))

d = c5.query_order(order.get("order_id"))
check("订单状态为已支付", d and d.get("status") == "paid", str(d and d.get("status")))

ok, txt = c5.mock_pay(order.get("order_id"))
check("重复支付幂等 (不重复加时长)", ok and "已支付" in txt, txt)

# 非法 plan_id
ok, txt, _ = c5.create_order("not_a_plan")
check("非法套餐被拒绝", not ok, txt)

# ---------------- 7. 卡密兑换 ----------------
gen = admin("/api/admin/keys/generate", {"type": "week", "count": 1, "note": "账号兑换测试"}, TOKEN)
cdk = gen["keys"][0]
before = c5.remaining
ok, txt = c5.redeem(cdk)
check("卡密兑换成功", ok, txt)
check("  周卡 +7 天", 6.9 <= hrs(c5.remaining - before) / 24 <= 7.1,
      "增加 %s 天" % round(hrs(c5.remaining - before) / 24, 2))

ok, txt = c5.redeem(cdk)
check("同一卡密不能重复兑换", not ok and "已被兑换" in txt, txt)

ok, txt = c5.redeem("HZ-XXXX-XXXX-XXXX")
check("不存在的卡密被拒绝", not ok, txt)

# ---------------- 8. 换机重绑 ----------------
c6 = AccountClient()
c6.machine = "TESTMACHINE000009"
before_rem = c5.remaining
ok, txt = c6.login(UNAME2, PW)
check("换机登录成功并重绑", ok and c6.remaining > 0, txt)
check("  换机扣 6 小时", abs((before_rem - c6.remaining) - 6 * HOUR) < 120,
      "%s h → %s h" % (hrs(before_rem), hrs(c6.remaining)))

# 旧机器的令牌应当失效 (单账号单机)
c5.token = c5.read_token()["token"] if c5.read_token() else c5.token
ok2, txt2, _ = c5.me()
check("旧机器令牌被踢下线", not ok2 or c5.user == "", txt2)

# ---------------- 8b. 安全码与找回密码 ----------------
UNAME3 = UNAME + "c"
RC = "Safe8888"
c8 = AccountClient()
c8.machine = "TESTMACHINE000101"

ok, txt = c8.register(UNAME3, PW, "12345678")
check("弱安全码被拒 (纯数字)", not ok and "安全码" in txt, txt)
ok, txt = c8.register(UNAME3, PW, PW)
check("安全码与密码相同被拒", not ok and "相同" in txt, txt)
ok, txt = c8.register(UNAME3, PW, "ab12")
check("过短安全码被拒", not ok and "至少" in txt, txt)
ok, txt = c8.register(UNAME3, PW, RC)
check("带安全码注册成功", ok, txt)
check("  账号视图 rc_set=true", c8.rc_set is True, str(c8.rc_set))


def raw_post(path, body):
    req = urllib.request.Request(API + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read().decode())


d = raw_post("/api/auth/register", {"username": UNAME + "f", "password": PW,
                                    "recovery": "Raw88888", "machine": "TESTMACHINE000104"})
check("注册响应不含安全码原文/哈希",
      "rc_hash" not in d and "rc_salt" not in d and "Raw88888" not in json.dumps(d),
      str(sorted(d.keys())))
check("  只回 rc_set 布尔", d.get("rc_set") is True, str(d.get("rc_set")))

# 新客户端实例 (模拟重装/换电脑): 没有任何本地令牌, 只能靠安全码
c9 = AccountClient()
c9.machine = "TESTMACHINE000101"
ok, txt = c9.forgot(UNAME3, "Wrong0000", "NewPass77")
check("错误安全码无法重置", not ok and "不正确" in txt, txt)
ok, txt = c9.forgot(UNAME3, "no_such_user_zz", "NewPass77")
check("不存在的账号给出同一句提示 (防枚举)", not ok and "不正确" in txt, txt)

old_token = c8.read_token()["token"] if c8.read_token() else c8.token
ok, txt = c9.forgot(UNAME3, RC, "NewPass77")
check("正确安全码重置成功", ok, txt)
check("  提示要重新登录", "重新登录" in txt, txt)

c8.token = old_token
ok2, txt2, _ = c8.me()
check("  重置后旧令牌确实失效", not ok2, txt2)

ok, txt = c9.login(UNAME3, PW)
check("旧密码无法登录", not ok and "错误" in txt, txt)
ok, txt = c9.login(UNAME3, "NewPass77")
check("新密码可以登录", ok, txt)

# 登录状态下更换安全码 (要验密码)
ok, txt = c9.set_recovery_code("WrongPw99", "Fresh999")
check("更换安全码需正确密码", not ok and "密码不正确" in txt, txt)
ok, txt = c9.set_recovery_code("NewPass77", "short1")
check("更换安全码同样做强度校验", not ok and "至少" in txt, txt)
ok, txt = c9.set_recovery_code("NewPass77", "Fresh999")
check("更换安全码成功", ok, txt)
ok, txt = c9.forgot(UNAME3, RC, "ThirdPass1")
check("旧安全码已作废", not ok, txt)
ok, txt = c9.forgot(UNAME3, "Fresh999", "ThirdPass1")
check("新安全码可用", ok, txt)

# 连错锁定
UNAME4 = UNAME + "d"
c10 = AccountClient()
c10.machine = "TESTMACHINE000102"
ok, txt = c10.register(UNAME4, PW, "Lock8888")
check("锁定测试账号注册", ok, txt)
last = ""
for i in range(5):
    ok, last = c10.forgot(UNAME4, "Bad00000", "Whatever1")
check("安全码连错 5 次锁定", (not ok) and "秒后再试" in last, last)
ok, txt = c10.forgot(UNAME4, "Lock8888", "Whatever1")
check("锁定期内正确安全码也被拒", (not ok) and "秒后再试" in txt, txt)

# 封禁账号不能自助找回
UNAME5 = UNAME + "e"
c11 = AccountClient()
c11.machine = "TESTMACHINE000103"
c11.register(UNAME5, PW, "Ban88888")
admin("/api/admin/members/ban", {"user": UNAME5, "banned": True}, TOKEN)
ok, txt = c11.forgot(UNAME5, "Ban88888", "Whatever1")
check("封禁账号不能自助找回", (not ok) and "封禁" in txt, txt)
admin("/api/admin/members/ban", {"user": UNAME5, "banned": False}, TOKEN)

# 管理台能看到"安全码 已设/未设", 但看不到任何哈希
m3 = admin("/api/admin/members", {"q": UNAME3, "page": 1, "size": 10}, TOKEN)
r3 = (m3.get("members") or [{}])[0]
check("管理台显示安全码已设", r3.get("rc_set") is True, str(r3.get("rc_set")))
check("  会员数据不含 rc_hash", "rc_hash" not in json.dumps(m3), "已脱敏")
m4 = admin("/api/admin/members", {"q": UNAME2, "page": 1, "size": 10}, TOKEN)
check("  无安全码账号显示未设", ((m4.get("members") or [{}])[0]).get("rc_set") is False,
      str(((m4.get("members") or [{}])[0]).get("rc_set")))

# ---------------- 9. 退出登录 ----------------
c6.logout()
ok, txt, _ = c6.me()
check("退出后令牌失效", not ok, txt)

# ---------------- 10. 管理台可见 ----------------
m = admin("/api/admin/members", {"q": UNAME2, "page": 1, "size": 10}, TOKEN)
row = (m.get("members") or [{}])[0]
check("管理台能查到会员", row.get("user") == UNAME2, str(row.get("user")))
check("  显示套餐与到期", row.get("plan_name") not in ("", "-"), row.get("plan_name"))
check("  记录付费金额", (row.get("total_paid") or 0) == 6900, "¥%s" % ((row.get("total_paid") or 0) / 100))

o = admin("/api/admin/orders", {"page": 1, "size": 20}, TOKEN)
check("管理台能查到订单", any(x["id"] == order.get("order_id") for x in o.get("orders", [])),
      "共 %d 单" % len(o.get("orders", [])))

# ---------------- 11. 封禁 ----------------
admin("/api/admin/members/ban", {"user": UNAME2, "banned": True}, TOKEN)
c7 = AccountClient()
c7.machine = "TESTMACHINE000009"
ok, txt = c7.login(UNAME2, PW)
check("封禁账号无法登录", not ok and "封禁" in txt, txt)
admin("/api/admin/members/ban", {"user": UNAME2, "banned": False}, TOKEN)

# ---------------- 12. 隔离自检 ----------------
_after = None
try:
    with open(_REAL, "rb") as f:
        _after = f.read()
except Exception:
    pass
check("未触碰真实账号文件", _after == _REAL_BEFORE, _REAL or "(无)")

print("-" * 40)
print("总计: %d 项, 通过 %d, 失败 %d"
      % (len(RESULTS), sum(RESULTS), len(RESULTS) - sum(RESULTS)))
print("ACCOUNT_TEST_PASS" if all(RESULTS) else "ACCOUNT_TEST_FAIL")

shutil.rmtree(_TMP_APPDATA, ignore_errors=True)
