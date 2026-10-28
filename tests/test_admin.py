# -*- coding: utf-8 -*-
"""KEY 后台 v2 全流程测试: 登录/权限/账号/发卡/加时长/封禁/解绑/审计/安全加固"""
import json
import time
import http.cookiejar
import urllib.request
import urllib.error
import os
import sys

BASE = os.environ.get("HZ_API_BASE", "http://127.0.0.1:3011")
DATA = os.environ.get("HZ_DATA_DIR",
                      r"F:\zhuomian\好人多窗口同步器V10.0\复刻版\server\testdata")
PASS, FAIL = [], []


def check(name, ok, extra=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name, ("- " + str(extra)) if extra else ""))


def post(path, body=None, jar=None, token=None):
    """返回 (status, json, headers)"""
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar)) \
        if jar is not None else urllib.request.build_opener()
    hdr = {"Content-Type": "application/json"}
    if token:
        hdr["x-admin-token"] = token
    req = urllib.request.Request(BASE + path,
                                 data=json.dumps(body or {}).encode("utf-8"),
                                 headers=hdr, method="POST")
    try:
        with opener.open(req, timeout=8) as r:
            try:
                b = json.loads(r.read().decode("utf-8"))
            except Exception:
                b = {}
            return r.status, b, dict(r.headers)
    except urllib.error.HTTPError as e:
        try:
            b = json.loads(e.read().decode("utf-8"))
        except Exception:
            b = {}
        return e.code, b, dict(e.headers)
    except Exception as e:
        return 0, {"msg": str(e)}, {}


def read_owner_password():
    p = os.path.join(DATA, "owner_password.txt")
    for line in open(p, encoding="utf-8"):
        if line.startswith("初始密码:"):
            return line.split(":", 1)[1].strip()
    raise RuntimeError("未找到初始密码")


def main():
    print("KEY 后台 v2 全流程测试 -> %s\n" % BASE)

    # ---------- 1. 基础连通 ----------
    print("[1] 基础连通")
    st, d, _ = post("/api/ping")
    check("ping 可用且为 v2", st == 200 and d.get("v") == 2, d)

    # ---------- 2. 未登录鉴权 ----------
    print("[2] 未登录鉴权")
    jar0 = http.cookiejar.CookieJar()
    st, d, _ = post("/api/admin/keys", {}, jar0)
    check("未登录访问管理 API 被拒 401", st == 401 and d.get("need_login"), d.get("msg"))
    st, d, _ = post("/api/admin/keys/generate", {"type": "day", "count": 1}, jar0)
    check("未登录发卡被拒 401", st == 401)
    st, d, _ = post("/api/admin/login", {"username": "admin", "password": "wrong-password"}, jar0)
    check("错误密码登录被拒 401", st == 401 and "用户名或密码错误" in d.get("msg", ""), d.get("msg"))

    # ---------- 3. 登录 + 强制改密 ----------
    print("[3] 登录与初始密码强制修改")
    pw0 = read_owner_password()
    jar = http.cookiejar.CookieJar()
    st, d, h = post("/api/admin/login", {"username": "admin", "password": pw0}, jar)
    check("初始账号登录成功", st == 200 and d.get("ok") and d.get("must_change"), d)
    check("登录下发 HttpOnly+SameSite 会话 Cookie",
          "HttpOnly" in h.get("Set-Cookie", "") and "SameSite" in h.get("Set-Cookie", ""),
          h.get("Set-Cookie", "")[:60])
    st, d, _ = post("/api/admin/keys", {}, jar)
    check("未改初始密码时业务 API 被拒 (need_change_password)",
          st == 403 and d.get("need_change_password"), d.get("msg"))
    st, d, _ = post("/api/admin/change_password",
                    {"old_password": pw0, "new_password": "123"}, jar)
    check("弱密码被拒 (<8位)", st == 400, d.get("msg"))
    st, d, _ = post("/api/admin/change_password",
                    {"old_password": "wrong", "new_password": "Admin@2026ok"}, jar)
    check("原密码错误时改密被拒 401", st == 401, d.get("msg"))
    st, d, _ = post("/api/admin/change_password",
                    {"old_password": pw0, "new_password": "Admin@2026ok"}, jar)
    check("正确改密成功", st == 200 and d.get("ok"), d.get("msg"))
    st, d, _ = post("/api/admin/keys", {}, jar)
    check("改密后业务 API 放行", st == 200 and d.get("ok"), d.get("msg"))
    st, d, _ = post("/api/admin/me", {}, jar)
    check("me 返回当前身份 owner", st == 200 and d.get("role") == "owner", d)

    # ---------- 3b. 改密码加固 (G1 强度 / G3 同值+会话吊销) ----------
    print("[3b] 管理员改密码加固")
    PW_CUR = "Admin@2026ok"
    for bad, label in (("12345678", "纯数字"), ("onlylettersxyz", "纯字母"),
                       (" Admin@2026x", "首尾带空格")):
        st, d, _ = post("/api/admin/change_password",
                        {"old_password": PW_CUR, "new_password": bad}, jar)
        check("%s 新密码被拒 (与客户端账号同一套强度规则)" % label, st == 400, d.get("msg"))
    st, d, _ = post("/api/admin/change_password",
                    {"old_password": PW_CUR, "new_password": PW_CUR}, jar)
    check("新旧同值被拒", st == 400 and "相同" in d.get("msg", ""), d.get("msg"))
    check("同值被拒后原密码仍可用",
          post("/api/admin/me", {}, jar)[0] == 200)

    # 模拟"另一台设备/被盗 Cookie": 改密必须把它踢掉, 但保住当前会话
    jarC = http.cookiejar.CookieJar()
    st, d, _ = post("/api/admin/login", {"username": "admin", "password": PW_CUR}, jarC)
    check("第二会话登录成功", st == 200 and d.get("ok"), d)
    PW_TMP = "Admin@2026ok2"
    st, d, _ = post("/api/admin/change_password",
                    {"old_password": PW_CUR, "new_password": PW_TMP}, jar)
    check("改密成功并吊销其他会话",
          st == 200 and d.get("ok") and d.get("revoked_sessions", 0) >= 1, d)
    st, d, _ = post("/api/admin/keys", {}, jarC)
    check("改密后另一台设备的会话失效 401", st == 401 and d.get("need_login"), d.get("msg"))
    st, d, _ = post("/api/admin/keys", {}, jar)
    check("改密后当前会话不被误吊销", st == 200 and d.get("ok"), d.get("msg"))
    # 后续用例仍按 Admin@2026ok 登录, 这里改回去 (临时密码与它不同值, 允许)
    st, d, _ = post("/api/admin/change_password",
                    {"old_password": PW_TMP, "new_password": PW_CUR}, jar)
    check("改回基线密码 (供后续用例)", st == 200 and d.get("ok"), d.get("msg"))

    # owner 不能用免原密码的重置接口绕过原密码校验
    st, d, _ = post("/api/admin/users/reset_password",
                    {"username": "admin", "password": "Bypass@2026"}, jar)
    check("禁止用重置接口改自己的密码 (必须验原密码)", st == 400, d.get("msg"))
    st, d, _ = post("/api/admin/login", {"username": "admin", "password": "Bypass@2026"},
                    http.cookiejar.CookieJar())
    check("被拒的重置确实没有改掉密码", st == 401, d.get("msg"))

    # ---------- 4. 发卡 + 客户端激活 ----------
    print("[4] 发卡与客户端激活")
    st, d, _ = post("/api/admin/keys/generate",
                    {"type": "year", "count": 1, "note": "测试买家A"}, jar)
    check("生成年卡成功", st == 200 and len(d.get("keys", [])) == 1, d.get("msg"))
    k1 = d["keys"][0]
    M1, M2 = "TESTADMIN0000AA", "TESTADMIN0000BB"
    st, d, _ = post("/api/activate", {"key": k1, "machine": M1})
    check("客户端激活年卡成功", st == 200 and d.get("ok"), d)
    rem1 = d.get("remaining", 0)
    check("年卡时长约 365 天", 365 * 24 * 3600 - 60 <= rem1 <= 365 * 24 * 3600, rem1)
    st, d, _ = post("/api/verify", {"key": k1, "machine": M1})
    check("心跳验证通过", st == 200 and d.get("ok"), d)
    st, d, _ = post("/api/activate", {"key": k1, "machine": M2})
    # v3 起换机不再"拒绝", 而是自动重绑: 扣 6 小时 + 占 1 次换绑额度 (上限 3)
    check("换机激活=自动重绑 (扣6h + 计 1/3 次)",
          st == 200 and d.get("ok") and d.get("rebound") and
          d.get("cost_seconds") == 6 * 3600 and d.get("rebind_count") == 1 and
          d.get("rebind_left") == 2, d)
    st, d, _ = post("/api/verify", {"key": k1, "machine": M1})
    check("重绑后旧机器立即失效 (一号一机的真正保证)", st == 200 and not d.get("ok"), d.get("msg"))
    st, d, _ = post("/api/verify", {"key": k1, "machine": M2})
    check("重绑后新机器可用心跳", st == 200 and d.get("ok"), d.get("msg"))
    rem_rebind = d.get("remaining", 0)
    check("扣时账目可核对 (激活剩余 - 6h, 容差 5 秒)",
          rem1 - 6 * 3600 - 5 <= rem_rebind <= rem1 - 6 * 3600 + 5,
          "激活后 %d -> 重绑后 %d" % (rem1, rem_rebind))

    # ---------- 5. 加时长 ----------
    print("[5] 加时长")
    st, d, _ = post("/api/admin/keys/extend", {"key": k1, "amount": 1, "unit": "day"}, jar)
    check("给已激活卡 +1天 成功", st == 200 and d.get("ok"), d.get("msg"))
    st, d, _ = post("/api/verify", {"key": k1, "machine": M2})
    rem2 = d.get("remaining", 0)
    check("续期后剩余增加约 86400 秒", 86300 <= rem2 - rem_rebind <= 86500,
          "增加 %d 秒 (基准=重绑后 %d)" % (rem2 - rem_rebind, rem_rebind))
    st, d, _ = post("/api/admin/keys/extend", {"key": k1, "amount": 0, "unit": "day"}, jar)
    check("非法加时长参数被拒 400", st == 400, d.get("msg"))
    st, d, _ = post("/api/admin/keys/extend", {"key": k1, "amount": 5, "unit": "century"}, jar)
    check("非法单位被拒 400", st == 400, d.get("msg"))
    st, d, _ = post("/api/admin/keys/extend", {"key": "HZ-XXXX-XXXX-XXXX", "amount": 1, "unit": "day"}, jar)
    check("给不存在的卡加时长被拒", st == 200 and not d.get("ok"), d.get("msg"))
    # 未激活卡: 待生效时长
    st, d, _ = post("/api/admin/keys/generate", {"type": "trial", "count": 1, "note": "待续期卡"}, jar)
    k2 = d["keys"][0]
    st, d, _ = post("/api/admin/keys/extend", {"key": k2, "amount": 2, "unit": "day"}, jar)
    check("未激活卡加时长 -> 待生效", st == 200 and "激活时生效" in d.get("msg", ""), d.get("msg"))
    st, d, _ = post("/api/activate", {"key": k2, "machine": M2})
    rem3 = d.get("remaining", 0)
    check("激活后待生效时长生效 (3小时+2天)", 2 * 86400 + 3 * 3600 - 60 <= rem3 <= 2 * 86400 + 3 * 3600,
          rem3)

    # ---------- 6. 封禁 / 解封 / 解绑 ----------
    print("[6] 封禁 / 解封 / 解绑换机")
    st, d, _ = post("/api/admin/ban", {"key": k1, "banned": True}, jar)
    check("封禁成功", st == 200 and d.get("banned") is True, d)
    # 必须用当前绑定机 M2 验: 用已解绑的 M1 会因"机器不匹配"而失效, 断言就测不到封禁本身
    st, d, _ = post("/api/verify", {"key": k1, "machine": M2})
    check("封禁后绑定机验证失效", st == 200 and not d.get("ok"), d.get("msg"))
    st, d, _ = post("/api/admin/ban", {"key": k1, "banned": False}, jar)
    check("解封成功", st == 200 and d.get("banned") is False, d)
    st, d, _ = post("/api/verify", {"key": k1, "machine": M2})
    check("解封后恢复可用", st == 200 and d.get("ok"), d)
    st, d, _ = post("/api/admin/keys/unbind", {"key": k1}, jar)
    check("解绑机器成功", st == 200 and d.get("ok"), d.get("msg"))
    st, d, _ = post("/api/verify", {"key": k1, "machine": M2})
    check("解绑后原绑定机失效", st == 200 and not d.get("ok"), d.get("msg"))
    st, d, _ = post("/api/activate", {"key": k1, "machine": M2})
    check("解绑后可在新机器激活且时长保留 (第 2 次重绑再扣 6h)",
          st == 200 and d.get("ok") and d.get("rebind_count") == 2 and
          rem2 - 6 * 3600 - 5 <= d.get("remaining", 0) <= rem2 - 6 * 3600 + 5,
          "解绑前 %d -> 重激活 %d" % (rem2, d.get("remaining", 0)))

    # ---------- 7. 子账号与角色权限 ----------
    print("[7] 子账号与角色权限")
    st, d, _ = post("/api/admin/users/create",
                    {"username": "viewer1", "password": "Viewer@2026", "role": "viewer",
                     "note": "只读财务"}, jar)
    check("owner 创建 viewer 账号成功", st == 200 and d.get("ok"), d.get("msg"))
    st, d, _ = post("/api/admin/users/create", {"username": "viewer1", "password": "x12345678", "role": "viewer"}, jar)
    check("重名账号被拒", st == 400, d.get("msg"))
    st, d, _ = post("/api/admin/users/create", {"username": "ab", "password": "x12345678", "role": "viewer"}, jar)
    check("非法用户名被拒", st == 400, d.get("msg"))
    st, d, _ = post("/api/admin/users/create", {"username": "seller1", "password": "1234", "role": "admin"}, jar)
    check("弱密码账号创建被拒", st == 400, d.get("msg"))
    st, d, _ = post("/api/admin/users/create",
                    {"username": "seller1", "password": "Seller@2026", "role": "admin",
                     "note": "经销商老王"}, jar)
    check("owner 创建 admin(经销商) 账号成功", st == 200 and d.get("ok"), d.get("msg"))

    jv = http.cookiejar.CookieJar()
    st, d, _ = post("/api/admin/login", {"username": "viewer1", "password": "Viewer@2026"}, jv)
    check("viewer 登录成功", st == 200 and d.get("ok"), d)
    post("/api/admin/change_password", {"old_password": "Viewer@2026", "new_password": "Viewer@2026ok"}, jv)
    st, d, _ = post("/api/admin/keys", {}, jv)
    check("viewer 可查看卡密 (只读)", st == 200 and d.get("ok"))
    st, d, _ = post("/api/admin/keys/generate", {"type": "day", "count": 1}, jv)
    check("viewer 发卡被拒 403", st == 403, d.get("msg"))
    st, d, _ = post("/api/admin/keys/extend", {"key": k1, "amount": 1, "unit": "day"}, jv)
    check("viewer 加时长被拒 403", st == 403, d.get("msg"))
    st, d, _ = post("/api/admin/users", {}, jv)
    check("viewer 查看账号管理被拒 403", st == 403, d.get("msg"))

    # ---- 子账号密码强度 + reset_password (这两条此前零覆盖) ----
    st, d, _ = post("/api/admin/users/create",
                    {"username": "weakonly", "password": "onlyletters", "role": "viewer"}, jar)
    check("纯字母子账号密码被拒", st == 400, d.get("msg"))
    st, d, _ = post("/api/admin/users/reset_password",
                    {"username": "viewer1", "password": "12345678"}, jar)
    check("重置子账号为纯数字密码被拒", st == 400, d.get("msg"))
    st, d, _ = post("/api/admin/users/reset_password",
                    {"username": "nosuchuser", "password": "Reset@2026"}, jar)
    check("重置不存在的账号被拒", st == 400, d.get("msg"))
    st, d, _ = post("/api/admin/users/reset_password",
                    {"username": "viewer1", "password": "Reset@2026"}, jar)
    check("owner 重置子账号密码成功", st == 200 and d.get("ok"), d.get("msg"))
    st, d, _ = post("/api/admin/keys", {}, jv)
    check("重置后子账号在线会话立即失效 401", st == 401, d.get("msg"))
    jv2 = http.cookiejar.CookieJar()
    st, d, _ = post("/api/admin/login", {"username": "viewer1", "password": "Reset@2026"}, jv2)
    check("新密码可登录且被要求改密", st == 200 and d.get("ok") and d.get("must_change"), d)

    js = http.cookiejar.CookieJar()
    st, d, _ = post("/api/admin/login", {"username": "seller1", "password": "Seller@2026"}, js)
    check("admin(经销商) 登录成功", st == 200 and d.get("ok"), d)
    post("/api/admin/change_password", {"old_password": "Seller@2026", "new_password": "Seller@2026ok"}, js)
    st, d, _ = post("/api/admin/keys/generate", {"type": "week", "count": 2, "note": "老王出货"}, js)
    check("admin 可发卡", st == 200 and len(d.get("keys", [])) == 2, d.get("msg"))
    st, d, _ = post("/api/admin/keys/delete", {"key": d["keys"][0]}, js)
    check("admin 删卡被拒 403 (仅 owner)", st == 403, d.get("msg"))
    st, d, _ = post("/api/admin/users", {}, js)
    check("admin 查看账号管理被拒 403", st == 403, d.get("msg"))

    st, d, _ = post("/api/admin/users/disable", {"username": "seller1", "disabled": True}, jar)
    check("owner 禁用子账号成功", st == 200 and d.get("ok"), d)
    st, d, _ = post("/api/admin/keys", {}, js)
    check("被禁用账号的会话立即失效 401", st == 401, d.get("msg"))
    st, d, _ = post("/api/admin/users/disable", {"username": "seller1", "disabled": False}, jar)
    check("owner 启用子账号成功", st == 200 and d.get("ok"), d)
    st, d, _ = post("/api/admin/users/delete", {"username": "viewer1"}, jar)
    check("owner 删除子账号成功", st == 200 and d.get("ok"), d)
    st, d, _ = post("/api/admin/users/delete", {"username": "admin"}, jar)
    check("删除自己被拒", st == 400, d.get("msg"))

    # ---------- 8. 搜索 / 统计 / 备注 ----------
    print("[8] 搜索 / 统计 / 备注 / 审计")
    st, d, _ = post("/api/admin/keys", {"q": "测试买家A"}, jar)
    check("按备注搜索命中", st == 200 and d.get("total", 0) >= 1, d.get("total"))
    st, d, _ = post("/api/admin/keys", {"state": "unused"}, jar)
    check("按状态筛选可用", st == 200 and all(x["state"] == "unused" for x in d.get("keys", [])),
          d.get("total"))
    st, d, _ = post("/api/admin/stats", {}, jar)
    check("统计接口返回各状态数量", st == 200 and "stats" in d and d["stats"]["total"] > 0, d.get("stats"))
    st, d, _ = post("/api/admin/keys/note", {"key": k1, "note": "已付全款"}, jar)
    check("改备注成功", st == 200 and d.get("ok"), d)
    st, d, _ = post("/api/admin/audit", {"limit": 200}, jar)
    logs = d.get("logs", [])
    actions = {l.get("action") for l in logs}
    check("审计日志含 LOGIN_OK", "LOGIN_OK" in actions)
    check("审计日志含 GENERATE", "GENERATE" in actions)
    check("审计日志含 EXTEND", "EXTEND" in actions)
    check("审计日志含 BAN", "BAN" in actions)
    check("审计日志含 USER_CREATE", "USER_CREATE" in actions)
    check("审计日志含 USER_DISABLE", "USER_DISABLE" in actions)

    # ---------- 9. 安全加固 ----------
    print("[9] 安全加固项")
    # XSS 载荷: 服务端按纯文本存储返回, 不渲染
    xss = "<img src=x onerror=alert(1)>"
    st, d, _ = post("/api/admin/keys/generate", {"type": "day", "count": 1, "note": xss}, jar)
    kx = d["keys"][0]
    st, d, h2 = post("/api/admin/keys", {"q": "onerror"}, jar)
    hit = [x for x in d.get("keys", []) if x["key"] == kx]
    check("XSS 载荷按纯文本存储返回 (不渲染)",
          st == 200 and hit and hit[0]["note"] == xss and
          "json" in h2.get("Content-Type", ""), hit[0]["note"] if hit else "未命中")
    # 参数白名单
    st, d, _ = post("/api/activate", {"key": "HZ-bad-key", "machine": M1})
    check("非法卡密格式被拒 400", st == 400, d.get("msg"))
    st, d, _ = post("/api/activate", {"key": k1, "machine": "../../etc"})
    check("非法机器码被拒 400", st == 400, d.get("msg"))
    # 安全响应头
    st, d, h3 = post("/api/ping")
    check("安全响应头 nosniff + DENY 框架",
          h3.get("X-Content-Type-Options") == "nosniff" and "X-Frame-Options" in h3)
    # 根令牌兼容
    token = open(os.path.join(DATA, "admin_token.txt"), encoding="utf-8").read().strip()
    st, d, _ = post("/api/admin/stats", {}, None, token=token)
    check("根令牌 x-admin-token 仍可用 (自动化接口)", st == 200 and d.get("ok"), d.get("msg"))
    st, d, _ = post("/api/admin/stats", {}, None, token="deadbeefdeadbeef")
    check("错误根令牌被拒 401", st == 401, d.get("msg"))
    # 登出
    st, d, _ = post("/api/admin/logout", {}, jar)
    check("登出成功", st == 200 and d.get("ok"), d)
    st, d, _ = post("/api/admin/keys", {}, jar)
    check("登出后会话失效 401", st == 401, d.get("msg"))
    # 试用接口
    st, d, _ = post("/api/trial", {"machine": "TRIALMACHINE001"})
    check("试用接口可用 (3小时)", st == 200 and d.get("ok") and d.get("remaining", 0) > 10000, d)

    # ---------- 10. 登录爆破防护 (放最后: 会锁本 IP) ----------
    print("[10] 登录爆破防护 (最后执行)")
    jarB = http.cookiejar.CookieJar()
    locked_at = 0
    for i in range(12):
        c = http.cookiejar.CookieJar()
        st, d, _ = post("/api/admin/login", {"username": "admin", "password": "wrong%d" % i}, c)
        if st == 429:
            locked_at = i + 1
            break
    check("连续错误登录触发锁定 429", locked_at > 0, "第 %d 次被锁" % locked_at)
    st, d, _ = post("/api/admin/login",
                    {"username": "admin", "password": "Admin@2026ok"}, jarB)
    check("锁定期间正确密码也被挡 (防爆破)", st == 429, d.get("msg"))

    print("\n" + "=" * 60)
    print("结果: %d 通过 / %d 失败" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项: " + ", ".join(FAIL))
        sys.exit(1)


if __name__ == "__main__":
    main()
