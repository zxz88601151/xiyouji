# -*- coding: utf-8 -*-
"""账号客户端 (v4): 注册 / 密码登录 / 套餐购买 / 卡密充值 / 设备绑定。

商业流程:
    注册 → 登录 → 选套餐 → 支付 → 开通 → 登录看到剩余时间

与 v3 (卡密绑定机器) 的区别:
  · 授权凭证从"卡密"变成"账号 + 服务端会话令牌";
  · 卡密降级为【充值码】, 兑换后把时长充进账号;
  · 设备绑定仍在账号级: 一个账号同一时刻只允许一台机器使用。

安全边界:
  · 密码只在登录请求里出现一次, 不落盘、不写日志; 本地只存令牌;
  · 本地令牌文件带 HMAC 签名, 手改会被识别 (但真正的权威仍是服务端);
  · 到期时间以服务端为准, 客户端缓存的 expires_at 只用于断网兜底。
"""
import os
import sys
import json
import time
import hmac
import hashlib
import winreg
import urllib.request
import urllib.error

# 生产后台: .123 机器 (adminjiedian); 本地测试可用环境变量 HZ_API_BASE 覆盖
API_BASE = os.environ.get("HZ_API_BASE", "http://192.168.3.123:3010")
SECRET = b"HzWindowSyncer@2026#license-sign"   # 本地令牌文件签名密钥(混淆级, 防手改)
HEARTBEAT_MS = 60 * 1000        # 会话心跳周期
# 断网兜底: 只要本地缓存的到期时间还没到, 就允许继续用 (与 v3 "卡密未到期即可离线使用"
# 保持一致)。代价是封禁无法即时作用到断网机器 —— 需要更强管控时把它改成秒数即可。
OFFLINE_ALLOW_UNTIL_EXPIRY = True


def machine_code():
    """机器码: 注册表 MachineGuid + 计算机名 的 SHA256 前 16 位"""
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                           r"SOFTWARE\Microsoft\Cryptography")
        guid = winreg.QueryValueEx(k, "MachineGuid")[0]
        winreg.CloseKey(k)
    except Exception:
        guid = "unknown-guid"
    raw = "%s|%s" % (guid, os.environ.get("COMPUTERNAME", ""))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16].upper()


def _fmt_secs(s):
    s = int(s)
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    if d:
        return "%d天%d小时" % (d, h)
    if h:
        return "%d小时%d分" % (h, m)
    return "%d分%d秒" % (m, s)


def _state_dir():
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    d = os.path.join(base, "HzWindowSyncer")
    os.makedirs(d, exist_ok=True)
    return d


def _token_path():
    return os.path.join(_state_dir(), "account.json")


def _atomic_write_json(path, data):
    """原子写入: 先写同目录临时文件再 os.replace。
    心跳工作线程与主线程可能同时读写, 直接覆写会读到半截 JSON。"""
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass
        raise


def api_post(path, data, timeout=8):
    """调用后台 API, 返回 (dict|None, err|None)。err 非空 = 网络层失败(可离线兜底)。"""
    req = urllib.request.Request(
        API_BASE + path,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8")), None
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode("utf-8")), None
        except Exception:
            return None, "HTTP %d" % e.code
    except Exception as e:
        return None, str(e)


class AccountClient:
    """账号客户端。所有方法返回 (ok, 文案) 或 (ok, 文案, 数据)。"""

    def __init__(self):
        self.machine = machine_code()
        self.token = None
        self.user = ""
        self.remaining = 0        # 剩余秒数 (服务端权威)
        self.expires_at = 0       # 到期时间戳 (秒)
        self.plan_id = ""
        self.plan_name = ""
        self.state = "none"       # active / expired / banned / none
        self.rebind_left = 0
        self._rc_set = False      # 是否已设安全码 (服务端下发) 
        self.last_ok = 0          # 最后一次成功联网的时刻
        # 构造时就把本地令牌读进来 (只做本地签名/机器码校验, 不联网),
        # 这样任何在 load_local() 之前发生的调用都不会误报"请先登录"。
        try:
            _rec = self.read_token()
        except Exception:
            _rec = None
        if _rec:
            self.token = _rec["token"]
            self.user = _rec["user"]
            self.expires_at = float(_rec.get("expires_at") or 0)
            self.remaining = max(0, int(self.expires_at - time.time()))

    # ---------- 本地令牌 ----------
    def _sign(self, body):
        return hmac.new(SECRET, body.encode("utf-8"), hashlib.sha256).hexdigest()

    def save_token(self, token, user, expires_at):
        data = {"token": token, "user": user, "machine": self.machine,
                "expires_at": int(expires_at or 0), "saved_at": int(time.time())}
        body = json.dumps(data, sort_keys=True)
        data["sig"] = self._sign(body)
        _atomic_write_json(_token_path(), data)

    def read_token(self):
        """读本地令牌。只校验签名与机器码 (不联网)。返回 dict 或 None。"""
        try:
            with open(_token_path(), "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                return None
            for k in ("token", "user", "machine", "expires_at", "saved_at", "sig"):
                if k not in data:
                    return None
            body = json.dumps({k: data[k] for k in
                               ("token", "user", "machine", "expires_at", "saved_at")},
                              sort_keys=True)
            if not hmac.compare_digest(str(data["sig"]), self._sign(body)):
                return None
            if data["machine"] != self.machine:
                return None
            return data
        except Exception:
            return None

    def clear_token(self):
        try:
            os.remove(_token_path())
        except Exception:
            pass
        self.token = None
        self.user = ""
        self.remaining = 0
        self.expires_at = 0
        self.state = "none"

    # ---------- 结果落地 ----------
    def _apply(self, d):
        """把服务端返回的账号视图写进实例字段"""
        self.user = d.get("user", self.user)
        self.remaining = int(d.get("remaining", 0) or 0)
        self.expires_at = int(d.get("expires_at", 0) or 0) / 1000.0
        self.plan_id = d.get("plan_id", "") or ""
        self.plan_name = d.get("plan_name", "") or ""
        self.state = d.get("state", "none")
        self.rebind_left = int(d.get("rebind_left", 0) or 0)
        if "rc_set" in d:
            self._rc_set = bool(d.get("rc_set"))
        self.last_ok = time.time()

    def _remember(self, d):
        if d.get("token"):
            self.token = d["token"]
        if self.token:
            try:
                self.save_token(self.token, self.user, self.expires_at)
            except Exception:
                pass

    # ---------- 账号 ----------
    def register(self, username, password, recovery=""):
        d, err = api_post("/api/auth/register",
                          {"username": username, "password": password,
                           "recovery": recovery, "machine": self.machine})
        if err:
            return False, "无法连接服务器: %s" % err
        if not d or not d.get("ok"):
            return False, (d or {}).get("msg", "注册失败")
        self._apply(d)
        self._remember(d)
        return True, d.get("msg", "注册成功")

    def forgot(self, username, recovery, new_password):
        """忘记密码: 用户名 + 安全码 + 新密码。成功后服务器会踢掉该账号全部旧令牌。"""
        d, err = api_post("/api/auth/forgot",
                          {"username": username, "recovery": recovery,
                           "new_password": new_password})
        if err:
            return False, "无法连接服务器: %s" % err
        return bool(d and d.get("ok")), (d or {}).get("msg", "")

    def set_recovery_code(self, password, recovery):
        """设置 / 更换安全码 (需密码确认, 防止令牌被盗后被改绑)。"""
        d, err = api_post("/api/auth/recovery_code",
                          {"token": self.token, "password": password, "recovery": recovery})
        if err:
            return False, "无法连接服务器: %s" % err
        return bool(d and d.get("ok")), (d or {}).get("msg", "")

    @property
    def rc_set(self):
        return bool(getattr(self, "_rc_set", False))

    def login(self, username, password):
        d, err = api_post("/api/auth/login",
                          {"username": username, "password": password,
                           "machine": self.machine})
        if err:
            return False, "无法连接服务器: %s" % err
        if not d or not d.get("ok"):
            return False, (d or {}).get("msg", "登录失败")
        self._apply(d)
        self._remember(d)
        return True, d.get("msg", "登录成功")

    def me(self):
        """会话校验 + 拉取最新剩余时间。返回 (ok, msg, offline)。"""
        if not self.token:
            return False, "尚未登录", False
        d, err = api_post("/api/auth/me",
                          {"token": self.token, "machine": self.machine}, timeout=6)
        if err:
            # 网络失败 → 断网兜底 (不把用户踢出去)
            if OFFLINE_ALLOW_UNTIL_EXPIRY and self.expires_at > time.time():
                self.remaining = int(self.expires_at - time.time())
                return True, "离线使用中 (剩余 %s)" % _fmt_secs(self.remaining), True
            return False, "连接服务器失败: %s" % err, True
        if not d or not d.get("ok"):
            msg = (d or {}).get("msg", "登录已失效")
            if "失效" in msg or "不符" in msg:
                self.clear_token()
            return False, msg, False
        self._apply(d)
        return True, "已验证", False

    def heartbeat(self):
        """兼容旧接口: 返回 (ok, msg)"""
        ok, msg, _off = self.me()
        return ok, msg

    def load_local(self):
        """启动时尝试免密进入: 读本地令牌 → 校验 → 拉账号状态。
        返回 (ok, msg)。"""
        rec = self.read_token()
        if not rec:
            return False, "尚未登录"
        self.token = rec["token"]
        self.user = rec["user"]
        self.expires_at = float(rec.get("expires_at") or 0)
        self.remaining = max(0, int(self.expires_at - time.time()))
        ok, msg, _off = self.me()
        return ok, msg

    def logout(self):
        try:
            if self.token:
                api_post("/api/auth/logout", {"token": self.token}, timeout=4)
        except Exception:
            pass
        self.clear_token()

    def change_password(self, old, new):
        d, err = api_post("/api/auth/password",
                          {"token": self.token, "old": old, "new": new})
        if err:
            return False, "无法连接服务器: %s" % err
        return bool(d and d.get("ok")), (d or {}).get("msg", "")

    # ---------- 充值 / 购买 ----------
    def redeem(self, key):
        d, err = api_post("/api/redeem",
                          {"token": self.token, "machine": self.machine, "key": key})
        if err:
            return False, "无法连接服务器: %s" % err
        if not d or not d.get("ok"):
            return False, (d or {}).get("msg", "兑换失败")
        self._apply(d)
        self._remember(d)
        return True, d.get("msg", "兑换成功")

    def plans(self):
        d, err = api_post("/api/plans", {}, timeout=6)
        if err or not d or not d.get("ok"):
            return []
        return d.get("plans", [])

    def create_order(self, plan_id):
        d, err = api_post("/api/order/create",
                          {"token": self.token, "machine": self.machine,
                           "plan_id": plan_id})
        if err:
            return False, "无法连接服务器: %s" % err, {}
        if not d or not d.get("ok"):
            return False, (d or {}).get("msg", "下单失败"), {}
        return True, "下单成功", d

    def query_order(self, order_id):
        d, err = api_post("/api/order/query",
                          {"token": self.token, "machine": self.machine,
                           "order_id": order_id})
        if err or not d or not d.get("ok"):
            return None
        return d

    def mock_pay(self, order_id):
        d, err = api_post("/api/order/mock_pay",
                          {"token": self.token, "machine": self.machine,
                           "order_id": order_id})
        if err:
            return False, "无法连接服务器: %s" % err
        if not d or not d.get("ok"):
            return False, (d or {}).get("msg", "支付失败")
        self._apply(d)
        self._remember(d)
        return True, d.get("msg", "开通成功")
