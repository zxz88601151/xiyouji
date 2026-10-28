/**
 * 账号客户端（S1）：注册 / 登录 / 找回 / 会话 / 改密 / 安全码。
 *
 * 与 license_client.py 的语义一一对应：
 *  - 网络层失败（连不上）→ 返回 (null, err)，可走离线兜底；
 *  - 服务端返回 ok:false 不是网络失败，按业务提示展示；
 *  - 到期时间以服务端为准（毫秒），本地缓存只用于断网兜底。
 */
import { DEV_MACHINE, invokeCmd, isTauri } from "../platform";

const DEV_TOKEN_KEY = "hz.dev.account";
const OFFLINE_ALLOW_UNTIL_EXPIRY = true;

export type ApiError = string | null;
type Dict = Record<string, unknown>;

export function fmtSecs(total: number): string {
  let s = Math.max(0, Math.floor(total));
  const d = Math.floor(s / 86400);
  s -= d * 86400;
  const h = Math.floor(s / 3600);
  s -= h * 3600;
  const m = Math.floor(s / 60);
  s -= m * 60;
  if (d) return `${d}天${h}小时`;
  if (h) return `${h}小时${m}分`;
  return `${m}分${s}秒`;
}

export function stateText(state: string): string {
  switch (state) {
    case "active":
      return "有效";
    case "expired":
      return "已到期";
    case "banned":
      return "已封禁";
    default:
      return "未开通";
  }
}

export class AccountClient {
  machine = "";
  token: string | null = null;
  user = "";
  remaining = 0;
  expiresAt = 0;
  planId = "";
  planName = "";
  state = "none";
  rebindLeft = 0;
  rcSet = false;
  lastOk = 0;

  async init(): Promise<void> {
    this.machine = isTauri()
      ? await invokeCmd<string>("machine_code").catch(() => DEV_MACHINE)
      : DEV_MACHINE;
  }

  private async post(path: string, body: Dict): Promise<[Dict | null, ApiError]> {
    if (isTauri()) {
      try {
        const d = await invokeCmd<Dict>("api_post", { path, body });
        return [d, null];
      } catch (e) {
        return [null, String(e)];
      }
    }
    try {
      const r = await fetch(path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const text = await r.text();
      try {
        return [JSON.parse(text) as Dict, null];
      } catch {
        return [null, `HTTP ${r.status}`];
      }
    } catch (e) {
      return [null, e instanceof Error ? e.message : String(e)];
    }
  }

  async readToken(): Promise<Dict | null> {
    if (isTauri()) {
      try {
        return await invokeCmd<Dict | null>("load_token");
      } catch {
        return null;
      }
    }
    try {
      const raw = localStorage.getItem(DEV_TOKEN_KEY);
      return raw ? (JSON.parse(raw) as Dict) : null;
    } catch {
      return null;
    }
  }

  private async writeToken(rec: Dict): Promise<void> {
    if (isTauri()) {
      await invokeCmd("save_token", {
        token: rec.token,
        user: rec.user,
        expiresAt: rec.expires_at,
      });
      return;
    }
    localStorage.setItem(DEV_TOKEN_KEY, JSON.stringify(rec));
  }

  async clearToken(): Promise<void> {
    if (isTauri()) {
      await invokeCmd("clear_token").catch(() => undefined);
    } else {
      localStorage.removeItem(DEV_TOKEN_KEY);
    }
    this.token = null;
    this.user = "";
    this.remaining = 0;
    this.expiresAt = 0;
    this.state = "none";
  }

  private apply(d: Dict): void {
    if (typeof d.user === "string") this.user = d.user;
    this.remaining = Number(d.remaining ?? 0) || 0;
    this.expiresAt = (Number(d.expires_at ?? 0) || 0) / 1000;
    this.planId = String(d.plan_id ?? this.planId);
    this.planName = String(d.plan_name ?? this.planName);
    this.state = String(d.state ?? "none");
    this.rebindLeft = Number(d.rebind_left ?? 0) || 0;
    if ("rc_set" in d) this.rcSet = Boolean(d.rc_set);
    this.lastOk = Date.now() / 1000;
  }

  private async remember(d: Dict): Promise<void> {
    if (typeof d.token === "string" && d.token) this.token = d.token;
    if (!this.token) return;
    try {
      await this.writeToken({
        token: this.token,
        user: this.user,
        machine: this.machine,
        expires_at: Math.floor(this.expiresAt),
        saved_at: Math.floor(Date.now() / 1000),
      });
    } catch {
      /* 令牌落盘失败不影响本次登录 */
    }
  }

  async register(
    username: string,
    password: string,
    recovery: string
  ): Promise<[boolean, string]> {
    const [d, err] = await this.post("/api/auth/register", {
      username,
      password,
      recovery,
      machine: this.machine,
    });
    if (err) return [false, `无法连接服务器: ${err}`];
    if (!d || !d.ok) return [false, String(d?.msg ?? "注册失败")];
    this.apply(d);
    await this.remember(d);
    return [true, String(d.msg ?? "注册成功")];
  }

  async forgot(
    username: string,
    recovery: string,
    newPassword: string
  ): Promise<[boolean, string]> {
    const [d, err] = await this.post("/api/auth/forgot", {
      username,
      recovery,
      new_password: newPassword,
    });
    if (err) return [false, `无法连接服务器: ${err}`];
    return [Boolean(d?.ok), String(d?.msg ?? "")];
  }

  async setRecoveryCode(password: string, recovery: string): Promise<[boolean, string]> {
    const [d, err] = await this.post("/api/auth/recovery_code", {
      token: this.token,
      password,
      recovery,
    });
    if (err) return [false, `无法连接服务器: ${err}`];
    return [Boolean(d?.ok), String(d?.msg ?? "")];
  }

  async login(username: string, password: string): Promise<[boolean, string]> {
    const [d, err] = await this.post("/api/auth/login", {
      username,
      password,
      machine: this.machine,
    });
    if (err) return [false, `无法连接服务器: ${err}`];
    if (!d || !d.ok) return [false, String(d?.msg ?? "登录失败")];
    this.apply(d);
    await this.remember(d);
    return [true, String(d.msg ?? "登录成功")];
  }

  /** 会话校验 + 拉最新剩余时间。返回 [ok, 文案, 是否离线]。 */
  async me(): Promise<[boolean, string, boolean]> {
    if (!this.token) return [false, "尚未登录", false];
    const [d, err] = await this.post("/api/auth/me", {
      token: this.token,
      machine: this.machine,
    });
    if (err) {
      if (OFFLINE_ALLOW_UNTIL_EXPIRY && this.expiresAt > Date.now() / 1000) {
        this.remaining = Math.max(0, Math.floor(this.expiresAt - Date.now() / 1000));
        return [true, `离线使用中 (剩余 ${fmtSecs(this.remaining)})`, true];
      }
      return [false, `连接服务器失败: ${err}`, true];
    }
    if (!d || !d.ok) {
      const msg = String(d?.msg ?? "登录已失效");
      if (msg.includes("失效") || msg.includes("不符")) await this.clearToken();
      return [false, msg, false];
    }
    this.apply(d);
    return [true, "已验证", false];
  }

  /** 启动时免密进入：读本地令牌 → 校验 → 拉账号状态。 */
  async loadLocal(): Promise<[boolean, string]> {
    const rec = await this.readToken();
    if (!rec) return [false, "尚未登录"];
    this.token = String(rec.token ?? "");
    this.user = String(rec.user ?? "");
    this.expiresAt = Number(rec.expires_at ?? 0) || 0;
    this.remaining = Math.max(0, Math.floor(this.expiresAt - Date.now() / 1000));
    const [ok, msg] = await this.me();
    return [ok, msg];
  }

  async logout(): Promise<void> {
    if (this.token) await this.post("/api/auth/logout", { token: this.token });
    await this.clearToken();
  }

  async changePassword(oldPw: string, newPw: string): Promise<[boolean, string]> {
    const [d, err] = await this.post("/api/auth/password", {
      token: this.token,
      old: oldPw,
      new: newPw,
    });
    if (err) return [false, `无法连接服务器: ${err}`];
    return [Boolean(d?.ok), String(d?.msg ?? "")];
  }

  async audit(kind: string, msg: string): Promise<void> {
    if (!isTauri()) return;
    await invokeCmd("audit_write", { kind, msg }).catch(() => undefined);
  }
}
