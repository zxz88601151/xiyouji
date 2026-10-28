import { useEffect, useState } from "react";
import { AccountClient } from "../api/account";
import { pwdProblem } from "../lib/validate";
import { Forgot } from "./Forgot";

interface Props {
  client: AccountClient;
  reason: string;
  onLoggedIn: () => void;
}

type Tab = "login" | "register";

export function LoginGate({ client, reason, onLoggedIn }: Props) {
  const [view, setView] = useState<"gate" | "forgot">("gate");
  const [tab, setTab] = useState<Tab>("login");
  const [msg, setMsg] = useState(reason);
  const [busy, setBusy] = useState(false);

  const [user, setUser] = useState("");
  const [pw, setPw] = useState("");

  const [rUser, setRUser] = useState("");
  const [rPw, setRPw] = useState("");
  const [rPw2, setRPw2] = useState("");
  const [rCode, setRCode] = useState("");
  const [rCode2, setRCode2] = useState("");

  useEffect(() => {
    client.readToken().then((rec) => {
      if (rec && typeof rec.user === "string") setUser(rec.user);
    });
  }, [client]);

  async function doLogin() {
    const u = user.trim();
    if (!u || !pw) {
      setMsg("请输入用户名和密码");
      return;
    }
    setBusy(true);
    setMsg("正在登录...");
    const [ok, txt] = await client.login(u, pw);
    setBusy(false);
    setMsg(txt);
    if (ok) {
      await client.audit("LOGIN", `账号登录 ${u}`);
      onLoggedIn();
    }
  }

  async function doRegister() {
    const u = rUser.trim();
    if (!u || !rPw) {
      setMsg("请填写用户名和密码");
      return;
    }
    const prob = pwdProblem(rPw);
    if (prob) {
      setMsg(prob);
      return;
    }
    if (rPw !== rPw2) {
      setMsg("两次输入的密码不一致");
      return;
    }
    if (!rCode) {
      setMsg("请设置安全码 (忘记密码时用它重置, 建议记在手机备忘录里)");
      return;
    }
    const codeProb = pwdProblem(rCode, "安全码");
    if (codeProb) {
      setMsg(codeProb);
      return;
    }
    if (rCode !== rCode2) {
      setMsg("两次输入的安全码不一致");
      return;
    }
    if (rCode === rPw) {
      setMsg("安全码不能和密码相同");
      return;
    }
    setBusy(true);
    setMsg("正在注册...");
    const [ok, txt] = await client.register(u, rPw, rCode);
    setBusy(false);
    setMsg(txt);
    if (ok) {
      await client.audit("REGISTER", `注册 ${u}`);
      onLoggedIn();
    }
  }

  if (view === "forgot") {
    return (
      <div className="app">
        <div className="card">
          <Forgot
            client={client}
            initialUser={user}
            onCancel={() => {
              setView("gate");
              setMsg("");
            }}
            onDone={(u) => {
              setUser(u);
              setPw("");
              setView("gate");
              setTab("login");
              setMsg("密码已重置, 请输入新密码登录 (其他电脑上的登录已失效)");
            }}
          />
        </div>
      </div>
    );
  }

  return (
    <div className="app">
      <div className="card">
        <div className="brand">阿信电脑同步器</div>
        <div className="brand-sub">账号登录 / 注册</div>
        <div className="machine">机器码: {client.machine || "..."}</div>

        <div className="tabs">
          <button
            className={"tab" + (tab === "login" ? " active" : "")}
            onClick={() => {
              setTab("login");
              setMsg("");
            }}
          >
            登录
          </button>
          <button
            className={"tab" + (tab === "register" ? " active" : "")}
            onClick={() => {
              setTab("register");
              setMsg("");
            }}
          >
            注册
          </button>
        </div>

        {tab === "login" ? (
          <div>
            <input
              className="field"
              placeholder="用户名"
              value={user}
              autoFocus={!!user}
              onChange={(e) => setUser(e.target.value)}
            />
            <input
              className="field"
              type="password"
              placeholder="密码"
              value={pw}
              autoFocus={!user}
              onChange={(e) => setPw(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && doLogin()}
            />
            <button className="btn green primary" onClick={doLogin} disabled={busy}>
              登录
            </button>
            <div className="row end">
              <button className="btn link" onClick={() => setView("forgot")}>
                忘记密码
              </button>
            </div>
            <div className="tip">
              换电脑登录会自动绑定新机器 (扣 6 小时, 最多 3 次)。{"\n"}
              忘记密码: 注册时设过「安全码」可自助重置, 否则联系客服。
            </div>
          </div>
        ) : (
          <div>
            <input
              className="field"
              placeholder="用户名 (3-24 位字母数字 _ . -)"
              value={rUser}
              autoFocus
              onChange={(e) => setRUser(e.target.value)}
            />
            <input
              className="field"
              type="password"
              placeholder="密码 (至少 8 位, 含字母和数字)"
              value={rPw}
              onChange={(e) => setRPw(e.target.value)}
            />
            <input
              className="field"
              type="password"
              placeholder="再输一次密码"
              value={rPw2}
              onChange={(e) => setRPw2(e.target.value)}
            />
            <input
              className="field"
              placeholder="安全码 (8-32 位, 含字母和数字, 找回密码用)"
              value={rCode}
              onChange={(e) => setRCode(e.target.value)}
            />
            <input
              className="field"
              type="password"
              placeholder="再输一次安全码"
              value={rCode2}
              onChange={(e) => setRCode2(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && doRegister()}
            />
            <button className="btn green primary" onClick={doRegister} disabled={busy}>
              注册并登录
            </button>
            <div className="tip">
              安全码 = 忘记密码时自助重置的凭据, 请记在只有你知道的地方{"\n"}
              (它和密码分开存, 不要设成一样的)。注册即赠 3 小时体验时长。
            </div>
          </div>
        )}

        <div className="status">{msg}</div>
      </div>
    </div>
  );
}
