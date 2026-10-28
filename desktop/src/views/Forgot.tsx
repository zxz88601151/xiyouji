import { useState } from "react";
import { AccountClient } from "../api/account";
import { pwdProblem } from "../lib/validate";

interface Props {
  client: AccountClient;
  initialUser: string;
  onDone: (user: string) => void;
  onCancel: () => void;
}

export function Forgot({ client, initialUser, onDone, onCancel }: Props) {
  const [user, setUser] = useState(initialUser);
  const [code, setCode] = useState("");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [msg, setMsg] = useState("安全码记不得了? 联系客服在管理台重置密码。");
  const [busy, setBusy] = useState(false);

  async function submit() {
    const u = user.trim();
    if (!u || !code || !pw) {
      setMsg("请填写用户名、安全码和新密码");
      return;
    }
    const prob = pwdProblem(pw);
    if (prob) {
      setMsg(prob);
      return;
    }
    if (pw !== pw2) {
      setMsg("两次输入的新密码不一致");
      return;
    }
    setBusy(true);
    setMsg("正在提交...");
    const [ok, txt] = await client.forgot(u, code, pw);
    setBusy(false);
    setMsg(txt);
    if (ok) {
      await client.audit("RECOVER", `找回密码 ${u}`);
      onDone(u);
    }
  }

  return (
    <div>
      <div className="brand">阿信电脑同步器</div>
      <div className="brand-sub">找回密码</div>
      <div className="tip">
        输入注册时设置的安全码即可重置密码。{"\n"}
        重置后, 该账号在所有设备上的登录都会失效, 需要重新登录。
      </div>
      <div style={{ height: 12 }} />
      <input
        className="field"
        placeholder="用户名"
        value={user}
        onChange={(e) => setUser(e.target.value)}
      />
      <input
        className="field"
        placeholder="安全码 (注册时设置的, 8-32 位)"
        value={code}
        onChange={(e) => setCode(e.target.value)}
      />
      <input
        className="field"
        type="password"
        placeholder="新密码 (至少 8 位, 含字母和数字)"
        value={pw}
        onChange={(e) => setPw(e.target.value)}
      />
      <input
        className="field"
        type="password"
        placeholder="再输一次新密码"
        value={pw2}
        onChange={(e) => setPw2(e.target.value)}
        onKeyDown={(e) => e.key === "Enter" && submit()}
      />
      <div className="status">{msg}</div>
      <div className="row end" style={{ marginTop: 10 }}>
        <button className="btn" onClick={onCancel} disabled={busy}>
          取消
        </button>
        <button className="btn green" onClick={submit} disabled={busy}>
          重置密码
        </button>
      </div>
    </div>
  );
}
