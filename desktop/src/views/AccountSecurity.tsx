import { useState } from "react";
import { AccountClient } from "../api/account";
import { pwdProblem } from "../lib/validate";

interface Props {
  client: AccountClient;
  onClose: () => void;
}

export function AccountSecurity({ client, onClose }: Props) {
  const [oldPw, setOldPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [newPw2, setNewPw2] = useState("");
  const [m1, setM1] = useState("");
  const [busy1, setBusy1] = useState(false);

  const [curPw, setCurPw] = useState("");
  const [code, setCode] = useState("");
  const [code2, setCode2] = useState("");
  const [m2, setM2] = useState(
    client.rcSet ? "已设置" : "尚未设置, 忘记密码只能联系客服"
  );
  const [busy2, setBusy2] = useState(false);

  async function changePw() {
    if (!oldPw || !newPw) {
      setM1("请填写原密码和新密码");
      return;
    }
    const prob = pwdProblem(newPw);
    if (prob) {
      setM1(prob);
      return;
    }
    if (newPw !== newPw2) {
      setM1("两次输入的新密码不一致");
      return;
    }
    if (newPw === oldPw) {
      setM1("新密码不能与原密码相同");
      return;
    }
    setBusy1(true);
    const [ok, txt] = await client.changePassword(oldPw, newPw);
    setBusy1(false);
    setM1(txt);
    if (ok) {
      await client.audit("PASSWORD", `修改密码 ${client.user}`);
      setOldPw("");
      setNewPw("");
      setNewPw2("");
    }
  }

  async function saveCode() {
    if (!curPw || !code) {
      setM2("请填写当前密码和安全码");
      return;
    }
    const prob = pwdProblem(code, "安全码");
    if (prob) {
      setM2(prob);
      return;
    }
    if (code !== code2) {
      setM2("两次输入的安全码不一致");
      return;
    }
    setBusy2(true);
    const [ok, txt] = await client.setRecoveryCode(curPw, code);
    setBusy2(false);
    setM2(txt);
    if (ok) {
      await client.audit("RECOVERY_CODE", `设置安全码 ${client.user}`);
      client.rcSet = true;
      setCurPw("");
      setCode("");
      setCode2("");
    }
  }

  return (
    <div className="app">
      <div className="card">
        <div className="account-head">
          <span className="account-user">账号安全</span>
          <span className="tip" style={{ margin: 0 }}>
            当前账号: {client.user || "-"}
          </span>
        </div>

        <div className="group">
          <div className="group-title">修改密码</div>
          <input
            className="field"
            type="password"
            placeholder="原密码"
            value={oldPw}
            onChange={(e) => setOldPw(e.target.value)}
          />
          <input
            className="field"
            type="password"
            placeholder="新密码 (至少 8 位, 含字母和数字)"
            value={newPw}
            onChange={(e) => setNewPw(e.target.value)}
          />
          <input
            className="field"
            type="password"
            placeholder="再输一次新密码"
            value={newPw2}
            onChange={(e) => setNewPw2(e.target.value)}
          />
          <button className="btn" onClick={changePw} disabled={busy1}>
            修改密码
          </button>
          <div className="status">{m1}</div>
        </div>

        <div className="group">
          <div className="group-title">安全码 (忘记密码时用它自助重置)</div>
          <input
            className="field"
            type="password"
            placeholder="当前密码 (用于确认身份)"
            value={curPw}
            onChange={(e) => setCurPw(e.target.value)}
          />
          <input
            className="field"
            placeholder="安全码 8-32 位, 含字母和数字"
            value={code}
            onChange={(e) => setCode(e.target.value)}
          />
          <input
            className="field"
            placeholder="再输一次安全码"
            value={code2}
            onChange={(e) => setCode2(e.target.value)}
          />
          <button className="btn" onClick={saveCode} disabled={busy2}>
            保存安全码
          </button>
          <div className="status">{m2}</div>
        </div>

        <div className="row end">
          <button className="btn" onClick={onClose}>
            关闭
          </button>
        </div>
      </div>
    </div>
  );
}
