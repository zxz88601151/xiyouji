import { useEffect, useMemo, useState } from "react";
import { AccountClient } from "./api/account";
import { AccountSecurity } from "./views/AccountSecurity";
import { LoginGate } from "./views/LoginGate";
import { SyncMain } from "./views/SyncMain";

type Phase = "boot" | "gate" | "home" | "security";

export default function App() {
  const client = useMemo(() => new AccountClient(), []);
  const [phase, setPhase] = useState<Phase>("boot");
  const [reason, setReason] = useState("");

  useEffect(() => {
    let alive = true;
    (async () => {
      await client.init();
      if (!alive) return;
      const [ok, msg] = await client.loadLocal();
      if (!alive) return;
      if (ok) {
        await client.audit("LOGIN", `账号自动登录 ${client.user}`);
        setPhase("home");
      } else {
        setReason(msg === "尚未登录" ? "" : msg);
        setPhase("gate");
      }
    })();
    return () => {
      alive = false;
    };
  }, [client]);

  if (phase === "boot") {
    return (
      <div className="app">
        <div className="card">
          <div className="brand">阿信电脑同步器</div>
          <div className="brand-sub">正在初始化</div>
        </div>
      </div>
    );
  }

  if (phase === "gate") {
    return (
      <LoginGate
        client={client}
        reason={reason}
        onLoggedIn={() => {
          setReason("");
          setPhase("home");
        }}
      />
    );
  }

  if (phase === "security") {
    return <AccountSecurity client={client} onClose={() => setPhase("home")} />;
  }

  return (
    <SyncMain
      client={client}
      onSecurity={() => setPhase("security")}
      onLogout={async () => {
        await client.audit("LOGOUT", "用户主动退出");
        await client.logout();
        setReason("");
        setPhase("gate");
      }}
      onSessionLost={(r) => {
        setReason(r);
        setPhase("gate");
      }}
    />
  );
}
