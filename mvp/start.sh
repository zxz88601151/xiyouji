#!/usr/bin/env bash
# 本地第一版 MVP: 隔离授权后台(3012) + 第三方平台演示(3020)
#
#   ./mvp/start.sh            # 保留上次的数据 (幂等/持久化都能看到)
#   ./mvp/start.sh --fresh    # 清空演示数据, 从"第一次注册"开始
#
# Ctrl+C 同时关掉两个服务。
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NODE="$(command -v node || true)"
HZ_PORT="${HZ_PORT:-3012}"
MVP_PORT="${MVP_PORT:-3020}"
DATA="$ROOT/mvp/.data/hz"
APP_ID="demoapp"
APP_SECRET="DemoSecret2026_local_9x"

if [ -z "$NODE" ]; then echo "[!] 找不到 node, 请先安装 Node >= 18"; exit 1; fi
# MSYS 下把 /f/... 转成 F:\... 再交给原生 node, 避免数据目录落到别处
winpath() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi; }
case " $* " in *" --fresh "*) echo "[i] 清空演示数据 $DATA"; rm -rf "$DATA";; esac
mkdir -p "$DATA"
DATA_W="$(winpath "$DATA")"

for p in "$HZ_PORT" "$MVP_PORT"; do
  if curl -s -m 1 "http://127.0.0.1:$p/" >/dev/null 2>&1 || curl -s -m 1 "http://127.0.0.1:$p/api/ping" >/dev/null 2>&1; then
    echo "[!] 端口 $p 已被占用, 先停掉旧进程 (netstat -ano | grep :$p)"
    exit 1
  fi
done

echo "[1/3] 启动授权后台 (隔离数据: mvp/.data/hz, 端口 $HZ_PORT)"
cd "$ROOT/server" || exit 1
PORT="$HZ_PORT" HZ_HOST=127.0.0.1 HZ_DATA_DIR="$DATA_W" HZ_OPEN_APPS="$APP_ID:$APP_SECRET" \
  "$NODE" server.js > "$DATA/hz.log" 2>&1 &
HZ_PID=$!

cleanup() {
  kill "$MVP_PID" "$HZ_PID" 2>/dev/null
  echo
  echo "[i] 已关闭授权后台(pid=$HZ_PID) 与演示平台(pid=$MVP_PID)"
}
trap cleanup EXIT INT TERM

for i in $(seq 1 40); do
  curl -s -m 1 "http://127.0.0.1:$HZ_PORT/api/ping" >/dev/null 2>&1 && break
  sleep 0.25
done
if ! curl -s -m 1 "http://127.0.0.1:$HZ_PORT/api/ping" >/dev/null 2>&1; then
  echo "[!] 授权后台没起来, 看 $DATA/hz.log"; exit 1
fi

echo "[2/3] 启动第三方平台演示 (端口 $MVP_PORT)"
cd "$ROOT/mvp" || exit 1
MVP_PORT="$MVP_PORT" HZ_BASE="http://127.0.0.1:$HZ_PORT" \
  HZ_APP_ID="$APP_ID" HZ_APP_SECRET="$APP_SECRET" "$NODE" server.js &
MVP_PID=$!

for i in $(seq 1 40); do
  curl -s -m 1 "http://127.0.0.1:$MVP_PORT/" >/dev/null 2>&1 && break
  sleep 0.25
done

cat <<EOF

[3/3] 就绪

  演示平台   http://127.0.0.1:$MVP_PORT
  授权后台   http://127.0.0.1:$HZ_PORT   (管理台 /admin, 初始密码见 $DATA/owner_password.txt)
  开放接口   http://127.0.0.1:$HZ_PORT/api/open/v1/ping   (app_id=$APP_ID)

  页面里点: 0 连接检查 → 1 注册 → 2 查状态 → 3 买会员 → 4 登录 → 5 校验。
  按 Ctrl+C 停止。

EOF

wait "$MVP_PID"
