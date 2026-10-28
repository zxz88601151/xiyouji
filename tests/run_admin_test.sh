#!/usr/bin/env bash
# KEY 后台全流程测试 · 一键运行
# 说明: 测试依赖"初始密码", 必须在干净数据上跑。本脚本自动完成:
#       端口检查 → 清空测试数据 → 启动隔离服务(3011) → 跑测试 → 收尾杀进程
set -u

ROOT="F:/zhuomian/好人多窗口同步器V10.0/复刻版"
PY="C:/Users/Administrator/.workbuddy/binaries/python/envs/default/Scripts/python.exe"
NODE="C:/Users/Administrator/.workbuddy/binaries/node/versions/22.22.2-6/node.exe"
DATA="$ROOT/server/testdata"
PORT=3011

if curl -s -m 1 "http://127.0.0.1:$PORT/api/ping" >/dev/null 2>&1; then
  echo "[!] 端口 $PORT 已被占用, 请先停掉旧的测试服务 (或改用其他端口)"
  exit 1
fi

echo "[1/4] 清空测试数据 $DATA"
rm -rf "$DATA"; mkdir -p "$DATA"

echo "[2/4] 启动隔离服务 (port=$PORT)"
cd "$ROOT/server" || exit 1
PORT=$PORT HZ_DATA_DIR="$DATA" "$NODE" server.js > "$DATA/hzkey.log" 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null; echo "[4/4] 测试服务已关闭"' EXIT

for i in $(seq 1 30); do
  curl -s -m 1 "http://127.0.0.1:$PORT/api/ping" >/dev/null 2>&1 && break
  sleep 0.5
done

echo "[3/4] 运行全流程测试"
cd "$ROOT/tests" || exit 1
"$PY" test_admin.py
RC=$?
exit $RC
