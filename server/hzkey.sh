#!/bin/bash
# 阿信电脑同步器 KEY 后台 · 启停脚本 (pidfile 方案, 避免 pgrep 自匹配假阳性)
#
# start|stop|restart|status|logs|ensure|reset
#   ensure  给 cron 每分钟调用: 进程没了就自动拉起 (崩溃自恢复)
#   reset   管理员账号离线维护, 转调 server/reset_admin.js (自动 stop → 改 → start)
#
# @reboot + 每分钟 ensure 两条一起配, 重启机和崩溃都能在 1 分钟内自愈。
BASE="$(cd "$(dirname "$0")" && pwd)"
SERVER_DIR="$BASE/server"
DATA_DIR="$SERVER_DIR/data"
PIDFILE="$DATA_DIR/hzkey.pid"
LOG="$DATA_DIR/hzkey.log"
CRON_LOG="$DATA_DIR/cron.log"
ENVFILE="$BASE/hzkey.env"
PORT="${PORT:-3010}"
export PORT HZ_DATA_DIR="$DATA_DIR"

is_running() {
  [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null
}

# hzkey.env 里放 HZ_PAY_PROVIDER / HZ_EPAY_* 等可选配置, 一行一个 KEY=VALUE
load_env() {
  if [ -f "$ENVFILE" ]; then
    set -a; . "$ENVFILE"; set +a
  fi
}

start() {
  if is_running; then echo "已在运行 pid=$(cat "$PIDFILE")"; return 0; fi
  load_env
  cd "$SERVER_DIR" || { echo "缺少 $SERVER_DIR"; return 1; }
  mkdir -p "$DATA_DIR"
  nohup node server.js >> "$LOG" 2>&1 &
  echo $! > "$PIDFILE"
  sleep 2
  if is_running; then
    echo "started pid=$(cat "$PIDFILE") port=$PORT"
  else
    rm -f "$PIDFILE"; echo "启动失败, 见 $LOG"; return 1
  fi
}

stop() {
  if is_running; then
    kill "$(cat "$PIDFILE")" 2>/dev/null
    for _ in 1 2 3 4 5; do is_running || break; sleep 0.4; done
    is_running && kill -9 "$(cat "$PIDFILE")" 2>/dev/null
    rm -f "$PIDFILE"; echo "stopped"
  else
    rm -f "$PIDFILE"; echo "未在运行"
  fi
}

case "$1" in
  start) start ;;
  stop) stop ;;
  restart) stop; start ;;
  status)
    if is_running; then
      echo "运行中 pid=$(cat "$PIDFILE") port=$PORT"
      curl -s -m 3 -X POST "http://127.0.0.1:$PORT/api/ping" || echo " (pid 在但接口无响应)"
      echo
    else
      echo "未在运行"
    fi
    ;;
  logs) tail -n "${2:-30}" "$LOG" ;;
  # 崩溃/重启自恢复: cron 每分钟一次, 活着就静默退出, 死了才写一行日志
  ensure)
    if is_running; then exit 0; fi
    rm -f "$PIDFILE"
    echo "[$(date '+%F %T')] 检测到服务未运行, 尝试拉起" >> "$CRON_LOG"
    start >> "$CRON_LOG" 2>&1
    ;;
  reset)
    shift
    # 只读查看不必停服务; 真要改盘才 stop → 改 → start
    case "$*" in
      *--list*|*--dry-run*)
        node "$SERVER_DIR/reset_admin.js" --data-dir "$DATA_DIR" "$@"
        exit $?
        ;;
    esac
    stop
    node "$SERVER_DIR/reset_admin.js" --data-dir "$DATA_DIR" "$@"
    RC=$?
    start
    exit $RC
    ;;
  *)
    echo "用法: hzkey.sh start|stop|restart|status|logs [N]|ensure"
    echo "      hzkey.sh reset --list"
    echo "      hzkey.sh reset --reset --user admin --generate [--out 文件]"
    echo "      hzkey.sh reset --rename --user admin --to 新登录名"
    echo "      hzkey.sh reset --create --user 名字 --role owner --generate"
    exit 2
    ;;
esac
