# 本地第一版 MVP · 第三方平台接入演示

一个"新平台"的最小可用版本：**自己不存密码**，把用户、登录、时长、换绑全部托管给本站授权后台，
通过开放接口 v1（HMAC 签名）打通。跑起来是一个网页，点按钮就能看到每一次签名调用。

```
浏览器 ──同源──► mvp/server.js ──HMAC──► server/server.js  /api/open/v1/*
                      │                        │
                      └─ 订单表(request_id) ───┴─► users.json / identities.json / user_sessions.json
```

## 启动

```bash
bash mvp/start.sh           # 保留上次数据
bash mvp/start.sh --fresh   # 清空演示数据
```

- 演示平台 http://127.0.0.1:3020
- 授权后台 http://127.0.0.1:3012（管理台 `/admin`，初始密码在 `mvp/.data/hz/owner_password.txt`）
- 两个服务都跑在隔离数据目录 `mvp/.data/hz`，不碰 `server/data`
- 后台用 `HZ_HOST=127.0.0.1` 只绑本机（不设时默认 `0.0.0.0`，生产行为不变）
- Ctrl+C 一起停

## 页面怎么走

| 步骤 | 做了什么 | 背后的接口 |
|------|----------|------------|
| 0 连接检查 | HMAC 握手，确认 app_id/secret 对得上 | `GET /api/open/v1/ping` |
| 1 注册 / 同步 | 用本平台的 `shop_10086` 建本站账号；再点一次只会返回现状 | `users/register`（幂等） |
| 2 查状态 | 看 `state` + `remaining`，本平台不自己算到期 | `users/status` |
| 3 买会员 | 模拟支付 → 折算成秒同步；"重复提交上一笔"证明不会加两次 | `users/extend`（订单表去重） |
| 4 登录 | 拿本站 token，机器码变了会扣 6 小时 | `auth/login` |
| 5 校验 | 同一个 token 既过开放接口，也能直接调客户端接口 | `auth/verify` + `/api/auth/me` |

右侧"签名调用日志"是服务端真实发出的请求（方法、路径、状态码、耗时、nonce 前 8 位、请求/响应 JSON），
可以对照 `server/开放接口.md` 的签名规则逐项核。

## 关键设计

1. **secret 只在服务端**：浏览器只调同源的 `/api/call`，白名单操作（ping/register/status/extend/login/verify/me），
   前端传不了任意 path，也看不到密钥。
2. **幂等两层**：
   - 注册：后台用 `external_id` 映射，重复调用不会造第二个账号；
   - 购买：本平台订单带 `request_id`，重复提交直接返回上次结果，不再调 `extend`（文档里明确提醒过 extend 本身不幂等）。
3. **同一套登录**：`auth/login` 与客户端登录共用核心路径，所以这里发的 token 拿去调 `/api/auth/me` 一样有效——
   步骤 5 两颗按钮就是给这件事做对照。

## 边界（这是 MVP）

- 订单表在内存，重启清零；密钥是演示值。
- 只监听 `127.0.0.1`，没有 HTTPS；生产要放反代后面并开 `HZ_TRUST_PROXY=1`。
- 页面没有做完整的平台业务（注册引导、订单列表、退款），只保留验证"统一账号后台"所需的最小闭环。

## 自测

除了在页面上点，也可以直接用 curl 走 API：

```bash
# 启动后另开一个终端
curl -s -X POST http://127.0.0.1:3020/api/call -H "Content-Type: application/json" \
  -d '{"op":"ping"}'
curl -s -X POST http://127.0.0.1:3020/api/call -H "Content-Type: application/json" \
  -d '{"op":"register","external_id":"shop_10086","password":"DemoPass2026"}'
```
