# 中继对外部署：三种让手机连上家里的方式

本文只讲**怎么把中继暴露给手机**。中继本身的部署步骤、初始化、查看注册密钥等内容见 [README.md](./README.md)。

CloudTerminal 的电脑 Agent 是**主动外连**中继的，所以电脑这一侧**永远不需要**开入站端口、端口映射或公网 IP。真正要解决的问题只有一个：**手机怎么访问到中继**。下面三种方式按门槛从低到高排列，选一种即可。

密钥和使用说明统一为：

- **注册密钥**：只有电脑 Agent 用它在中继上注册 → 用 `show-key` 查看。
- **短配对码**：手机用它配对到某台电脑 → 电脑启动器运行时显示，一次性、会过期。
- **连接地址**：手机和电脑访问中继的地址，形如 `wss://host/ws` 或 `ws://host:port/ws`。

---

## 方式 A：公网服务器 + Docker Compose TLS（域名 + 443）

**适用**：有一台公网服务器和一个域名，想要最稳定、无依赖的入口。**这是生产推荐方案。**

### 步骤

1. 把域名解析到服务器（A / AAAA 记录）。
2. 在云服务器安全组和系统防火墙开放 **TCP 80 和 443**，并确认没有其他服务占用。
3. 上传本仓库根目录的 Compose 文件和 `deploy/` 到服务器，进入该目录：

   ```sh
   cd /opt/cloudterminal-relay-server
   ```

4. 复制并填写域名（不要带 `https://` 或路径）：

   ```sh
   cp .env.example .env
   ```

   ```dotenv
   RELAY_DOMAIN=relay.example.com
   ```

5. 确认镜像可用后启动 TLS 入口（默认只拉镜像，不在服务器上构建）：

   ```sh
   docker compose -f compose.tls.yml pull
   docker compose -f compose.tls.yml up -d
   ```

   `compose.tls.yml` 的默认镜像地址是首次 CI 发布后才存在的目标地址；在那之前先在 `.env` 里设置 `RELAY_IMAGE=实际镜像:标签`，或用显式 override 从源码构建：`docker compose -f compose.tls.yml -f compose.build.yml up -d --build`。

6. 查看电脑要用的注册密钥：

   ```sh
   docker compose -f compose.tls.yml exec relay node src/relay/show-key.ts
   ```

### 手机 / 电脑要填的地址

```text
wss://relay.example.com/ws
```

Caddy 自动申请和续期证书，公网只暴露 80/443，中继的 8787 端口留在 Docker 网络内部，不对外。

### 注意事项

- **必须用 `wss://`**，不要再写 `:443` 或 `/ws` 之外的路径。
- 用 `RELAY_TRUST_PROXY=1`（`compose.tls.yml` 已内置）让限流看到真实客户端 IP；手工改成 Nginx 时也一样。
- 域名必须先解析成功，Caddy 才能签发证书；签发失败先查 DNS 和 80/443 入站。
- 官方证书仅对**域名**有效。直接用 IP 访问会证书不匹配，手机连不上。

---

## 方式 B：家里电脑 + Cloudflare Tunnel（免公网 IP）

**适用**：没有公网 IP、不想开端口、又想让手机在外网也能连。中继跑在本机 `localhost:8787`，由 `cloudflared` 主动建立出站隧道把流量送出去。

### 前置

- 本机能访问外网。
- 安装 `cloudflared`（Windows：`winget install --id Cloudflare.cloudflared`；macOS：`brew install cloudflared`；Linux 见官方文档）。
- 本机先按 [README.md](./README.md) 的“局域网 / VPN 部署”把中继起起来（默认 `8787`）：

  ```sh
  docker compose pull
  docker compose up -d
  ```

  或直接在 Windows 上用主仓库（https://github.com/azurekiln2333/cloudterminal）配套的脚本启动本地中继：

  ```powershell
  pwsh -File server/scripts/tunnel-relay.ps1
  ```

### 快速试用（临时随机域名，几分钟有效）

```sh
cloudflared tunnel --url http://localhost:8787
```

命令会打印一个形如 `https://random-words.trycloudflare.com` 的地址。把它换成 WebSocket 地址填到手机和电脑：

```text
wss://random-words.trycloudflare.com/ws
```

### 长期使用（自有域名）

1. 登录并授权：

   ```sh
   cloudflared tunnel login
   ```

2. 创建命名隧道并绑定域名（例如 `relay.example.com`）：

   ```sh
   cloudflared tunnel create cloudterminal
   cloudflared tunnel route dns cloudterminal relay.example.com
   ```

3. 用配置指向本机中继（`~/.cloudflared/config.yml`）：

   ```yaml
   tunnel: cloudterminal
   credentials-file: C:\Users\<你>\.cloudflared\<tunnel-id>.json
   ingress:
     - hostname: relay.example.com
       service: http://localhost:8787
     - service: http_status:404
   ```

4. 运行：

   ```sh
   cloudflared tunnel run cloudterminal
   ```

   手机和电脑填：

   ```text
   wss://relay.example.com/ws
   ```

### 注意事项

- **入口地址是 `wss://`**，`cloudflared` 负责 HTTPS 终止；本机中继仍是明文 `ws://localhost:8787`。
- 中继在这里**看不到客户端真实 IP**（都来自 `cloudflared`）。如需放宽或收紧限流，按需设置 `RELAY_TRUST_PROXY=1` 并在隧道层做限制。
- `trycloudflare.com` 临时域名每次启动都会变，适合试用，不适合长期；手机地址要跟着更新。
- 免费隧道可能限速或中断，重要场景请用方式 A 或付费 Cloudflare。
- 本机防火墙不需要对外开放 8787；隧道是出站连接。若中继和 `cloudflared` 不在同一台机器，才需要放行内网 8787。
- 电脑上的启动器窗口和 `cloudflared` **都要保持运行**，手机才能连。

---

## 方式 C：Tailscale 组网

**适用**：只想在自己设备之间（电脑 + 手机，或加上一台云主机）连通，不想把中继暴露到公网。

### 步骤

1. 在**运行中继的机器**上安装并登录 Tailscale：

   ```sh
   tailscale up
   ```

   Windows：`winget install --id Tailscale.Tailscale`，登录后在托盘查看本机 Tailscale IP。

2. 在**手机**上安装 Tailscale App，登录**同一个账号 / tailnet**。

3. 中继监听在所有网卡的 `8787`（README 的默认部署已满足）。记下中继机器的 Tailscale IP，例如 `100.101.102.103`。

### 手机 / 电脑要填的地址

```text
ws://100.101.102.103:8787/ws
```

或使用 MagicDNS 名称（在 tailnet 中开启 MagicDNS 后）：

```text
ws://<主机名>:8787/ws
```

### 注意事项

- Tailscale 本身加密传输，因此这里用明文 `ws://` 是可以接受的；若在 Tailscale 之上再套一层 TLS（Tailscale Serve / 反代），则用 `wss://`。
- **不要**用公网 IP 或 `localhost`：`localhost` 只在中继本机有效，手机必须用 Tailscale IP / MagicDNS 名。
- 必须确保**这台机器防火墙放行 Tailscale 网卡的 8787**。Windows 上若首次运行弹出防火墙询问，选择允许专用网络即可；也可显式放行：

  ```powershell
  New-NetFirewallRule -DisplayName "CloudTerminal relay (Tailscale)" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8787 -Profile Private
  ```

- 手机上的 Tailscale 必须保持连接；断开后地址就不可达。
- 不需要公网 IP、不需要域名、不需要端口映射。

---

## 怎么选

| 方式 | 公网 IP | 域名 | 证书 | 门槛 | 适合 |
| --- | --- | --- | --- | --- | --- |
| A 公网服务器 + TLS | 需要 | 需要 | Caddy 自动 | 中 | 长期稳定使用 |
| B Cloudflare Tunnel | 不需要 | 可选 | Cloudflare 提供 | 低 | 家里电脑、免公网 |
| C Tailscale | 不需要 | 不需要 | Tailscale 自带 | 最低 | 只在自用设备之间 |

三种方式可以**同时存在**：中继本身不变，手机上填哪个地址就通过哪条路连。

---

## 防火墙 / 网络速查

| 方式 | 需要入站放行 | 电脑 Agent 需要入站 |
| --- | --- | --- |
| A 公网服务器 | 服务器 TCP 80、443 | 否 |
| B Cloudflare Tunnel | 无（纯出站） | 否 |
| C Tailscale | 中继机在 Tailscale 网卡放行 TCP 8787 | 否 |

## 排障

- **手机连不上**：先在中继机本地验证 `http://localhost:8787/healthz` 返回 200，再确认手机用的地址 `ws`/`wss` 前缀、域名、端口都对。
- **证书/域名错误**：仅方式 A 会有；检查 DNS 解析、80/443 入站，以及是否误用了 IP。
- **隧道地址变了**：方式 B 的临时域名每次重启都变，重新填写手机地址即可；已配对过的手机仍用原来的 `agentId` + secret，只需替换服务器地址。
- **能连上但手机看不到电脑**：说明手机连到了中继，但电脑 Agent 没在线。检查电脑启动器是否在运行、注册密钥是否正确、电脑能否访问同一个中继地址。
- **修改端口**：中继端设置 `RELAY_PORT=8788` 后，三种方式里的地址端口都要同步改成 8788。
