# CloudTerminal 中继服务

电脑端 Agent 与 App 在 https://github.com/azurekiln2333/cloudterminal（主仓库）。本仓库只有中继服务端：WebSocket 中继、可选的 OAuth2 账号层和 MySQL 绑定。

服务器**只拉取镜像运行**：不需要上传源码、不在服务器上 `npm install`、不在服务器上 `docker build`。真正需要的文件只有 Compose 文件、Caddy 配置和 `.env`。

中继只负责连接认证和消息转发。终端、Claude 和 Codex Desktop 仍在你的 Windows 电脑上运行；镜像里只有中继进程，不含桌面 Agent、PTY 或 SDK 依赖。

## 1. 先把镜像准备好（部署前置条件）

**当前没有任何已发布的镜像。** Compose 里的默认地址只是按你现有 azurekiln 仓库的命名规则推出的**目标地址**，首次 CI 发布成功之前它 pull 不到任何东西。仓库目前也没有配置 git remote，所以还没有任何流水线跑过。

默认地址（缺省值写在 `compose.yml` / `compose.tls.yml` 里）：

| 来源 | 地址 |
| --- | --- |
| GitHub（默认） | `ghcr.io/azurekiln2333/cloudterminal-relay-server:<tag>`，即通用写法 `ghcr.io/<owner>/<repo>:<tag>` |
| CNB | `docker.cnb.cool/azurekiln/cloudterminal-relay-server:<tag>` |

三选一，然后再部署：

1. **等 CI 发布**（推荐）：推 `v*` 标签后，CNB 流水线（`.cnb.yml`）和 GitHub Actions（`.github/workflows/image.yml`）会构建并推送 `<镜像>:<版本标签>`；稳定版本额外获得 `:latest`，`-rc` 之类的预发布**不会**覆盖 `:latest`。
2. **指定已有镜像**：在 `.env` 里设 `RELAY_IMAGE=实际地址:标签`，Compose 会用这个值，不需要改文件。
3. **本地构建**（见第 6 节）：显式加载 build override。

镜像路径和标签都可以配置：GitHub 侧用仓库变量 `RELAY_IMAGE_REGISTRY` / `RELAY_IMAGE_NAME` 覆盖，CNB 侧用环境变量 `CNB_IMAGE` 覆盖（详见流水线文件头部注释）。

确认镜像真的存在，再继续：

```sh
docker manifest inspect ghcr.io/azurekiln2333/cloudterminal-relay-server:latest
```

## 2. 服务器上需要哪些文件

```text
compose.yml           # 局域网 / VPN 入口（默认）
compose.tls.yml       # 公网 HTTPS 入口（与上面二选一）
compose.build.yml     # 仅本地构建用的显式 override，不用就不要上传
.env.example          # 复制成 .env 后修改
deploy/Caddyfile      # 只有 compose.tls.yml 需要
```

`Dockerfile`、`.dockerignore`、`src/`、`deploy/relay/` 只在“从源码本地构建”或跑测试时需要，日常部署不用上传，也不会被服务器上的任何默认命令读取。

服务器安装 Docker Engine 和 Docker Compose 插件。后续命令都在这些文件所在目录执行，例如：

```sh
cd /opt/cloudterminal-relay-server
```

## 3. 公网部署：域名 + HTTPS

1. 把域名解析到服务器。
2. 在防火墙和云服务器安全组中开放 TCP **80、443**；确认这两个端口未被其他服务占用。
3. 复制配置示例：

```sh
cp .env.example .env
```

把 `.env` 里的域名改成你自己的，不要加 `https://` 或路径：

```dotenv
RELAY_DOMAIN=relay.example.com
```

4. 拉镜像并启动：

```sh
docker compose -f compose.tls.yml pull
docker compose -f compose.tls.yml up -d
```

5. 查看电脑连接用的注册密钥：

```sh
docker compose -f compose.tls.yml exec relay node src/relay/show-key.ts
```

Caddy 自动申请和续期证书。公网只暴露 80/443，中继的 8787 端口留在容器网络内部。电脑和手机填写同一个地址：

```text
wss://relay.example.com/ws
```

## 4. 局域网 / VPN 部署：不需要域名

```sh
docker compose pull
docker compose up -d
docker compose exec relay node src/relay/show-key.ts
```

连接地址为 `ws://服务器IP:8787/ws`。防火墙只需向预期的局域网 / VPN 客户端开放 TCP 8787。要改端口，可在 `.env` 中设置 `RELAY_PORT=8788`。

这个入口使用明文 WebSocket，适合局域网或可信 VPN；公网使用上面的 HTTPS 入口。

## 5. Windows 和手机连接

Windows 电脑仍使用完整项目中的根目录启动器，服务器上不需要启动它：

1. 安装 Node.js 24 LTS，双击仓库根目录的 `start.cmd`。
2. 首次向导选择连接中继，填写服务器地址、刚才查看的注册密钥和工作目录。
3. Agent 连接后，手机填写相同服务器地址与 **Windows 显示的短配对码**。

**注册密钥填电脑，短配对码填手机。** 后续启动复用已保存的配置。电脑启动器窗口需要保持打开；修改连接用 `start.cmd --setup`。共享终端遮住配对信息时，按 Ctrl-] 退出桌面接管，再按空行回车生成配对码；输入 `attach` 并回车重新接管。

电脑设置和手机配对身份保存在 `%USERPROFILE%\.cloudterminal\agent.json`（或 `CLOUDTERMINAL_HOME`）。`--no-terminal` / `--terminal` 保存是否接管桌面终端的偏好。命令行参数优先于环境变量，环境变量优先于已保存设置；环境中的连接密钥不会另行写入保存配置。macOS / Linux 使用根目录的 `sh start.sh`。

Codex Desktop 本机适配仍在联调，部署中继本身不代表 Desktop 项目、历史和控制功能已经验收通过。

## 6. 本地构建（显式 override，服务器默认不用）

只有确实要在这台机器上从源码构建时才加载 `compose.build.yml`；它不在任何默认命令里，所以默认部署永远是纯镜像：

```sh
# 局域网入口
docker compose -f compose.yml -f compose.build.yml up -d --build

# 公网 TLS 入口
docker compose -f compose.tls.yml -f compose.build.yml up -d --build
```

构建上下文是仓库根目录（也就是原来的 `server/` 目录），产物打本地标签 `cloudterminal-relay:local`（可用 `RELAY_LOCAL_IMAGE` 改）。这条路径才需要 `Dockerfile`、`.dockerignore`、`src/` 和 `deploy/relay/` 的锁文件。镜像里的运行时依赖只有 `deploy/relay/package-lock.json` 锁定的两个纯 JS 包（`ws`、`mysql2`），不需要编译工具，也不会带上桌面 Agent 的 `node-pty` / SDK。

镜像本身：Node 24 Alpine，以非 root 的 `node` 用户运行，`/data` 可写，健康检查走 `/healthz`。

## 7. 可选账号层（OAuth2 + MySQL）

不配置就是原来的中继行为。要启用桌面/手机账号登录，在 `.env` 中提供 `DB_*`（`DB_HOST`、`DB_PORT`、`DB_USER`、`DB_PASSWORD`、`DB_NAME`，可选 `DB_TLS`、`DB_TLS_CA_FILE`、`DB_CONNECTION_LIMIT`、`DB_CONNECT_TIMEOUT_MS`）和 `OAUTH_*`（`OAUTH_ISSUER`、`OAUTH_CLIENT_ID`、`OAUTH_CLIENT_SECRET`、`OAUTH_REDIRECT_URI`、`OAUTH_AUDIENCE` 等）。缺项时中继照常启动，只在日志里说明账号功能未启用。

这些变量会真正进入容器：两个入口的 `relay` 服务都用 `env_file` 读取同一个 `.env`（`required: false`，所以没有 `.env` 时和以前完全一样）。注意 `.env` 同时还是 Compose 的插值来源，改完要重新创建容器才生效：

```sh
docker compose -f compose.tls.yml up -d

docker compose -f compose.tls.yml exec relay printenv DB_HOST OAUTH_ISSUER
docker compose -f compose.tls.yml logs --tail=20 relay   # 看 accounts=on/off 与数据库状态
```

TLS 入口的 `RELAY_TRUST_PROXY=1` 写在 `environment:` 里，优先级高于 `env_file`，不会被 `.env` 覆盖。

`RELAY_KEY` **不要**放进 `.env`：注册密钥应留在 `relay-data` 卷的 `/data/relay-key` 里，否则重建容器或换服务器时电脑的注册身份会跟着变。

数据库结构不会自动创建：先在能连到数据库的环境执行一次 `node src/db/migrate.ts`，或临时设置 `RELAY_DB_AUTO_MIGRATE=1`。迁移失败时中继会拒绝启动，避免代码和表结构不一致。

## 8. 查看状态、升级和切换入口

公网入口：

```sh
docker compose -f compose.tls.yml ps
docker compose -f compose.tls.yml logs --tail=50 relay caddy
```

局域网入口去掉 `-f compose.tls.yml`。内部健康检查路径为 `/healthz`。

升级只换镜像标签，保留 `.env` 和数据卷：

```sh
# 部署某个已发布的版本
sed -i 's/^RELAY_IMAGE=.*/RELAY_IMAGE=ghcr.io\/azurekiln2333\/cloudterminal-relay-server:v0.1.0/' .env
docker compose -f compose.tls.yml pull
docker compose -f compose.tls.yml up -d
```

用 `:latest` 时 `pull` + `up -d` 即可拿到新版本。`restart: unless-stopped` 不会自动升级镜像，需要重新 `pull`。

两个 Compose 文件是**独立入口**，不要叠加使用。从局域网切到 HTTPS：

```sh
docker compose down
docker compose -f compose.tls.yml up -d
```

反向切换先执行 `docker compose -f compose.tls.yml down`，再执行 `docker compose up -d`。不要加 `-v`，以免删除持久数据。

两个入口都显式使用项目名 `cloudterminal`，与原先从 `cloudterminal/` 仓库根目录启动的默认项目名一致；中继拆到独立仓库后仍复用 `cloudterminal_relay-data` 等数据卷（Compose 项目名是普通字符串，没跟着仓库改名）。**如果旧部署使用过自定义 `-p`、`COMPOSE_PROJECT_NAME`，或原目录名不是 `cloudterminal`，请在新命令中沿用原项目名**，例如 `docker compose -p 原项目名 -f compose.tls.yml up -d`。停止旧入口和查询密钥时也要使用同一项目名。

## 9. 数据和排障

- 中继首次启动生成注册密钥，保存到 `relay-data` 卷内的 `/data/relay-key`，后续启动、重启和升级都复用；普通日志不打印密钥。
- 不要删除 `relay-data` 卷。TLS 入口还使用 `caddy-data` 和 `caddy-config` 卷保存证书与配置。
- 如需显式指定密钥，可在环境中设置 `RELAY_KEY`；它优先于 `RELAY_KEY_FILE`。显式空值会报错，不能用于关闭认证。
- TLS 保护传输，中继进程仍可读取转发内容；当前没有端到端加密。
- `pull` 失败：确认镜像标签真的发布过（第 1 节的 `docker manifest inspect`），以及这台机器是否已 `docker login` 到该仓库。
- 证书失败时检查域名解析和 80/443 入站；无法连接时先查看容器状态及日志，再核对电脑使用的地址和注册密钥。

## 10. 验证状态

- 镜像构建、容器启动、`/healthz`、非 root 用户、重启后密钥复用：已在开发机的隔离 Docker 环境（独立项目名、独立卷、临时端口）实测通过，未触碰任何现有部署。
- 镜像**尚未发布**到任何仓库：本仓库还没有 git remote，CNB / GitHub 流水线都没有运行过。第一次发布需要先配好 remote 并推 `v*` 标签。