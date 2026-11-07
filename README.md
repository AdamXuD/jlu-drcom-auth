# JLU DrCOM Docker 认证客户端

客户端通过 UDP `61440` 完成 DrCOM challenge/login，登录后持续发送心跳并探测真实联网状态。WiFi 等网络连接由宿主机管理。网络断开、服务器不可达、心跳异常或联网探测连续失败时，客户端通过同一个重试流程重新认证。

## Docker 部署

在能访问吉林大学校园网认证服务器的 Docker 宿主机上运行。

```sh
cp .env.example .env
chmod 600 .env
```

在 `.env` 中填写认证服务器地址 `DRCOM_SERVER`、账号 `DRCOM_USERNAME`、密码 `DRCOM_PASSWORD` 和已登记的 MAC 地址 `DRCOM_REGISTERED_MAC`。

```sh
docker build -t jlu-drcom-auth .
```

### Host 模式

Linux Docker Engine 可使用 host 模式直接通过宿主机的网络发送 UDP。请先停止占用宿主机 UDP `61440` 的其他 DrCOM 客户端。 [Docker host 网络文档](https://docs.docker.com/engine/network/drivers/host/)

```sh
docker run -d --name jlu-drcom-auth --restart unless-stopped \
  --network host --env-file .env jlu-drcom-auth
```

### Bridge 模式

如果宿主机能访问认证服务器的 UDP `61440`，且校园网接受 NAT 后的源地址和端口，可以使用 bridge 模式。客户端主动发送请求，UDP 回包通过 NAT 返回容器。 [Docker bridge 网络文档](https://docs.docker.com/engine/network/drivers/bridge/)

```sh
docker run -d --name jlu-drcom-auth --restart unless-stopped \
  --network bridge --env-file .env jlu-drcom-auth
```

客户端优先使用 challenge 响应提供的 IPv4 写入登录包和心跳包，缺失时使用 UDP 套接字的本地 IPv4。bridge 模式下，本地 IPv4 通常是容器的私网地址。如果认证服务拒绝该地址或 NAT 后的流量，请使用 host 模式。

账号、密码和 MAC 通过运行时环境变量传入。镜像构建只读取客户端代码和 Dockerfile。运行 `docker logs -f jlu-drcom-auth` 查看日志。

## 重试和探测参数

| 环境变量 | 默认值 | 作用 |
| --- | --- | --- |
| `DRCOM_CHECK_INTERVAL` | `30` | UDP 或联网探测失败后重新认证前等待的秒数 |
| `DRCOM_KEEP_ALIVE_INTERVAL` | `10` | 两轮心跳之间等待的秒数 |
| `DRCOM_SOCKET_TIMEOUT` | `10` | 每次 UDP 请求等待响应的秒数 |
| `DRCOM_MAX_UDP_RETRIES` | `3` | 每个 UDP 请求的最大尝试次数 |
| `DRCOM_ONLINE_CHECK_INTERVAL` | `10` | 联网探测间隔，单位为秒，设为 `0` 可关闭 |
| `DRCOM_ONLINE_CHECK_TIMEOUT` | `5` | 单个联网探测请求的超时秒数 |
| `DRCOM_ONLINE_CHECK_FAILS` | `1` | 连续失败多少轮后重新认证 |
| `DRCOM_ONLINE_CHECK_URLS` | 见 `.env.example` | 英文逗号分隔的探测 URL，任一成功即视为联网 |

联网探测在心跳成功后执行，直接访问探测地址。默认 `generate_204` 地址须直接返回 HTTP `204`，其他自定义地址须直接返回 `2xx`。

已有部署可继续通过环境变量配置登录包字段 `DRCOM_HOST_NAME`、`DRCOM_PRIMARY_DNS`、`DRCOM_DHCP_SERVER`、`DRCOM_CONTROLCHECKSTATUS`、`DRCOM_ADAPTERNUM`、`DRCOM_IPDOG`、`DRCOM_AUTH_VERSION` 和 `DRCOM_KEEP_ALIVE_VERSION`。
