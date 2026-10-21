# CADP — Challenge Anti DDoS +

**一个给静态站点用的、可插拔 challenge 的反 DDoS 门禁。**

当你的站点只是静态页面、却因为暴露公网端口被扫描器/僵尸网络按着打时，CADP 可以做几件事：

1. **给新访客一个 challenge**（不用登录、不用数据库）；
2. **多组 challenge**：必须依次完成所有配置的组才放行；
3. **把部分 challenge 换成短时算力任务**（hash 挖矿式 PoW / 小线性模型训练），把成本转移给客户端；
4. **自动封禁**：challenge 超时、刷请求、验证失败、SYN/连接洪泛；
5. **自带管理后台**：统计、调参、封禁/解封、查看 top IP；
6. **一键安装**：`install.ps1` 从 GitHub 下载并注册为 Windows 计划任务。

> ⚠️ 定位：CADP 是**应用层门禁**，不是带宽型 DDoS 清洗设备。真正的流量型攻击仍需要 Cloudflare / 阿里云高防 / WAF。CADP 负责把“扫描器、脚本、半开连接”挡在静态站之外。

---

## 一键安装（Windows Server）

前置条件：**Python 3.10+ 已在 PATH 中**。

以**管理员**身份打开 PowerShell：

```powershell
irm https://raw.githubusercontent.com/LLYlab/CADP/main/install.ps1 | iex
```

或下载后运行：

```powershell
.\install.ps1 -Dest C:\CADP -Port 8080
```

安装脚本会：

- 下载并解压仓库 zip 到 `C:\CADP`
- 找到 `python.exe`，生成 `config.json` 和随机 Admin 密码
- 创建计划任务 `CADP`（开机自启、异常重启）
- 添加防火墙放行端口
- 打印后台地址和密码

默认地址：

- 站点：`http://<host>:8080/`
- 后台：`http://<host>:8080/__cadp/admin`

> 部署到公网建议加 HTTPS（反向代理 / Cloudflare），并改掉随机密码。后台密码在 `C:\CADP\ADMIN_PASSWORD.txt`，首次登录后请自行保存。

## 手动运行

```powershell
python cadp.py --init-config --config config.json --port 8080 --root site
python cadp.py --config config.json
```

把静态文件放进 `site/`。

## Challenge 类型（可选）

在 `config.json` 的 `challenge_groups` 里配置，每个组会**按顺序**执行：

| type | 说明 | 客户端成本 |
|---|---|---|
| `pow_fnv` | FNV-1a 前导零 PoW（默认） | 约 0.1–3 秒 |
| `mine` | 更高难度的 hash 任务（“挖矿式”，非加密货币） | 数秒 |
| `arith` | 简单算术（最弱，仅建议做交互门槛） | <1ms |
| `linear_train` | 在浏览器里训练一个小线性回归模型，服务端验收 MSE | 约 0.5–3 秒 |

多组示例（必须全部完成）：

```json
"challenge_groups": [
  {"id": "pow-1", "type": "pow_fnv", "bits": 20, "count": 1, "enabled": true},
  {"id": "pow-2", "type": "pow_fnv", "bits": 22, "count": 2, "enabled": true},
  {"id": "train", "type": "linear_train", "epochs": 120, "lr": 0.05, "threshold": 0.01, "count": 1, "enabled": false}
]
```

`count` 表示该组要连续完成的次数。所有组完成后发放 `cadp_pass` cookie（HMAC、绑定 IP、默认 1 小时）。

## 盈利任务与使用提示（monetization）

CADP 支持把 challenge 后面的 **work groups** 作为盈利/回血任务。开启后，新访客会**自动进入 challenge 页**，页面顶部显示提示；challenge 是自动、强制的，不同意请直接关闭页面。

```json
"monetization": {
  "enabled": false,
  "notice": "服务器将通过验证系统进行小规模盈利任务，如您不同意，请关闭页面。",
  "groups": [
    {"id": "work-1", "type": "mine", "bits": 20, "count": 1, "enabled": true}
  ]
}
```

- `enabled` 默认 **false**；设为 `true` 后，访问者会直接看到带提示的 challenge 页。
- challenge 自动开始，不需要点击同意；**不同意就关闭页面**。关闭页面不会被封禁。
- 先完成 `challenge_groups`，再执行 `monetization.groups`；结果写入 `work.jsonl`，后台显示 **Work units**。
- 这些任务仍然是**可验证的短时计算**（PoW / 小模型训练），服务端验证结果用于记账；它们不是安全放行验证。
- 仓库**不内置矿池、不内置结算/提现**；`work.jsonl` 只是工作记录，真实盈利需要你自行接外部结算。
- 任务必须短时、可见；不要在第三方站点强制使用。

## 管理后台

`/__cadp/admin`：

- **Dashboard**：请求数、challenge 通过数、当前封禁数、组数
- **Ban / Unban**：手动封禁/解封 IP（解封会同时删除防火墙规则）
- **Config**：直接编辑 JSON 并保存（challenge 组、阈值、pass TTL、SYN 阈值等）
- **Top IPs**：请求量排行

后台使用密码登录（PBKDF2），会话 cookie 为 HMAC 签名、`HttpOnly`、`SameSite=Strict`。

## SYN / 连接洪泛检测

`syn` 配置：

```json
"syn": {
  "enabled": true,
  "syn_threshold": 10,
  "est_threshold": 24,
  "block_firewall": true
}
```

- Windows：每 2 秒读 `GetExtendedTcpTable`，统计到监听端口的 `SYN_RCVD` / `ESTABLISHED`；
- 同一 IP 超阈值 → 封禁；`block_firewall=true` 时同时添加 Windows 防火墙规则，**只封该 IP 的监听端口**（不会封 SSH）；
- Linux：读取 `/proc/net/tcp`（基础支持，建议生产用 nftables/iptables 配合）。

## 配置文件（节选）

```json
{
  "listen_host": "0.0.0.0",
  "listen_port": 8080,
  "root": "site",
  "pass_ttl": 3600,
  "pending_ttl": 30,
  "rate_window": 10,
  "rate_max": 30,
  "fail_max": 5,
  "ban_ttl": 3600,
  "pool_size": 20000,
  "challenge_groups": [...],
  "syn": {...}
}
```

- `pool_size`：预生成 challenge 池大小（默认 20,000；轮换使用，不按请求生成）
- `pending_ttl`：拿到 challenge 后未完成就封禁的秒数
- `rate_max/rate_window`：每 IP 的 start 请求速率
- `fail_max`：验证失败上限
- `ban_ttl`：封禁默认时长

## 安全与伦理

- **算力任务必须可见、短时、可退出**：`monetization.enabled` 默认关闭；开启后 challenge 自动开始并在页面顶部显示提示，不同意可直接关闭页面，不会被封禁。
- **不做隐藏挖矿、不接矿池、不持久占用客户端 CPU**：所有任务在 challenge 页内完成，无后台循环；仓库不内置矿池或结算。
- **不记录敏感内容**：工作记录只写 `work.jsonl`（IP、任务类型、结果），后台密码 hash 存储。
- **建议 HTTPS**：pass/admin/consent cookie 在 HTTP 下可被同路径窃听；绑定 IP 能降低风险，但不等于 TLS。
- 必须在**你拥有或获授权**的服务器/站点上使用；不要在第三方站点上强制算力任务。

## 测试

```powershell
python -m unittest discover -s tests -v
```

## 目录

```
cadp.py                 单文件服务（无第三方依赖）
config.example.json     示例配置
site/index.html         示例静态页
install.ps1             Windows 一键安装
tests/test_cadp.py      核心函数自检
tests/test_integration.py  端到端 challenge / admin 测试
work.jsonl              运行时的盈利任务记录（自动生成）
```

## License

MIT
