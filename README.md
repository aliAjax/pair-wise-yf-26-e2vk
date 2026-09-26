# 数字档案长期保存服务

仅使用 Python 3.11+ 标准库实现的独立档案保存项目，支持清单校验、真实 SHA-256 内容校验、多个离线副本、损坏检测与自动修复、格式迁移、保留期限和访问控制。

## 运行

```bash
python3 app.py --init --seed
python3 app.py
```

服务地址为 <http://127.0.0.1:8102>，默认数据库 `preservation.db`。测试：

```bash
python3 -m unittest -v
```

演示用户：`owner`、`archivist`、`auditor`、`outsider`。API 使用 `X-User-Id`。文件通过 Base64 提交，单文件上限 10 MiB；这是为了保持示例自包含，生产部署应换成对象存储和流式上传。

## 主要接口

- `POST /api/archives`：创建受限档案。
- `POST /api/archives/{id}/members`：所有者授予 read/write 权限。
- `POST /api/archives/{id}/versions`：提交文件清单，服务端重新计算哈希和大小。
- `GET /api/versions/{id}`：查看版本、文件清单和副本状态。
- `POST /api/versions/{id}/copies`：创建独立副本内容。
- `POST /api/copies/{id}/verify`：校验副本；发现损坏时从健康副本修复。
- `POST /api/copies/{id}/simulate-corruption`：演示/测试介质损坏，仅 owner 或 archivist 可用。
- `POST /api/versions/{id}/migrate`：生成格式迁移后的新版本并保留派生关系。
- `GET /api/archives/{id}/status`：保留期限、版本状态、解密申请记录和审计记录。
- `POST /api/archives/{id}/declassification-requests`：提交解密申请。仅保密期限已到期的受限档案可进队列；最新版本仍有未迁到新格式的文件（见 `LEGACY_FORMATS`）时不受理并在 `error.files` 中列出清单，迁完再提；同一档案只留一份待处理申请。
- `GET /api/declassification-requests?status=pending`：查看复核队列（owner/archivist/auditor）。
- `POST /api/declassification-requests/{id}/review`：复核，`decision` 为 `approve` 或 `reject`。提出人不能复核自己的申请，须另找一名同事；驳回必须附 `comment` 意见；补充后重提自动记录轮次 `round`；批准后档案不再受限。
- `GET /api/public/archives`、`GET /api/public/archives/{id}`：公开目录与版本文件清单，无需登录；未公开档案一律 404。
- `GET /api/versions/{id}/files/{path}`：下载文件正文，即使档案已公开仍要求成员权限。

档案路径拒绝绝对路径和 `..`；同一版本副本位置唯一；没有健康副本时版本标记为 `degraded`；所有变更写入审计日志。
