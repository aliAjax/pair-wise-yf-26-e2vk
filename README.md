# 数字档案长期保存服务

仅使用 Python 3.11+ 标准库实现的独立档案保存项目，支持清单校验、真实 SHA-256 内容校验、多个离线副本、损坏检测与自动修复、格式迁移、保留期限、访问控制，以及受限档案的到期解密公开（申请-复核-公开目录）。

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

种子数据包含四个演示档案：已公开档案、到期但含旧格式文件（`.tif`/`.xml`）的档案、到期且已迁移并有一份待处理申请的档案、未到期档案。

## 主要接口

- `POST /api/archives`：创建受限档案。
- `POST /api/archives/{id}/members`：所有者授予 read/write 权限。
- `POST /api/archives/{id}/versions`：提交文件清单，服务端重新计算哈希和大小。
- `GET /api/versions/{id}`：查看版本、文件清单和副本状态。
- `POST /api/versions/{id}/copies`：创建独立副本内容。
- `POST /api/copies/{id}/verify`：校验副本；发现损坏时从健康副本修复。
- `POST /api/copies/{id}/simulate-corruption`：演示/测试介质损坏，仅 owner 或 archivist 可用。
- `POST /api/versions/{id}/migrate`：生成格式迁移后的新版本并保留派生关系。
- `GET /api/archives/{id}/status`：保留期限、版本状态和审计记录。

## 到期解密公开

- `POST /api/archives/{id}/declassification`：提交解密申请。仅保留期限已过的档案可提交；档案中仍有旧格式文件（`.xml`、`.tif`、`.tiff`、`.gif`、`.bmp`、`.doc`、`.rtf`，以最新版本为准）时不受理，响应 `422 unmigrated_files` 并在 `error.details.files` 中列出这些文件，迁移完成后再提。每个档案只保留一份待处理申请（重复提交返回 `409 pending_exists`）。
- `GET /api/declassification/requests`：待处理申请队列（owner / archivist）。
- `POST /api/declassification/{id}`：复核，`{"approve": true|false, "comment": "..."}`。提出人不能复核自己的申请（`403 self_review_forbidden`），须由另一名 owner / archivist 处理；驳回必须写明意见（`422 comment_required`）。批准后档案 `restricted=0`；驳回后可补充重提，申请记录中的 `attempt` 逐次累加。
- `GET /api/archives/{id}/declassification`：该档案的全部申请记录（含意见与提交次数），需成员权限。
- `GET /api/public/catalog`：公开目录，任何访客无需登录即可查看已解密档案的名称与期限。
- `GET /api/public/archives/{id}/manifest`：已解密档案最新版本的公开清单（路径、SHA-256、大小），不含正文；受限档案返回 403。
- `GET /api/archives/{id}/files?path=...`：读取文件正文（Base64）。档案解密后正文仍要求成员权限，公众只能查目录和清单。

档案路径拒绝绝对路径和 `..`；同一版本副本位置唯一；没有健康副本时版本标记为 `degraded`；所有变更（含解密申请与复核）写入审计日志。

网页（`http://127.0.0.1:8102/`）提供公开目录浏览、解密申请提交、复核队列和申请记录查询。
