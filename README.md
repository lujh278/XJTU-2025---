# 可搜索加密SSE 系统（Go）

本项目实现的是**单用户 - 单服务器**模型，并且在代码层做了模块隔离：
- 客户端模块：`client/crypto`（密钥、加密、关键词检索、文档解析）
- 服务器接口：`server/sse`（仅暴露服务器操作接口）
- 服务器实现：`server/store`（内存存储与状态持久化）

服务器只保存密文和加密索引；只有客户端持有密钥并执行检索解密。

## 模块边界

### `server/sse`（接口层，仅接口）
- `Backend`：
  - `AddPosting`
  - `Postings`
  - `PutDocument`
  - `GetDocument`
- `State`/`Posting`/`EncryptedDocument`：服务端共享数据结构

### `server/store`（服务器存储实现）
- `InMemory`：实现 `server/sse.Backend`
- `SaveState` / `LoadState`：服务端状态落盘与恢复

### `client/crypto`（客户端密码与检索）
- `MasterKey`、`ClientState`
- `Client.AddDocument`、`Client.SearchAND`
- `SaveMasterKey` / `LoadMasterKey`
- `SaveClientState` / `LoadClientState`
- `LoadDocumentTextFromPath`（支持 `.pdf/.docx/.txt`）

## 目录结构

```text
.
├─ client/
│  ├─ crypto/
│  │  ├─ core.go
│  │  ├─ persist.go
│  │  └─ document_loader.go
│  ├─ sse-cli/main.go
│  ├─ sse-ui/main.go
│  └─ data/
│     ├─ master_key.json
│     └─ client_state.json
├─ server/
│  ├─ sse/backend.go
│  ├─ store/
│  │  ├─ memory.go
│  │  └─ persist.go
│  └─ data/
│     └─ server_state.json
└─ go.mod
```

## 初始化

```bash
go run ./client/sse-cli init --client-dir ./client/data --server-dir ./server/data --force
```

## 添加文档

文本方式：

```bash
go run ./client/sse-cli add --client-dir ./client/data --server-dir ./server/data --id doc1 --text "cloud storage for backups"
```

路径方式（支持 `.docx/.txt`）：

```bash
go run ./client/sse-cli add --client-dir ./client/data --server-dir ./server/data --path "C:\Users\lujh\Desktop\1.docx"
```

## 关键词查询（AND）

```bash
go run ./client/sse-cli search --client-dir ./client/data --server-dir ./server/data --keywords cloud,storage
```

## 终端交互界面

```bash
go run ./client/sse-ui
```

## 安全语义（当前实现）

- 客户端：
  - 持有主密钥（`master_key.json`）
  - 生成关键词 token（trapdoor）
  - 维护本地关键词计数器（`client_state.json`）
  - 解密命中文档
- 服务器：
  - 保存 `server_state.json`（密文文档 + token 索引）
  - 不具备明文检索能力

bilibili演示视频：https://www.bilibili.com/video/BV11pPTzsEQM/?vd_source=eedeef56d5bcd4a1c2dd8dfa7d97d697
