### 仍应以单元测试覆盖（不应误归为集成测试）

- `src/dnstamp.rs`：域名/路径校验、Base64/二进制 Stamp 解析、截断/空输入等边界。现有测试已经主要覆盖这里。
- `src/config.rs:39-50`、`src/config.rs:53-68`：Minisign 验签可使用固定正文、签名与公钥 fixture 直接调用真实密码学库测试；无需真实网络。
- `src/config.rs:111-124`：resolver Markdown 的 heading/stamp 提取应抽成纯函数后测试合法与损坏文本。
- `src/rug_dns_resolver.rs:180-201`：重试次数、超时预算、错误分类和是否触发重连应在连接/查询接口可替换后，使用 fake 和 Tokio 暂停时钟（paused time）测试。
- `src/rug_dns_handler.rs:41-94`：多 query 的 `NotImp`、响应 ID 回写、SOA 分区与 resolver 错误映射，均可在 resolver 抽象为 trait 后用 fake resolver 和 fake response handler 做单元测试。

### 必须使用受控本地集成测试的路径（最高优先级）

1. **入站 UDP DNS 服务。** `src/main.rs:27-41` 将配置、UDP socket、Hickory `ServerFuture` 和 handler 组合在一起。测试必须在 `127.0.0.1:0` 绑定真实 socket，并使用 DNS wire-format client 发送请求；mock 不能证明绑定、编码/解码和实际响应语义正确。
2. **上游 DoH 传输。** `src/rug_dns_resolver.rs:91-130` 直接构建 Rustls、HTTP/2 和 `DnssecClient`。应通过 loopback TLS+HTTP/2 DoH fixture 验证 TLS/SNI/ALPN、请求 path、DNS wire 格式和响应解析；此层不能由 fake client 替代。
3. **DoH 断线与重连。** `src/rug_dns_resolver.rs:134-169` 的 background task 状态与重新握手，必须由本地 DoH 服务主动断开连接后，以后续真实 DNS 请求验证重连是否恢复服务。
4. **端到端超时传播。** `src/rug_dns_resolver.rs:179-193` 与 `src/rug_dns_handler.rs:52-63` 都在 `timeout` 后 `expect`，目前会 panic 而非返回 DNS 错误。需用延迟响应的本地 DoH fixture + UDP client 验证客户端能获得定义的失败响应且服务继续存活。
5. **缓存读写与离线回退。** `src/config.rs:71-128` 同时涉及 Tokio 文件系统、并发下载和环境确定的缓存路径。使用独立临时目录及本地 fixture server 验证“下载成功写缓存 → 网络不可用 → 验签后从缓存加载”、缺失/损坏签名、权限错误与并发更新。此为文件系统组件集成测试，不应访问公网或 `/tmp/rugdns`。
6. **配置发现与二进制启动。** `src/config.rs:131-170`、`src/main.rs:22-41` 依赖 CWD、环境和真实启动过程。应以隔离的子进程、CWD、HOME/XDG 与临时配置文件验证优先级、无配置/无效 TOML 的退出行为和监听配置。特别应覆盖 `"~/.config/..."` 不会由 Rust 自动展开的实际缺陷。