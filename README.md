# hmac-mbt — HMAC 消息认证码

## 项目目标

将 Python 标准库 `hmac` 的核心功能移植到 MoonBit，实现基于哈希函数的消息认证码（HMAC-SHA256）。

## 功能要求

- 实现 HMAC-SHA256 算法（RFC 2104）
- 支持任意长度的密钥和消息
- 支持密钥超过 64 字节时先对密钥做哈希
- 提供 `hmac_sha256(key, message)` → `Bytes`
- 提供 `verify(key, message, tag)` → `Bool`（恒定时间比较）
- 依赖 MoonBit 标准库的 SHA256 实现

## 参考

- Python: `import hmac; hmac.new(key, msg, 'sha256').digest()`
- 已有生态：mooncakes 上有独立 SHA256（gmlewis/sha256），但无 HMAC

## 难度

⭐⭐⭐ — 需要理解 HMAC 算法和位运算
