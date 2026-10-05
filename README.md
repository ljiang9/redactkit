# redactkit

本地 PII / 密钥脱敏小工具。敏感数据进，`[REDACTED:*]` 出。

**纯本地、纯标准库、不联网** —— 你的数据不会离开这台机器。

## 快速开始

```bash
# 脱敏一个文本文件
python3 -m redactkit examples/mixed.txt

# 从 stdin 读，结果写文件
cat log.txt | python3 -m redactkit --stdin -o log.redacted.txt

# JSON 模式：敏感键名的值整体脱敏，结构保留
python3 -m redactkit --json examples/payload.json

# 看脱敏统计
python3 -m redactkit --stats examples/mixed.txt

# 审计模式：逐行对照 原行 → 脱敏行
python3 -m redactkit --diff examples/mixed.txt
```

## 内置检测器

| 类型 | 说明 |
|---|---|
| `email` | 邮箱地址 |
| `phone_cn` | 中国大陆手机号 `1[3-9]xxxxxxxxx` |
| `phone` | 通用电话（`010-88889999`、`+86-138-1234-5678` 等） |
| `cn_id` | 18 位身份证号（按格式匹配） |
| `ipv4` | IPv4 地址（校验每段 0–255，`999.1.1.1` 不会被误杀） |
| `card` | 13–19 位卡号，**必须通过 Luhn 校验**才会脱敏 |
| `aws_key` | `AKIA…` 开头的 AWS 访问密钥 |
| `github_token` | `ghp_…` 等 GitHub token |
| `secret_key` | （仅 JSON 模式）键名命中 `password` / `api_key` / `token` / `secret` 等的值，整体脱敏 |

重叠命中时，排在前面的检测器优先（`card` 优先于 `phone`，避免卡号被切碎）。

## 实用参数

```bash
# 只启用部分检测器
python3 -m redactkit --types email,phone_cn file.txt

# 卡号保留后四位：[REDACTED:card:****1111]
python3 -m redactkit --keep-last4 file.txt

# 自定义检测器（可重复）
python3 -m redactkit --custom 'order_id:ORD-\d{8}' file.txt

# 查看所有类型
python3 -m redactkit --list-types
```

## 诚实说明（局限）

- **正则方案有固有误报/漏报**：比如 `phone` 可能把订单号当电话，`email` 匹配不了带中文的畸形地址。重要场景请用 `--diff` 人工审计一遍。
- 身份证号只按 **18 位格式**匹配，不做校验位验证（避免把输错一位的真实号码漏掉）；代价是连续的 18 位数字串会被脱敏。
- 卡号依赖 **Luhn 校验**：测试卡 `4111111111111111` 会被脱敏，`4111111111111112`（校验失败）不会。
- JSON 模式只看**键名**脱敏敏感值；键名起得随意（如 `data` 里塞密码）就靠文本检测器兜底。
- **这不是合规保证**。它是个开发/调试期的小工具，正式的 PII 合规流程请走法务认可的方案。

## License

MIT
