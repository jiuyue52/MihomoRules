# MihomoRules

这个仓库通过 GitHub Actions 将 SKK 的 Clash 规则和自定义规则源转换为
Mihomo MRS。

## SKK 输出

SKK 产物保留上游 `Clash` 下的路径和分类：

- `Clash/domainset/foo.txt` -> `rules/skk/domainset/foo.mrs`
- `Clash/non_ip/foo.txt` -> `rules/skk/non_ip/foo.mrs`
- `Clash/ip/foo.txt` -> `rules/skk/ip/foo.mrs`

混合文件会按 MRS 支持的行为拆分。主分类仍使用原文件名；次要分类增加后缀，
例如 `Clash/non_ip/reject.txt` 中的 IP 规则会输出为
`rules/skk/non_ip/reject_ipcidr.mrs`。

转换器逐条处理规则。无法无损表示为 domain/ipcidr MRS 的
`DOMAIN-KEYWORD`、复杂 `DOMAIN-WILDCARD`、`IP-ASN`、进程、端口和源地址规则
会被剔除，但不会拖垮同一文件里的可转换条目。详情见
`rules/skk/conversion-report.json`。

MRS 不能保存每一条 IP 规则上的 `no-resolve` 标记；需要该行为时，应在使用
规则集的 `RULE-SET` 规则上设置 `no-resolve`。

## 自定义规则

只需编辑仓库根目录的 `custom-rules.json`。每项支持以下字段：

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `source` | 是 | 仓库内相对路径，或 HTTPS URL |
| `behavior` | 否 | `domain`、`ipcidr` 或 `auto`，默认 `auto` |
| `output` | 否 | `JYRules` 内的相对路径；省略时取源文件名 |
| `enabled` | 否 | 是否启用，默认 `true` |

示例：

```json
{
  "rules": [
    {
      "source": "https://example.com/domain-rules.txt",
      "behavior": "domain",
      "output": "example/domain.mrs"
    },
    {
      "source": "sources/mixed-rules.txt",
      "behavior": "auto",
      "output": "mixed/example"
    }
  ]
}
```

`domain` 和 `ipcidr` 各生成一个指定文件。`auto` 始终按行为使用固定后缀，
例如上例会按实际内容生成 `mixed/example_domain.mrs` 和/或
`mixed/example_ipcidr.mrs`。本地源只能使用仓库内相对路径，输出也不能使用
绝对路径或 `..`。

规则源支持 SKK 这种逐行文本，以及只有 `payload:`/`rules:` 列表的简单 YAML。
它不会解析带完整 Clash 配置结构或 flow-style payload 的复杂 YAML。

工作流每小时检查 SKK、Mihomo 版本和自定义远程规则；也可以在 Actions 页面
手动运行 `Update SKK and custom Mihomo MRS`。

工作流目前固定使用已校验的 Mihomo `v1.19.29`。升级核心时需要同时更新工作流
里的版本号和 Linux 资产 SHA256，避免下载未经固定校验的滚动资产。
