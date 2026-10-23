# SKK Ruleset attribution

These MRS files are generated from the Mihomo-compatible Clash output
published by [Sukka Ruleset](https://github.com/SukkaLab/ruleset.skk.moe).

- Upstream commit: `fb9700a0c0fc933b57c4e2f0c95fbc068ae1ba51`
- Clash tree: `f37b4a79412f3882d52d044d041ed2c0fa00fc7a`
- Converter: Mihomo `alpha-3f27ef3`
- Most `domainset`, `non_ip`, and `ip` sources: AGPL-3.0
- `ip/china_ip.mrs` and `ip/china_ip_ipv6.mrs`: CC BY-SA 2.0

Clash classical files are split into the domain and ipcidr subsets that
MRS can represent without changing their matching direction. Unsupported
individual entries are listed in `conversion-report.json` and do not
prevent other entries in the same source file from being converted. MRS
cannot store per-entry `no-resolve`; set that option on the consuming
`RULE-SET` rule when required.
