# SKK Ruleset attribution

These MRS files are generated from the Mihomo-compatible Clash output
published by [Sukka Ruleset](https://github.com/SukkaLab/ruleset.skk.moe).

- Upstream commit: `4947c8bad43b655800fb61a5af702602197be472`
- Clash tree: `6756afdf17c02f7986512d8e7f64d69f38e1d7aa`
- Converter: Mihomo `v1.19.29`
- Most `domainset`, `non_ip`, and `ip` sources: AGPL-3.0
- `ip/china_ip.mrs` and `ip/china_ip_ipv6.mrs`: CC BY-SA 2.0

Clash classical files are split into the domain and ipcidr subsets that
MRS can represent without changing their matching direction. Unsupported
individual entries are listed in `conversion-report.json` and do not
prevent other entries in the same source file from being converted. MRS
cannot store per-entry `no-resolve`; set that option on the consuming
`RULE-SET` rule when required.
