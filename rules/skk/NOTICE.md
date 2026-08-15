# SKK Ruleset attribution

These MRS files are generated from the Mihomo-compatible Clash output
published by [Sukka Ruleset](https://github.com/SukkaLab/ruleset.skk.moe).

- Upstream commit: `9fbd0c0b84c14b2552149e7389628b0a08963795`
- Clash tree: `ce36163c6a4c481053a3d0b53b490ccb38dfd189`
- Converter: Mihomo `v1.19.29`
- Most `domainset`, `non_ip`, and `ip` sources: AGPL-3.0
- `ip/china_ip.mrs` and `ip/china_ip_ipv6.mrs`: CC BY-SA 2.0

Clash classical files are split into the domain and ipcidr subsets that
MRS can represent without changing their matching direction. Unsupported
individual entries are listed in `conversion-report.json` and do not
prevent other entries in the same source file from being converted. MRS
cannot store per-entry `no-resolve`; set that option on the consuming
`RULE-SET` rule when required.
