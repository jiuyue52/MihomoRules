#!/usr/bin/env python3

from __future__ import annotations

import argparse
import ast
import ipaddress
import json
import os
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Iterable


MAX_SOURCE_BYTES = 64 * 1024 * 1024
MAX_DROP_EXAMPLES = 3
SUPPORTED_BEHAVIORS = {"auto", "domain", "ipcidr"}
WINDOWS_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CLOCK$"}
    | {f"COM{index}" for index in range(1, 10)}
    | {f"LPT{index}" for index in range(1, 10)}
)
SKK_MARKERS = frozenset(
    {
        "7h15.ru1353t.1s.m4d3.by.5ukk4w.skk.moe",
        "7h1s_rul35et_i5_mad3_by_5ukk4w-ruleset.skk.moe",
        "th1s_rule5et_1s_m4d3_by_5ukk4w_ruleset.skk.moe",
        "this_ruleset_is_made_by_sukkaw.ruleset.skk.moe",
    }
)


class BuildError(RuntimeError):
    pass


@dataclass
class RuleBuckets:
    candidates: int = 0
    domain: list[str] = field(default_factory=list)
    ipcidr: list[str] = field(default_factory=list)
    dropped: Counter[str] = field(default_factory=Counter)
    examples: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    _domain_seen: set[str] = field(default_factory=set)
    _ipcidr_seen: set[str] = field(default_factory=set)

    def drop(self, reason: str, line: str) -> None:
        self.dropped[reason] += 1
        if len(self.examples[reason]) < MAX_DROP_EXAMPLES:
            self.examples[reason].append(line[:240])

    def add_domain(self, value: str, line: str) -> None:
        if value in self._domain_seen:
            self.drop("duplicate_domain", line)
            return
        self._domain_seen.add(value)
        self.domain.append(value)

    def add_ipcidr(self, value: str, line: str) -> None:
        if value in self._ipcidr_seen:
            self.drop("duplicate_ipcidr", line)
            return
        self._ipcidr_seen.add(value)
        self.ipcidr.append(value)

    def dropped_json(self) -> dict[str, dict[str, object]]:
        return {
            reason: {
                "count": self.dropped[reason],
                "examples": self.examples.get(reason, []),
            }
            for reason in sorted(self.dropped)
        }


def _unquote_yaml_scalar(value: str) -> str:
    if len(value) < 2 or value[0] not in "\"'" or value[-1] != value[0]:
        return value
    try:
        parsed = ast.literal_eval(value)
    except (SyntaxError, ValueError):
        return value[1:-1]
    return parsed if isinstance(parsed, str) else value


def iter_rule_lines(text: str) -> Iterable[str]:
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        if line.lower() in {"---", "...", "payload:", "payload: []", "rules:", "rules: []"}:
            continue
        if line.startswith("- "):
            line = _unquote_yaml_scalar(line[2:].strip()).strip()
            if not line:
                continue
        yield line


def is_skk_marker(value: str) -> bool:
    value = value.lower().strip()
    if value.startswith("+."):
        value = value[2:]
    elif value.startswith("."):
        value = value[1:]
    return value in SKK_MARKERS


def valid_domain_text(value: str) -> bool:
    if not value or value.endswith(".") or "/" in value or "," in value:
        return False
    if value[0].isspace() or value[-1].isspace():
        return False
    parts = value.split(".")
    if len(parts) == 1:
        return bool(parts[0])
    return all(parts[index] for index in range(1, len(parts)))


def optimized_domain(value: str) -> str | None:
    value = value.strip().lower()
    return value if valid_domain_text(value) else None


def exact_domain(value: str) -> str | None:
    value = value.strip().lower()
    if "*" in value or "?" in value:
        return None
    parts = value.split(".")
    if not parts or parts[0] in {"", "+"}:
        return None
    return value if valid_domain_text(value) else None


def suffix_domain(value: str) -> str | None:
    value = value.strip().lower()
    if value.startswith("+."):
        value = value[2:]
    elif value.startswith("."):
        value = value[1:]
    value = exact_domain(value)
    return f"+.{value}" if value else None


def wildcard_domain(value: str) -> str | None:
    value = value.strip().lower()
    if "*" not in value and "?" not in value:
        return exact_domain(value)
    if value.startswith("*.") and value.count("*") == 1 and "?" not in value:
        suffix = exact_domain(value[2:])
        return f".{suffix}" if suffix else None
    return None


def normalized_network(value: str) -> str | None:
    try:
        network = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return None
    return str(network)


def _parse_classical(line: str) -> tuple[str, str, list[str]] | None:
    if "," not in line:
        return None
    parts = [part.strip() for part in line.split(",")]
    if len(parts) < 2:
        return None
    return parts[0].upper(), parts[1], parts[2:]


def parse_rules(text: str, behavior: str) -> RuleBuckets:
    if behavior not in SUPPORTED_BEHAVIORS:
        raise BuildError(f"unsupported behavior: {behavior}")

    result = RuleBuckets()
    for line in iter_rule_lines(text):
        result.candidates += 1
        classical = _parse_classical(line)

        if classical is None:
            if is_skk_marker(line):
                result.drop("skk_marker", line)
                continue
            if behavior == "domain":
                domain = optimized_domain(line)
                if domain:
                    result.add_domain(domain, line)
                else:
                    result.drop("invalid_domain", line)
                continue
            if behavior == "ipcidr":
                network = normalized_network(line)
                if network:
                    result.add_ipcidr(network, line)
                else:
                    result.drop("invalid_ipcidr", line)
                continue

            network = normalized_network(line)
            if network:
                result.add_ipcidr(network, line)
                continue
            domain = optimized_domain(line)
            if domain:
                result.add_domain(domain, line)
            else:
                result.drop("invalid_entry", line)
            continue

        rule_type, payload, params = classical
        if not payload:
            result.drop("missing_payload", line)
            continue
        if is_skk_marker(payload):
            result.drop("skk_marker", line)
            continue

        if rule_type == "DOMAIN" and behavior in {"auto", "domain"}:
            domain = exact_domain(payload)
            if domain:
                result.add_domain(domain, line)
            else:
                result.drop("invalid_domain", line)
        elif rule_type == "DOMAIN-SUFFIX" and behavior in {"auto", "domain"}:
            domain = suffix_domain(payload)
            if domain:
                result.add_domain(domain, line)
            else:
                result.drop("invalid_domain_suffix", line)
        elif rule_type == "DOMAIN-WILDCARD" and behavior in {"auto", "domain"}:
            domain = wildcard_domain(payload)
            if domain:
                result.add_domain(domain, line)
            else:
                result.drop("unsupported_domain_wildcard", line)
        elif rule_type in {"IP-CIDR", "IP-CIDR6"} and behavior in {"auto", "ipcidr"}:
            if any(param.lower() == "src" for param in params):
                result.drop("unsupported_source_ipcidr", line)
            else:
                network = normalized_network(payload)
                if network:
                    result.add_ipcidr(network, line)
                else:
                    result.drop("invalid_ipcidr", line)
        else:
            result.drop(f"unsupported_rule_type:{rule_type}", line)

    return result


def read_text_file(path: Path) -> str:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise BuildError(f"cannot read {path}: {exc}") from exc
    return decode_source(data, str(path))


def decode_source(data: bytes, source: str) -> str:
    if len(data) > MAX_SOURCE_BYTES:
        raise BuildError(f"source exceeds {MAX_SOURCE_BYTES} bytes: {source}")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise BuildError(f"source is not valid UTF-8: {source}: {exc}") from exc
    if "\x00" in text:
        raise BuildError(f"source contains NUL bytes: {source}")
    return text


def _validate_https_url(url: str) -> urllib.parse.ParseResult:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise BuildError(f"custom URLs must use HTTPS and include a hostname: {url}")
    if parsed.username is not None or parsed.password is not None:
        raise BuildError(f"custom URLs must not contain user information: {url}")
    hostname = parsed.hostname.rstrip(".").lower()
    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise BuildError(f"custom URL hostname is not public: {url}")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        if not address.is_global:
            raise BuildError(f"custom URL address is not public: {url}")
    return parsed


def download_text(url: str) -> str:
    _validate_https_url(url)
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "MihomoRules/1.0 (+https://github.com/jiuyue52/MihomoRules)"},
    )
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            _validate_https_url(response.geturl())
            data = response.read(MAX_SOURCE_BYTES + 1)
    except (OSError, urllib.error.URLError) as exc:
        raise BuildError(f"failed to download {url}: {exc}") from exc
    return decode_source(data, url)


def run_mihomo(
    mihomo: Path,
    behavior: str,
    entries: list[str],
    target: Path,
    work_dir: Path,
) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)
    token = f"{len(list(work_dir.iterdir())):04d}-{behavior}"
    source_file = work_dir / f"{token}.txt"
    dump_file = work_dir / f"{token}.dump.txt"
    source_file.write_text(
        "".join(f"{entry}\n" for entry in entries),
        encoding="utf-8",
        newline="\n",
    )

    convert = subprocess.run(
        [str(mihomo), "convert-ruleset", behavior, "text", str(source_file), str(target)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    log = convert.stdout or ""
    invalid_log = "invalid domain" in log.lower() or "invalid ipcidr" in log.lower()
    if convert.returncode != 0 or invalid_log or not target.is_file() or target.stat().st_size == 0:
        target.unlink(missing_ok=True)
        raise BuildError(
            f"Mihomo failed to convert {target} "
            f"({behavior}, exit {convert.returncode}):\n{log.strip()}"
        )

    verify = subprocess.run(
        [str(mihomo), "convert-ruleset", behavior, "mrs", str(target), str(dump_file)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if verify.returncode != 0 or not dump_file.is_file() or dump_file.stat().st_size == 0:
        target.unlink(missing_ok=True)
        raise BuildError(
            f"Mihomo could not read back {target} ({behavior}, exit {verify.returncode}):\n"
            f"{(verify.stdout or '').strip()}"
        )


def _output_with_suffix(relative: Path, suffix: str) -> Path:
    return relative.with_name(f"{relative.stem}{suffix}.mrs")


def _file_report(
    source: str,
    rules: RuleBuckets,
    outputs: list[dict[str, object]],
) -> dict[str, object]:
    return {
        "source": source,
        "candidate_rules": rules.candidates,
        "kept_domain_rules": len(rules.domain),
        "kept_ipcidr_rules": len(rules.ipcidr),
        "dropped_rules": sum(rules.dropped.values()),
        "dropped": rules.dropped_json(),
        "outputs": outputs,
    }


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def build_skk(skk_root: Path, output_root: Path, mihomo: Path, work_dir: Path) -> dict[str, object]:
    categories = {"domainset": "domain", "non_ip": "auto", "ip": "auto"}
    for category in categories:
        directory = skk_root / category
        if not directory.is_dir():
            raise BuildError(f"missing SKK Clash directory: {directory}")

    reports: list[dict[str, object]] = []
    claimed_outputs: set[str] = set()
    mrs_files = 0
    for category, behavior in categories.items():
        category_root = skk_root / category
        sources = sorted(path for path in category_root.rglob("*.txt") if path.is_file())
        if not sources:
            raise BuildError(f"no .txt rules found in {category_root}")
        for source in sources:
            relative = source.relative_to(category_root)
            source_name = (Path(category) / relative).as_posix()
            rules = parse_rules(read_text_file(source), behavior)
            outputs: list[dict[str, object]] = []

            plans: list[tuple[str, list[str], Path]] = []
            if category in {"domainset", "non_ip"} and rules.domain:
                plans.append(("domain", rules.domain, relative.with_suffix(".mrs")))
            if category == "non_ip" and rules.ipcidr:
                plans.append(("ipcidr", rules.ipcidr, _output_with_suffix(relative, "_ipcidr")))
            if category == "ip" and rules.ipcidr:
                plans.append(("ipcidr", rules.ipcidr, relative.with_suffix(".mrs")))
            if category == "ip" and rules.domain:
                plans.append(("domain", rules.domain, _output_with_suffix(relative, "_domain")))

            for output_behavior, entries, output_relative in plans:
                report_path = (Path(category) / output_relative).as_posix()
                output_key = report_path.casefold()
                if output_key in claimed_outputs:
                    raise BuildError(f"duplicate SKK output path: {report_path}")
                claimed_outputs.add(output_key)
                run_mihomo(
                    mihomo,
                    output_behavior,
                    entries,
                    output_root / category / output_relative,
                    work_dir,
                )
                outputs.append(
                    {"behavior": output_behavior, "path": report_path, "input_rules": len(entries)}
                )
                mrs_files += 1

            reports.append(_file_report(source_name, rules, outputs))

    if mrs_files == 0:
        raise BuildError("SKK conversion produced no MRS files")

    summary = {
        "source_files": len(reports),
        "candidate_rules": sum(int(item["candidate_rules"]) for item in reports),
        "kept_domain_rules": sum(int(item["kept_domain_rules"]) for item in reports),
        "kept_ipcidr_rules": sum(int(item["kept_ipcidr_rules"]) for item in reports),
        "dropped_rules": sum(int(item["dropped_rules"]) for item in reports),
        "mrs_files": mrs_files,
    }
    report = {"schema_version": 1, "summary": summary, "files": reports}
    _write_json(output_root / "conversion-report.json", report)
    return report


def _safe_relative(value: str, label: str) -> PurePosixPath:
    value = value.replace("\\", "/").strip()
    path = PurePosixPath(value)
    if (
        not value
        or not path.parts
        or path.is_absolute()
        or any(ord(character) < 32 for character in value)
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(any(character in '<>:"|?*' for character in part) for part in path.parts)
    ):
        raise BuildError(f"unsafe {label}: {value!r}")
    for part in path.parts:
        if (
            part.casefold() == ".git"
            or part.endswith((" ", "."))
            or part.split(".", 1)[0].upper() in WINDOWS_RESERVED_NAMES
        ):
            raise BuildError(f"unsafe {label}: {value!r}")
    return path


def _custom_output_key(path: PurePosixPath) -> str:
    if path.parts[0].casefold() in {"readme.md", "conversion-report.json"}:
        raise BuildError(f"reserved JYRules output path: {path.as_posix()}")
    return path.as_posix().casefold()


def _default_output(source: str) -> str:
    parsed = urllib.parse.urlparse(source)
    source_path = parsed.path if parsed.scheme in {"http", "https"} else source.replace("\\", "/")
    name = PurePosixPath(source_path).name
    stem = PurePosixPath(name).stem
    if not stem:
        raise BuildError(f"cannot derive output name from source: {source}")
    return stem


def _manifest_output(entry: dict[str, object], source: str) -> object:
    if "output" in entry:
        return entry["output"]
    return _default_output(source)


def _single_output(value: str) -> PurePosixPath:
    path = _safe_relative(value, "custom output")
    return path if path.suffix == ".mrs" else path.with_suffix(".mrs")


def _auto_outputs(value: str) -> tuple[PurePosixPath, PurePosixPath]:
    base = _safe_relative(value, "custom output")
    if base.suffix == ".mrs":
        base = base.with_suffix("")
    parent = base.parent
    return (
        parent / f"{base.name}_domain.mrs",
        parent / f"{base.name}_ipcidr.mrs",
    )


def load_manifest(path: Path) -> list[dict[str, object]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BuildError(f"cannot read custom manifest {path}: {exc}") from exc
    entries = data.get("rules") if isinstance(data, dict) else data
    if not isinstance(entries, list):
        raise BuildError("custom manifest must be an array or an object containing a 'rules' array")
    for index, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            raise BuildError(f"custom manifest entry {index} must be an object")
    return entries


def _read_custom_source(source: str, repo_root: Path) -> str:
    parsed = urllib.parse.urlparse(source)
    if parsed.scheme == "https":
        return download_text(source)
    if parsed.scheme:
        raise BuildError(f"unsupported custom source scheme: {source}")

    relative = _safe_relative(source, "custom source path")
    candidate = (repo_root / Path(*relative.parts)).resolve()
    try:
        candidate.relative_to(repo_root)
    except ValueError as exc:
        raise BuildError(f"custom source escapes repository: {source}") from exc
    if not candidate.is_file():
        raise BuildError(f"custom source does not exist: {source}")
    return read_text_file(candidate)


def build_custom(
    manifest: Path,
    repo_root: Path,
    output_root: Path,
    mihomo: Path,
    work_dir: Path,
) -> dict[str, object]:
    reports: list[dict[str, object]] = []
    claimed_outputs = {"readme.md", "conversion-report.json"}
    source_cache: dict[str, str] = {}
    enabled_entries = 0
    mrs_files = 0

    for index, entry in enumerate(load_manifest(manifest), start=1):
        enabled = entry.get("enabled", True)
        if not isinstance(enabled, bool):
            raise BuildError(f"custom manifest entry {index}: enabled must be true or false")
        if not enabled:
            continue
        enabled_entries += 1

        source = entry.get("source")
        if not isinstance(source, str) or not source.strip():
            raise BuildError(f"custom manifest entry {index}: source must be a non-empty string")
        source = source.strip()
        behavior = entry.get("behavior", "auto")
        if not isinstance(behavior, str) or behavior.lower() not in SUPPORTED_BEHAVIORS:
            raise BuildError(
                f"custom manifest entry {index}: behavior must be auto, domain, or ipcidr"
            )
        behavior = behavior.lower()
        output_value = _manifest_output(entry, source)
        if not isinstance(output_value, str) or not output_value.strip():
            raise BuildError(f"custom manifest entry {index}: output must be a non-empty string")

        if source not in source_cache:
            source_cache[source] = _read_custom_source(source, repo_root)
        rules = parse_rules(source_cache[source], behavior)
        plans: list[tuple[str, list[str], PurePosixPath]] = []
        if behavior == "auto":
            domain_output, ipcidr_output = _auto_outputs(output_value)
            if rules.domain:
                plans.append(("domain", rules.domain, domain_output))
            if rules.ipcidr:
                plans.append(("ipcidr", rules.ipcidr, ipcidr_output))
        else:
            entries = rules.domain if behavior == "domain" else rules.ipcidr
            if entries:
                plans.append((behavior, entries, _single_output(output_value)))

        if not plans:
            raise BuildError(
                f"custom source has no convertible {behavior} rules: {source}; "
                f"dropped={dict(rules.dropped)}"
            )

        outputs: list[dict[str, object]] = []
        for output_behavior, output_entries, relative in plans:
            report_path = relative.as_posix()
            output_key = _custom_output_key(relative)
            if output_key in claimed_outputs:
                raise BuildError(f"duplicate or reserved JYRules output path: {report_path}")
            claimed_outputs.add(output_key)
            run_mihomo(
                mihomo,
                output_behavior,
                output_entries,
                output_root / Path(*relative.parts),
                work_dir,
            )
            outputs.append(
                {
                    "behavior": output_behavior,
                    "path": report_path,
                    "input_rules": len(output_entries),
                }
            )
            mrs_files += 1
        reports.append(_file_report(source, rules, outputs))

    summary = {
        "enabled_entries": enabled_entries,
        "candidate_rules": sum(int(item["candidate_rules"]) for item in reports),
        "kept_domain_rules": sum(int(item["kept_domain_rules"]) for item in reports),
        "kept_ipcidr_rules": sum(int(item["kept_ipcidr_rules"]) for item in reports),
        "dropped_rules": sum(int(item["dropped_rules"]) for item in reports),
        "mrs_files": mrs_files,
    }
    report = {"schema_version": 1, "summary": summary, "files": reports}
    output_root.mkdir(parents=True, exist_ok=True)
    (output_root / "README.md").write_text(
        "# JYRules\n\n"
        "This directory is generated from `custom-rules.json`. Do not edit generated\n"
        "MRS files directly.\n",
        encoding="utf-8",
        newline="\n",
    )
    _write_json(output_root / "conversion-report.json", report)
    return report


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Convert SKK Clash rules and user-defined sources to Mihomo MRS files."
    )
    parser.add_argument("--skk-root", required=True, type=Path)
    parser.add_argument("--skk-output", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--jy-output", required=True, type=Path)
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--mihomo", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    repo_root = args.repo_root.resolve()
    mihomo = args.mihomo.resolve()
    skk_output = args.skk_output.resolve()
    jy_output = args.jy_output.resolve()
    if not mihomo.is_file():
        raise BuildError(f"Mihomo binary does not exist: {mihomo}")
    outputs_overlap = (
        skk_output == jy_output
        or skk_output in jy_output.parents
        or jy_output in skk_output.parents
    )
    if outputs_overlap:
        raise BuildError("SKK and JYRules output directories must not overlap")
    if skk_output.exists() or jy_output.exists():
        raise BuildError("output directories must not already exist; use fresh staging paths")

    with tempfile.TemporaryDirectory(prefix="mihomo-rules-") as temporary:
        work_root = Path(temporary)
        skk_report = build_skk(
            args.skk_root.resolve(),
            skk_output,
            mihomo,
            work_root / "skk",
        )
        custom_report = build_custom(
            args.manifest.resolve(),
            repo_root,
            jy_output,
            mihomo,
            work_root / "custom",
        )
    print(
        "converted "
        f"{skk_report['summary']['mrs_files']} SKK MRS files and "
        f"{custom_report['summary']['mrs_files']} JYRules MRS files"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BuildError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
