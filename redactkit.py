#!/usr/bin/env python3
"""redactkit —— 本地 PII / 密钥脱敏工具。

敏感数据进，[REDACTED:*] 出。纯标准库，纯本地，不联网。
"""
import argparse
import json
import re
import sys
from collections import Counter

VERSION = "0.1.0"


# ---------------------------------------------------------------- 校验工具

def luhn_ok(digits: str) -> bool:
    """Luhn 校验：信用卡 / 银行卡号。"""
    if not digits.isdigit():
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def find_cards(text: str):
    """找出通过 Luhn 校验的 13-19 位卡号（含空格/连字符分隔写法）。"""
    out = []
    for m in re.finditer(r"(?<!\d)\d(?:[ -]?\d){12,18}(?!\d)", text):
        digits = re.sub(r"[ -]", "", m.group(0))
        if 13 <= len(digits) <= 19 and luhn_ok(digits):
            out.append((m.start(), m.end(), digits))
    return out


def find_ipv4(text: str):
    """找出合法的 IPv4 地址（每段 0-255）。"""
    out = []
    for m in re.finditer(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)", text):
        try:
            if all(0 <= int(p) <= 255 for p in m.group(0).split(".")):
                out.append((m.start(), m.end()))
        except ValueError:
            pass
    return out


# ------------------------------------------------------------ 内置检测器

def build_detectors(custom=(), only=None):
    """返回 [(name, compiled_pattern|None, finder|None), ...]。

    顺序即优先级：排在前面的检测器在重叠时胜出。
    """
    dets = [
        ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), None),
        ("github_token", re.compile(
            r"\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})\b"), None),
        ("email", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), None),
        ("phone_cn", re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)"), None),
        ("cn_id", re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)"), None),
        ("ipv4", None, find_ipv4),
        ("card", None, find_cards),
        ("phone", re.compile(
            r"(?<!\d)(?:\+\d{1,3}[-.\s])?\d{3,4}[-.\s]?\d{3,4}[-.\s]?\d{4}(?!\d)"), None),
    ]
    for name, rx in custom:
        dets.append((name, re.compile(rx), None))
    if only:
        keep = {t.strip() for t in only.split(",") if t.strip()}
        unknown = keep - {d[0] for d in dets}
        if unknown:
            raise ValueError("未知的检测器类型：%s（可用 --list-types 查看）"
                             % "、".join(sorted(unknown)))
        dets = [d for d in dets if d[0] in keep]
    return dets


def redact_text(text: str, detectors, keep_last4=False):
    """脱敏一段文本。返回 (脱敏后文本, Counter)。"""
    spans = []  # (start, end, name, raw)
    for name, pattern, finder in detectors:
        if pattern is not None:
            for m in pattern.finditer(text):
                spans.append((m.start(), m.end(), name, m.group(0)))
        else:
            for item in finder(text):
                s, e = item[0], item[1]
                raw = item[2] if len(item) > 2 else text[s:e]
                spans.append((s, e, name, raw))
    prio = {d[0]: i for i, d in enumerate(detectors)}
    # 起点相同：优先级高的先、跨度大的先
    spans.sort(key=lambda s: (s[0], prio.get(s[2], 99), -(s[1] - s[0])))
    taken = []
    chosen = []
    for s, e, name, raw in spans:
        if any(s < te and e > ts for ts, te in taken):
            continue
        taken.append((s, e))
        chosen.append((s, e, name, raw))
    chosen.sort()
    out = []
    last = 0
    counts = Counter()
    for s, e, name, raw in chosen:
        out.append(text[last:s])
        if keep_last4 and name == "card":
            digits = re.sub(r"\D", "", raw)
            out.append("[REDACTED:%s:****%s]" % (name, digits[-4:]))
        else:
            out.append("[REDACTED:%s]" % name)
        counts[name] += 1
        last = e
    out.append(text[last:])
    return "".join(out), counts


# --------------------------------------------------------------- JSON 模式

SENSITIVE_KEYS = re.compile(
    r"(?i)^(api[_-]?key|password|passwd|pwd|secret|client[_-]?secret|"
    r"access[_-]?token|private[_-]?key|token|auth[_-]?token|aws[_-]?secret\w*)$")


def redact_json(obj, detectors, keep_last4, counts):
    """递归脱敏 JSON：敏感键名的值整体脱敏，字符串值走文本检测器。"""
    if isinstance(obj, dict):
        new = {}
        for k, v in obj.items():
            if SENSITIVE_KEYS.match(str(k)):
                new[k] = "[REDACTED:key]"
                counts["secret_key"] += 1
            else:
                new[k] = redact_json(v, detectors, keep_last4, counts)
        return new
    if isinstance(obj, list):
        return [redact_json(v, detectors, keep_last4, counts) for v in obj]
    if isinstance(obj, str):
        red, c = redact_text(obj, detectors, keep_last4)
        counts.update(c)
        return red
    return obj


# ------------------------------------------------------------------- CLI

def parse_custom(specs):
    out = []
    for spec in specs:
        if ":" not in spec:
            raise ValueError("--custom 格式应为 name:regex，收到：%r" % spec)
        name, rx = spec.split(":", 1)
        name = name.strip()
        if not name:
            raise ValueError("--custom 的 name 不能为空：%r" % spec)
        try:
            re.compile(rx)
        except re.error as e:
            raise ValueError("--custom 正则无效 [%s]：%s" % (name, e))
        out.append((name, rx))
    return out


def read_input(args):
    if args.file and not args.stdin:
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                return f.read(), args.file
        except FileNotFoundError:
            sys.stderr.write("error: 文件不存在：%s\n" % args.file)
            sys.exit(1)
        except OSError as e:
            sys.stderr.write("error: 读取文件失败：%s\n" % e)
            sys.exit(1)
    data = sys.stdin.read()
    if not data:
        sys.stderr.write("error: 输入为空（stdin 无数据）。\n")
        sys.exit(1)
    return data, "<stdin>"


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="redactkit",
        description="本地 PII/密钥脱敏：敏感数据进，[REDACTED:*] 出。纯本地，不联网。")
    ap.add_argument("file", nargs="?", help="输入文件；省略则从 stdin 读取")
    ap.add_argument("--stdin", action="store_true", help="强制从 stdin 读取")
    ap.add_argument("-o", "--output", help="输出写到文件（默认 stdout）")
    ap.add_argument("--json", action="store_true",
                    help="按 JSON 解析：敏感键名的值整体脱敏，保留结构")
    ap.add_argument("--stats", action="store_true", help="输出脱敏统计（stderr）")
    ap.add_argument("--keep-last4", action="store_true",
                    help="卡号脱敏时保留后四位，如 [REDACTED:card:****1111]")
    ap.add_argument("--custom", action="append", default=[], metavar="name:regex",
                    help="自定义检测器，可重复使用")
    ap.add_argument("--types", metavar="t1,t2",
                    help="只启用这些检测器，逗号分隔（如 email,phone_cn）")
    ap.add_argument("--diff", action="store_true",
                    help="审计模式：逐行显示 原行 → 脱敏行（仅文本模式）")
    ap.add_argument("--list-types", action="store_true", help="列出所有检测器类型")
    ap.add_argument("--version", action="version", version="%(prog)s " + VERSION)
    args = ap.parse_args(argv)

    try:
        custom = parse_custom(args.custom)
        detectors = build_detectors(custom, args.types)
    except ValueError as e:
        sys.stderr.write("error: %s\n" % e)
        sys.exit(1)

    if args.list_types:
        for name, _, _ in detectors:
            print(name)
        return 0

    if args.diff and args.json:
        sys.stderr.write("error: --diff 暂不支持 JSON 模式。\n")
        sys.exit(1)

    text, src = read_input(args)
    counts = Counter()

    if args.json:
        try:
            obj = json.loads(text)
        except json.JSONDecodeError as e:
            sys.stderr.write("error: JSON 解析失败（%s）：%s\n" % (src, e))
            sys.exit(1)
        obj = redact_json(obj, detectors, args.keep_last4, counts)
        out = json.dumps(obj, ensure_ascii=False, indent=2) + "\n"
    else:
        out, counts = redact_text(text, detectors, args.keep_last4)

    if args.diff:
        for old_line, new_line in zip(text.splitlines(), out.splitlines()):
            if old_line != new_line:
                print("- " + old_line)
                print("+ " + new_line)
        diff_only = True
    else:
        diff_only = False

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out)
        except OSError as e:
            sys.stderr.write("error: 写入文件失败：%s\n" % e)
            sys.exit(1)
    else:
        if not diff_only:
            sys.stdout.write(out)

    if args.stats:
        total = sum(counts.values())
        sys.stderr.write("脱敏统计（共 %d 处）：\n" % total)
        for name, n in counts.most_common():
            sys.stderr.write("  %s: %d\n" % (name, n))
    return 0


if __name__ == "__main__":
    sys.exit(main())
