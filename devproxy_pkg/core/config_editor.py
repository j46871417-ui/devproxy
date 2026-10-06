"""Token-based top-level JSONC edits with validation and atomic replacement."""
import json
import os
import re
import shutil
import tempfile


_TOKEN = re.compile(r'\s+|//[^\r\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|[{}\[\]:,]|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null')


def tokens(text):
    result = []
    pos = 1 if text.startswith("\ufeff") else 0
    while pos < len(text):
        match = _TOKEN.match(text, pos)
        if not match:
            raise ValueError("Invalid JSONC token")
        value = match.group()
        if not value.isspace() and not value.startswith(("//", "/*")):
            result.append((value, pos, match.end()))
        pos = match.end()
    return result


def strip_json_comments(text):
    output = list(text)
    pos = 1 if text.startswith("\ufeff") else 0
    if pos:
        output[0] = " "
    while pos < len(text):
        match = _TOKEN.match(text, pos)
        if not match:
            raise ValueError("Invalid JSONC token")
        if match.group().startswith(("//", "/*")):
            for i in range(pos, match.end()):
                if output[i] not in "\r\n":
                    output[i] = " "
        pos = match.end()
    return "".join(output)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def parse_jsonc(text):
    clean = list(strip_json_comments(text))
    ts = tokens(text)
    for index, (value, start, end) in enumerate(ts[:-1]):
        if value == "," and ts[index + 1][0] in ("}", "]"):
            clean[start:end] = " " * (end - start)
    data = json.loads("".join(clean), object_pairs_hook=_unique)
    if not isinstance(data, dict):
        raise ValueError("Settings must be an object")
    return data


def _fields(text):
    parse_jsonc(text)
    ts = tokens(text)
    result = {}
    i = 1
    while ts[i][0] != "}":
        key, key_start, _ = ts[i]
        name = json.loads(key)
        i += 2  # key and colon
        start = ts[i][1]
        if ts[i][0] in ("{", "["):
            depth = 0
            while True:
                value = ts[i][0]
                depth += value in ("{", "[")
                depth -= value in ("}", "]")
                end = ts[i][2]
                i += 1
                if not depth:
                    break
        else:
            end = ts[i][2]
            i += 1
        comma = ts[i] if ts[i][0] == "," else None
        result[name] = (key_start, start, end, comma)
        if comma:
            i += 1
    return result, ts[i][1]


def _apply(text, edits):
    for start, end, value in sorted(edits, reverse=True):
        text = text[:start] + value + text[end:]
    parse_jsonc(text)
    return text


class ConfigEditor:
    @staticmethod
    def load_jsonc(path):
        raw = None
        try:
            with open(path, "r", encoding="utf-8", newline="") as f:
                raw = f.read()
            return parse_jsonc(raw), raw
        except FileNotFoundError:
            return {}, ""
        except (OSError, ValueError, UnicodeError):
            return None, raw

    @staticmethod
    def update_json_fields_preserving(raw_text, updates):
        if not raw_text:
            return json.dumps(updates, indent=4, ensure_ascii=False)
        content = raw_text
        for key, value in updates.items():
            fields, closing = _fields(content)
            encoded = json.dumps(value, ensure_ascii=False)
            if key in fields:
                _, start, end, _ = fields[key]
                content = _apply(content, [(start, end, encoded)])
            else:
                edits = [(closing, closing, "\n    " + json.dumps(key) + ": " + encoded + "\n")]
                if fields:
                    _, _, end, comma = next(reversed(fields.values()))
                    if not comma:
                        edits.append((end, end, ","))
                content = _apply(content, edits)
        return content

    @staticmethod
    def remove_json_fields_preserving(raw_text, keys):
        content = raw_text
        for key in keys:
            fields, _ = _fields(content)
            if key not in fields:
                continue
            key_start, _, end, comma = fields[key]
            edits = [(key_start, end, "")]
            if comma:
                edits.append((comma[1], comma[2], ""))
            else:
                names = list(fields)
                index = names.index(key)
                if index:
                    previous = fields[names[index - 1]][3]
                    if previous:
                        edits.append((previous[1], previous[2], ""))
            content = _apply(content, edits)
        return content

    @staticmethod
    def atomic_write(path, content):
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)
        if os.path.exists(path):
            # Backup failure must abort the edit.
            shutil.copy2(path, path + ".bak")
        fd, temporary = tempfile.mkstemp(dir=directory, prefix="devproxy_")
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.remove(temporary)
