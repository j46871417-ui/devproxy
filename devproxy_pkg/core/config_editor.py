"""Token-aware JSONC edits. Unrelated tokens and comments remain unchanged."""
import json
import os
import shutil
import tempfile
from dataclasses import dataclass


@dataclass
class Token:
    kind: str
    start: int
    end: int
    text: str


def tokens(text):
    out, i = [], 0
    while i < len(text):
        start, char = i, text[i]
        if char.isspace() or (i == 0 and char == '\ufeff'):
            i += 1
        elif text.startswith('//', i):
            while i < len(text) and text[i] not in '\r\n':
                i += 1
        elif text.startswith('/*', i):
            end = text.find('*/', i + 2)
            if end < 0:
                raise ValueError('Unterminated JSONC comment.')
            i = end + 2
        elif char == '"':
            i += 1
            while i < len(text):
                if text[i] == '\\':
                    i += 2
                elif text[i] == '"':
                    i += 1
                    break
                else:
                    i += 1
            else:
                raise ValueError('Unterminated JSON string.')
            out.append(Token('string', start, i, text[start:i]))
        elif char in '{}[]:,':
            i += 1
            out.append(Token(char, start, i, char))
        else:
            while i < len(text) and not text[i].isspace() and text[i] not in '{}[]:,/':
                i += 1
            if i == start:
                raise ValueError('Invalid JSONC token.')
            out.append(Token('literal', start, i, text[start:i]))
    return out


def strip_json_comments(text):
    chars = ['\n' if c == '\n' else ' ' for c in text]
    for t in tokens(text):
        chars[t.start:t.end] = text[t.start:t.end]
    return ''.join(chars)


def _no_duplicates(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise ValueError('Duplicate JSON object key.')
        result[k] = v
    return result


def parse_jsonc(text):
    ts = tokens(text)
    cleaned = ' '.join(t.text for i, t in enumerate(ts)
                       if not (t.kind == ',' and i + 1 < len(ts) and ts[i + 1].kind in ('}', ']')))
    data = json.loads(cleaned, object_pairs_hook=_no_duplicates,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite JSON number.')))
    if not isinstance(data, dict):
        raise ValueError('Configuration root must be an object.')
    return data


def _properties(text):
    parse_jsonc(text)
    ts, props, i = tokens(text), [], 1
    while i < len(ts) - 1:
        key, start = ts[i], i + 2
        end, depth = start, 0
        while end < len(ts):
            kind = ts[end].kind
            if kind in ('{', '['):
                depth += 1
            elif kind in ('}', ']'):
                if depth == 0:
                    break
                depth -= 1
            if depth == 0 and kind not in ('{', '['):
                end += 1
                break
            end += 1
        comma = ts[end] if end < len(ts) and ts[end].kind == ',' else None
        props.append((json.loads(key.text), key, ts[start], ts[end - 1], comma))
        i = end + (1 if comma else 0)
    return ts, props


def _edit(text, edits):
    for start, end, replacement in sorted(edits, reverse=True):
        text = text[:start] + replacement + text[end:]
    parse_jsonc(text)
    return text


class ConfigEditor:
    @staticmethod
    def load_jsonc(path):
        raw = None
        try:
            with open(path, 'r', encoding='utf-8', newline='') as handle:
                raw = handle.read()
            return parse_jsonc(raw), raw
        except FileNotFoundError:
            return {}, ''
        except (OSError, UnicodeError, ValueError):
            return None, raw

    @staticmethod
    def update_json_fields_preserving(raw_text, updates):
        text = raw_text if raw_text else '{}'
        ts, props = _properties(text)
        found, edits = {p[0]: p for p in props}, []
        for key, value in updates.items():
            if key in found:
                _, _, start, end, _ = found[key]
                edits.append((start.start, end.end, json.dumps(value, ensure_ascii=False, allow_nan=False)))
        missing = {k: v for k, v in updates.items() if k not in found}
        if missing:
            newline = '\r\n' if '\r\n' in text else '\n'
            indent = '    '
            comma_prefix = ''
            if props:
                prefix = text[text.rfind('\n', 0, props[0][1].start) + 1:props[0][1].start]
                if prefix and not prefix.strip():
                    indent = prefix
                if props[-1][4] is None:
                    pos = props[-1][3].end
                    if pos == ts[-1].start:
                        comma_prefix = ','
                    else:
                        edits.append((pos, pos, ','))
            insertion = comma_prefix + newline + (',' + newline).join(
                indent + json.dumps(k) + ': ' + json.dumps(v, ensure_ascii=False, allow_nan=False)
                for k, v in missing.items()) + newline
            edits.append((ts[-1].start, ts[-1].start, insertion))
        return _edit(text, edits)

    @staticmethod
    def remove_json_fields_preserving(raw_text, keys):
        text = raw_text
        for key in keys:
            _, props = _properties(text)
            for idx, (name, kt, start, end, comma) in enumerate(props):
                if name != key:
                    continue
                edits = [(kt.start, end.end, '')]
                if comma:
                    edits.append((comma.start, comma.end, ''))
                elif idx and props[idx - 1][4]:
                    previous = props[idx - 1][4]
                    edits.append((previous.start, previous.end, ''))
                text = _edit(text, edits)
                break
        return text

    @staticmethod
    def atomic_write(path, content, backup=True):
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)
        if backup and os.path.exists(path) and not os.path.exists(path + '.bak'):
            backup_fd, backup_temp = tempfile.mkstemp(dir=directory, prefix='.devproxy-backup-')
            os.close(backup_fd)
            try:
                shutil.copy2(path, backup_temp)
                os.chmod(backup_temp, 0o600)
                # Windows _commit (os.fsync) requires a writable descriptor.
                with open(backup_temp, 'r+b') as handle:
                    os.fsync(handle.fileno())
                try:
                    os.link(backup_temp, path + '.bak')
                except FileExistsError:
                    pass
            finally:
                os.unlink(backup_temp)
        fd, temp = tempfile.mkstemp(dir=directory, prefix='.devproxy-')
        try:
            with os.fdopen(fd, 'wb') as handle:
                handle.write(content if isinstance(content, bytes) else content.encode('utf-8'))
                handle.flush()
                os.fsync(handle.fileno())
            if os.path.exists(path):
                os.chmod(temp, os.stat(path).st_mode & 0o777)
            os.replace(temp, path)
        finally:
            if os.path.exists(temp):
                os.unlink(temp)
