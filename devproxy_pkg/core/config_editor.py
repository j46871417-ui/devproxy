"""
ConfigEditor: Safe JSONC and config modifier.
- Preserves comments and structure where possible.
- Atomic writes with backups.
- Keeps track of changes made specifically by devproxy in a rollback ledger.
- Never replaces a malformed file with an empty dictionary.
"""

import os
import json
import re
import shutil
import tempfile
from typing import Any, Dict, Optional, Tuple


def strip_json_comments(text: str) -> str:
    """State-machine comment stripper preserving string literals and URLs."""
    out = []
    in_string = False
    escape = False
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if in_string:
            out.append(c)
            if escape:
                escape = False
            elif c == '\\':
                escape = True
            elif c == '"':
                in_string = False
            i += 1
            continue

        if c == '"':
            in_string = True
            out.append(c)
            i += 1
            continue

        if c == '/' and i + 1 < n:
            if text[i + 1] == '/':
                # Line comment
                while i < n and text[i] != '\n':
                    i += 1
                if i < n:
                    out.append(text[i])
                    i += 1
                continue
            elif text[i + 1] == '*':
                # Block comment
                i += 2
                while i + 1 < n and not (text[i] == '*' and text[i + 1] == '/'):
                    i += 1
                i += 2
                continue

        out.append(c)
        i += 1
    return "".join(out)


class ConfigEditor:
    @staticmethod
    def load_jsonc(path: str) -> Tuple[Optional[dict], Optional[str]]:
        """
        Safely reads JSONC file.
        Returns: (parsed_dict, raw_text).
        If file doesn't exist, returns ({}, "").
        If parse error, returns (None, raw_text).
        """
        if not os.path.exists(path):
            return {}, ""
        try:
            with open(path, "r", encoding="utf-8-sig") as f:
                raw = f.read()
            if not raw.strip():
                return {}, ""
            cleaned = strip_json_comments(raw)
            # Remove trailing commas
            cleaned = re.sub(r',\s*([\}\]])', r'\1', cleaned)
            data = json.loads(cleaned)
            return data, raw
        except Exception as e:
            return None, raw

    @staticmethod
    def update_json_fields_preserving(raw_text: str, updates: Dict[str, Any]) -> str:
        """
        Updates keys in JSON/JSONC text preserving other keys and comments.
        If key exists, replaces its value using regex.
        If key doesn't exist, inserts it before the final closing brace.
        """
        content = raw_text.strip()
        if not content:
            return json.dumps(updates, indent=4, ensure_ascii=False)

        for key, val in updates.items():
            val_json = json.dumps(val, ensure_ascii=False)
            pattern = re.compile(
                r'("' + re.escape(key) + r'"\s*:\s*)(?:"(?:\\.|[^"\\])*"|true|false|null|\d+(?:\.\d+)?|\[[^\]]*\]|\{[^\}]*\})'
            )
            if pattern.search(content):
                content = pattern.sub(r'\g<1>' + val_json.replace('\\', r'\\'), content, count=1)
            else:
                last_brace = content.rfind('}')
                if last_brace != -1:
                    before = content[:last_brace].rstrip()
                    needs_comma = bool(before and not before.endswith('{') and not before.endswith(','))
                    indent = "    "
                    insert = (",\n" if needs_comma else "\n") + f'{indent}"{key}": {val_json}\n'
                    content = before + insert + content[last_brace:]
                else:
                    content = json.dumps(updates, indent=4, ensure_ascii=False)
        return content

    @staticmethod
    def remove_json_fields_preserving(raw_text: str, keys: list) -> str:
        """Removes specified keys from JSON/JSONC text preserving other structure."""
        content = raw_text
        for key in keys:
            pattern = re.compile(
                r'([ \t]*)"' + re.escape(key) + r'"\s*:\s*(?:"(?:\\.|[^"\\])*"|true|false|null|\d+(?:\.\d+)?|\[[^\]]*\]|\{[^\}]*\})\s*,?'
            )
            content = pattern.sub('', content)

        # Cleanup dangling comma before closing brace
        content = re.sub(r',\s*(\})', r'\1', content)
        return content

    @staticmethod
    def atomic_write(path: str, content: str):
        """Writes content atomically to avoid corruption on crash."""
        dir_name = os.path.dirname(os.path.abspath(path))
        os.makedirs(dir_name, exist_ok=True)
        # Create backup if file exists
        if os.path.exists(path):
            backup_path = path + ".bak"
            try:
                shutil.copy2(path, backup_path)
            except Exception:
                pass

        fd, tmp_path = tempfile.mkstemp(dir=dir_name, prefix="devproxy_tmp_")
        try:
            with open(fd, "w", encoding="utf-8") as f:
                f.write(content)
            # Atomic replace
            os.replace(tmp_path, path)
        except Exception:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass
            raise
