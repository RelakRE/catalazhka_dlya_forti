"""Strict OS-independent JSON decoding at trust boundaries (RFC 8259 profile)."""
import json

MAX_DEPTH = 64


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Повторяющееся поле JSON: " + key)
        result[key] = value
    return result


def invalid_constant(value):
    raise ValueError("JSON не допускает " + value)


def loads(text):
    if isinstance(text, (bytes, bytearray)):
        text = text.decode("utf-8-sig")
    if not isinstance(text, str):
        raise ValueError("JSON должен быть текстом UTF-8.")
    # CPython's C decoder recursion limits differ between versions. Enforce our
    # own limit before decoding; bracket characters inside strings don't count.
    depth, quoted, escaped = 0, False, False
    for character in text:
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
        elif character == '"':
            quoted = True
        elif character in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise ValueError("Слишком большая вложенность JSON (максимум 64).")
        elif character in "]}":
            depth -= 1
    try:
        return json.loads(text, object_pairs_hook=unique_object, parse_constant=invalid_constant)
    except RecursionError as exc:
        raise ValueError("Слишком большая вложенность JSON.") from exc
