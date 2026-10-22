"""Strict OS-independent JSON decoding at trust boundaries (RFC 8259 profile)."""
import json


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
    try:
        return json.loads(text, object_pairs_hook=unique_object, parse_constant=invalid_constant)
    except RecursionError as exc:
        raise ValueError("Слишком большая вложенность JSON.") from exc
