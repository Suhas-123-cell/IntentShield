"""A tool's input schema: measured, trimmed to its skeleton for the agent, stripped of patterns and checked with a bounded
validator, so a hostile schema cannot cost unbounded time or memory."""
from __future__ import annotations

import contextvars
import re
from collections.abc import Iterable
from typing import Any, Callable, Protocol

from jsonschema import Draft202012Validator, validators
from pydantic import BaseModel

from intentshield.mcp_upstream import MCPTool

# Dicts and lists nested deeper than this in an input schema are not a schema anyone wrote: the tool is left
# out. The libraries that read one (jsonschema, json, pydantic) recurse, and a 100-level schema of 3 KB
# raised RecursionError out of connect() for every server behind the proxy.
MAX_SCHEMA_DEPTH = 64


def _too_deep(value: Any, limit: int = MAX_SCHEMA_DEPTH) -> bool:
    """Whether dicts and lists nest more than ``limit`` levels deep. Iterative: it is the guard."""
    stack = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        children = node.values() if isinstance(node, dict) else node if isinstance(node, list) else ()
        if children and depth > limit:
            return True
        stack.extend((child, depth + 1) for child in children if isinstance(child, (dict, list)))
    return False


_NESTED_FIELDS = {"input_schema": "an input schema", "output_schema": "an output schema",
                  "annotations": "annotations", "meta": "metadata"}


def _too_deep_field(tool: MCPTool) -> str | None:
    """The first of the tool's structured fields (input and output schema, annotations, meta) that nests deeper
    than ``MAX_SCHEMA_DEPTH``, or None. Each is the upstream's to write, and each is read by something that
    recurses: the hash below, the size count, the validator, the scanners."""
    return next((name for name in _NESTED_FIELDS if _too_deep(getattr(tool, name))), None)


_SCHEMA_ANNOTATIONS = {
    "title", "description", "examples", "default",
    "deprecated", "readOnly", "writeOnly",
}
# JSON Schema keywords that carry validation structure (2020-12, plus draft-07's dependencies,
# additionalItems and definitions, and OpenAPI's nullable). Anything else an upstream server adds,
# x-* keys and unknown keywords included, is free text the agent would read unscanned. ``$schema``,
# ``$id`` and ``$comment`` name nothing the agent needs, so they are never forwarded.
_SCHEMA_KEYWORDS = frozenset({
    "type", "enum", "const", "properties", "patternProperties", "additionalProperties", "required",
    "items", "prefixItems", "additionalItems", "contains", "minContains", "maxContains", "minItems",
    "maxItems", "uniqueItems", "minLength", "maxLength", "pattern", "format", "minimum", "maximum",
    "exclusiveMinimum", "exclusiveMaximum", "multipleOf", "minProperties", "maxProperties",
    "dependentRequired", "dependentSchemas", "dependencies", "propertyNames", "allOf", "anyOf", "oneOf",
    "not", "if", "then", "else", "$ref", "$defs", "definitions", "$anchor",
    "$dynamicRef", "$dynamicAnchor", "unevaluatedItems", "unevaluatedProperties", "contentEncoding",
    "contentMediaType", "contentSchema", "nullable",
})
# Keywords whose value is a short token, never prose: a value with whitespace or past 200 characters
# is a carrier for text, and is not forwarded.
_TOKEN_KEYWORDS = frozenset({"$ref", "$anchor", "$dynamicRef", "$dynamicAnchor", "contentEncoding",
                             "contentMediaType"})
_TOKEN = re.compile(r"[\w$#./:~%+;=@!*,-]{1,200}")
_FORMATS = frozenset({
    "date-time", "date", "time", "duration", "email", "idn-email", "hostname", "idn-hostname", "ipv4", "ipv6",
    "uri", "uri-reference", "iri", "iri-reference", "uri-template", "uuid", "json-pointer",
    "relative-json-pointer", "regex", "int32", "int64", "float", "double", "byte", "binary", "password",
})
MAX_PATTERN = 512
_JSON_TYPES = frozenset({"object", "array", "string", "number", "integer", "boolean", "null"})
# A short identifier: two or three joined words at most (the longest of 383 parameter names in 159 recorded MSB
# tool schemas is 20 characters). A longer one (or one cut into many words) can carry a sentence,
# in a form an agent reads as one, so a tool the judge has not read shows no such parameter.
_PARAMETER_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,23}")
_MAX_NAME_SEPARATORS = 2


def _skeleton_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Types and parameter names only, for a tool whose description the judge has not read: an enum value, a
    ``const``, a default, a format, a ``$ref`` or a parameter name that is a sentence is text the judge was to read
    with the description, and the agent must not get it first. Names that look like identifiers stay, so the tool
    stays usable; a schema that leans on ``$ref`` loses that part."""
    result: dict[str, Any] = {}
    kind = schema.get("type")
    if isinstance(kind, str) and kind in _JSON_TYPES:
        result["type"] = kind
    elif isinstance(kind, list) and (kept := [k for k in kind if isinstance(k, str) and k in _JSON_TYPES]):
        result["type"] = kept
    properties = schema.get("properties")
    if isinstance(properties, dict):
        result["properties"] = {name: _skeleton_schema(child) if isinstance(child, dict) else {}
                                for name, child in properties.items()
                                if isinstance(name, str) and _PARAMETER_NAME.fullmatch(name)
                                and sum(name.count(c) for c in "_.-") <= _MAX_NAME_SEPARATORS}
        if isinstance(schema.get("required"), list):
            result["required"] = [n for n in schema["required"] if isinstance(n, str) and n in result["properties"]]
    if isinstance(schema.get("items"), dict):
        result["items"] = _skeleton_schema(schema["items"])
    for key in ("anyOf", "oneOf", "allOf"):
        if isinstance(schema.get(key), list):
            result[key] = [_skeleton_schema(child) for child in schema[key] if isinstance(child, dict)]
    return result


def _withheld_schema(schema: dict[str, Any], *, flagged: bool) -> dict[str, Any]:
    """What the agent sees of a tool's parameters while its description is withheld: nothing for a tool the judge,
    classifier or memory flagged, the skeleton for one not read yet."""
    return {"type": "object"} if flagged else (_skeleton_schema(_public_schema(schema)) or {"type": "object"})


def _exceeds_bytes(value: Any, limit: int) -> bool:
    """Whether ``value`` (JSON data, models allowed) is certainly over ``limit`` bytes once dumped: a lower bound
    from the strings' lengths, one per other node, stopping at the limit. It copies nothing."""
    total, stack = 0, [value]
    while stack:
        node = stack.pop()
        if isinstance(node, str):
            total += len(node)
        elif isinstance(node, dict):
            total += len(node)
            stack.extend(node.keys())
            stack.extend(node.values())
        elif isinstance(node, (list, tuple)):
            total += len(node)
            stack.extend(node)
        elif isinstance(node, BaseModel):
            stack.extend(node.__dict__.values())
        else:
            total += 1
        if total > limit:
            return True
    return False


def _public_schema(schema: dict[str, Any], annotations: bool = False) -> dict[str, Any]:
    """Validation structure only: an allowlist, so text in a keyword nobody scans never reaches
    the agent. ``annotations`` keeps the ones ``tool_text`` scanned (transparent mode shows them).
    Keywords that take a value of their own kind (``format``, ``pattern``, the token keywords) are
    forwarded only when the value looks like one."""
    result: dict[str, Any] = {}
    schema_maps = {"properties", "patternProperties", "$defs", "definitions", "dependentSchemas"}
    schema_lists = {"allOf", "anyOf", "oneOf", "prefixItems", "items"}
    for key, value in schema.items():
        if key in _SCHEMA_ANNOTATIONS:
            if annotations:
                result[key] = value
        elif key not in _SCHEMA_KEYWORDS:
            continue
        elif key == "format":
            if value in _FORMATS:
                result[key] = value
        elif key == "pattern":
            if isinstance(value, str) and len(value) <= MAX_PATTERN:
                result[key] = value
        elif key in _TOKEN_KEYWORDS:
            if isinstance(value, str) and _TOKEN.fullmatch(value):
                result[key] = value
        elif key in schema_maps and isinstance(value, dict):
            result[key] = {
                name: _public_schema(child, annotations) if isinstance(child, dict) else child
                for name, child in value.items()
            }
        elif key in schema_lists and isinstance(value, list):
            result[key] = [
                _public_schema(child, annotations) if isinstance(child, dict) else child for child in value
            ]
        elif isinstance(value, dict) and key not in {"const", "enum"}:
            result[key] = _public_schema(value, annotations)
        else:
            result[key] = value
    return result


# Keywords whose value maps names to schemas (the keys are names, not keywords), and the keywords whose value is
# data the validator compares with, not a schema.
_NAME_MAPS = frozenset({"properties", "$defs", "definitions", "dependentSchemas", "dependencies", "patternProperties"})
_DATA_KEYWORDS = frozenset({"enum", "const"})
_REF_KEYWORDS = frozenset({"$ref", "$dynamicRef"})


def _holds_pattern(value: Any) -> bool:
    """Whether a dict anywhere in ``value`` has a ``pattern`` or ``patternProperties`` key. Iterative."""
    stack = [value]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if "pattern" in node or "patternProperties" in node:
                return True
            stack.extend(child for child in node.values() if isinstance(child, (dict, list)))
        elif isinstance(node, list):
            stack.extend(child for child in node if isinstance(child, (dict, list)))
    return False


def _without_patterns(schema: dict[str, Any], *, strip_data: bool = False) -> dict[str, Any]:
    """A copy of ``schema`` for the validator without the regexes the upstream wrote: ``pattern`` and
    ``patternProperties``, at every depth of the document. Python's ``re`` backtracks without limit, so a pattern
    like ``^(a+)+$`` run on a 45-character argument hangs the worker for hours, and the argument is the agent's.
    The walk reads the whole document, not only the places a schema keyword puts a sub-schema: a ``$ref`` can
    point at any of it (``#/x-lib/p``). The upstream still checks its own patterns; the gateway checks structure.
    Which names count as additional is ``patternProperties``' to say, so ``additionalProperties`` and
    ``unevaluatedProperties`` go with it. ``enum`` and ``const`` are compared, not read as schemas, and are left
    whole unless one of them holds a ``pattern`` key and the document has a ``$ref`` anywhere: a ``$ref`` may name
    the place by any spelling (``#/x/%65num/0``, ``#/x%2Fenum%2F0``), and reading the spelling is how the first
    version missed it, so it is not read at all. Data with a ``pattern`` key in it is rare, and stripping it from
    data costs only that key. Iterative, and the result shares nothing mutable with ``schema``."""
    root: dict[str, Any] = {}
    stack: list[tuple[Any, Any, bool]] = [(schema, root, False)]  # source, its copy, keys are names
    has_ref = holds_pattern = False

    def copy(value: Any, names: bool = False) -> Any:
        container: dict[Any, Any] | list[Any] | None = {} if isinstance(value, dict) else [] if isinstance(value, list) else None
        if container is not None:
            stack.append((value, container, names))
        return value if container is None else container

    while stack:
        source, target, names = stack.pop()
        if isinstance(source, list):
            target.extend(copy(item) for item in source)
            continue
        for key, value in source.items():
            if not names:
                if (key == "pattern" and isinstance(value, str)) or (key == "patternProperties" and isinstance(value, dict)):
                    continue
                if key in _REF_KEYWORDS:
                    has_ref = True
                if key in _DATA_KEYWORDS and not strip_data:
                    holds_pattern = holds_pattern or _holds_pattern(value)
                    target[key] = value  # shared, never written to
                    continue
            target[key] = copy(value, not names and key in _NAME_MAPS)
        if not names and isinstance(source.get("patternProperties"), dict):
            target.pop("additionalProperties", None)
            target.pop("unevaluatedProperties", None)
    if has_ref and holds_pattern and not strip_data:
        return _without_patterns(schema, strip_data=True)
    return root


class SchemaTooCostly(ValueError):
    """Checking the arguments would take more reference resolutions than the arguments can need."""


# A ``$ref`` chain where every level refers twice to the next (2 KB of schema, 20 levels) makes a valid
# argument take over 8 s to check and 40 levels never finish, with no regex in it. Every ``$ref`` the validator
# resolves is counted: the allowance is a base plus a few per node of the argument, so a big argument with a
# ``$ref`` per item is fine and an expansion the argument does not call for is refused.
REF_BASE_ALLOWANCE, REF_PER_NODE = 10_000, 20
_ref_budget: contextvars.ContextVar[list[int] | None] = contextvars.ContextVar("intentshield_ref_budget", default=None)


def _counted(keyword: Callable[..., Any]) -> Callable[..., Any]:
    def run(validator: Any, value: Any, instance: Any, schema: Any) -> Any:
        budget = _ref_budget.get()
        if budget is not None:
            budget[0] -= 1
            if budget[0] < 0:
                raise SchemaTooCostly("the input schema refers to itself more often than the arguments call for")
        yield from keyword(validator, value, instance, schema)

    return run


_BoundedValidator = validators.extend(Draft202012Validator, {
    key: _counted(Draft202012Validator.VALIDATORS[key]) for key in _REF_KEYWORDS
})


def _nodes(value: Any) -> int:
    count, stack = 0, [value]
    while stack:
        node = stack.pop()
        count += 1
        if isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return count


def schema_errors(schema: dict[str, Any], instance: Any) -> list[Any]:
    """The validation errors of ``instance`` against ``schema`` (patterns removed), in bounded work.
    Raises ``SchemaTooCostly`` for a reference expansion or loop the instance does not call for."""
    validator = _BoundedValidator(_without_patterns(schema))
    return _bounded_errors(validator, instance)


class _SchemaValidator(Protocol):
    """What the proxy asks of a jsonschema validator (the package ships no type information)."""

    def iter_errors(self, instance: Any) -> Iterable[Any]: ...


def _bounded_errors(validator: _SchemaValidator, instance: Any) -> list[Any]:
    token = _ref_budget.set([REF_BASE_ALLOWANCE + REF_PER_NODE * _nodes(instance)])
    try:
        return list(validator.iter_errors(instance))
    except RecursionError:
        raise SchemaTooCostly("the input schema refers to itself without end") from None
    finally:
        _ref_budget.reset(token)
