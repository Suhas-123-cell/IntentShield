"""Tool descriptions and tool outputs read with the rules, and the check for a tool that asks about the agent itself."""
from __future__ import annotations

import re
from typing import Any, Iterable, Iterator
from urllib.parse import unquote

from .normalize import _normalize, _scan, leaf_text, readable
from .rules import _DESCRIPTION_RULES, _I, _OUTPUT_RULES

# Schema keywords whose values are structure, not text a model reads as prose.
_STRUCTURAL = frozenset({"$ref", "$dynamicRef", "$schema", "$id", "$anchor", "$dynamicAnchor", "$vocabulary",
                         "type", "format", "pattern", "contentEncoding", "contentMediaType", "required",
                         "dependentRequired"})
_READ_BY_TOOL_TEXT = frozenset({"title", "description", "$comment", "examples", "default", "enum"})
_SCHEMA_MAPS = frozenset({"properties", "patternProperties", "$defs", "definitions", "dependentSchemas"})


def schema_text(schema: dict[str, Any] | None) -> str:
    """Agent-visible schema text ``tool_text`` does not read: ``const``, ``x-*`` and unknown
    keywords, and property names of four or more words ("ignore_previous_instructions_and_...").
    Shorter names stay out: ``private_key`` or ``change_url_to`` name a field, not an instruction.
    Kept apart from ``tool_text`` so ``scan_server`` joins only titles and descriptions."""
    parts: list[str] = []

    def visit(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in _SCHEMA_MAPS and isinstance(value, dict):
                    for name, child in value.items():
                        words = re.sub(r"([a-z])([A-Z])", r"\1 \2", str(name)).replace("_", " ").replace("-", " ")
                        if key == "properties" and len(words.split()) >= 4:
                            parts.append(words)
                        visit(child)
                elif key in _STRUCTURAL or key in _READ_BY_TOOL_TEXT:
                    continue
                elif isinstance(value, (dict, list)) and not (key == "const" or str(key).startswith("x-")):
                    visit(value)
                else:
                    parts.append(leaf_text(value))
        elif isinstance(node, list):
            for item in node:
                visit(item)

    visit(schema or {})
    return "\n".join(part for part in parts if part)


def scan_description(text: str, other_tools: Iterable[str] = ()) -> list[str]:
    """Poisoning rule names for one tool's text; ``shadowing`` if it names another tool."""
    findings = _scan(text, _DESCRIPTION_RULES)
    # Whole identifiers only ("get_x" is not named by "get_x_v1Arguments"), tokenized once rather
    # than one compiled pattern per foreign tool, which thrashes the regex cache past 512 tools.
    identifiers = set(re.findall(r"[a-z0-9_]+(?:[\-.][a-z0-9_]+)*", _normalize(text).lower()))
    for name in other_tools:
        # Only distinctive names: "search" in prose is not a reference to a tool.
        if len(name) >= 6 and re.search(r"[_\-.]|[a-z][A-Z]", name) and name.lower() in identifiers:
            findings.append("shadowing")
            break
    return findings


# What each description rule looks for, in a few words, for a person reading a scan.
RULE_MEANINGS = {
    "instruction_override": "tells the agent to ignore or replace its instructions",
    "hidden_directive": "a tag such as <IMPORTANT> that marks hidden instructions",
    "cross_tool_directive": "orders what to do before or after using a tool",
    "tool_call_directive": "orders the agent to call a particular tool first",
    "prerequisite_call": "says another tool must be called before this one",
    "threat_coercion": "warns of damage if the agent does not comply",
    "concealment": "tells the agent not to tell the user",
    "sensitive_target": "names a key, a credential or a secrets file",
    "argument_override": "tells the agent to change the arguments it sends",
    "forced_payload": "orders extra content into what the agent sends",
    "priority_claim": "claims its rules outrank the user's or the system's",
    "mandatory_policy": "presents an order as a mandatory policy",
    "cross_tool_data": "asks for the data of other tools",
    "external_send": "sends data to a fixed outside address",
    "hidden_text": "contains invisible Unicode text",
}


def explain_rules(text: str, rules: Iterable[str], width: int = 70) -> str:
    """One line for a person: each rule of ``rules`` that fired on ``text``, what it means and the first words it matched
    (cut to ``width`` characters). A rule that fires only on a server's tools read together has no single place in ``text``."""
    shown = readable(text)
    parts = []
    for name in rules:
        pattern = dict(_DESCRIPTION_RULES).get(name)
        meaning = RULE_MEANINGS.get(name.removeprefix("split_"))
        found = next(iter(pattern.finditer(shown)), None) if pattern is not None else None
        quote = " ".join(found.group(0).split()) if found else ""
        if len(quote) > width:
            quote = quote[:width - 3] + "..."
        parts.append(f"{name}" + (f" ({meaning})" if meaning else "") + (f": \"{quote}\"" if quote else ""))
    return "; ".join(parts)


def scan_server(texts: Iterable[str]) -> list[str]:
    """Rules that fire only when one server's tool texts are read together, in catalog
    order and with line breaks folded: one instruction split across tools (ShareLock)."""
    texts = list(texts)
    single = {finding for text in texts for finding in _scan(text, _DESCRIPTION_RULES)}
    joined = " ".join(" ".join(text.split()) for text in texts)
    return [f"split_{finding}" for finding in _scan(joined, _DESCRIPTION_RULES) if finding not in single]


_SELF_FIELD_NAME = re.compile(
    r"^(?:llm|lm)_?(?:model_?)?(?:name|id|version|type|provider)?$|"
    r"^(?:ai|agent|assistant|caller)_?model(?:_?(?:name|id|version))?$|"
    r"^(?:system_?(?:prompt|message|instructions?)|full_?conversation|conversation_?(?:history|context)|chat_?(?:history|log)|"
    r"previous_?messages|prior_?messages|transcript|initial_?prompt|agent_?instructions|calling_?model)$", _I)
_SELF_FIELD_TEXT = re.compile(
    r"\b(?:llm|model|ai|assistant|agent)\b[^.\n]{0,40}?\b(?:that|which|who)\s+(?:is\s+)?"
    r"(?:calls?|calling|invok\w+|uses?|using)\s+this\s+tool\b|"
    r"\byour\s+(?:own\s+)?(?:model(?:\s+name)?|system\s+prompt|instructions|conversation(?:\s+history)?|"
    r"chat\s+history|previous\s+messages)\b|"
    r"\b(?:system\s+prompt|instructions)\s+(?:you\s+(?:were|are|have\s+been)\s+(?:given|using|following)|given\s+to\s+you)\b|"
    r"\b(?:conversation|chat|discussion)\s+so\s+far\b|"
    r"\beverything\s+the\s+user\s+(?:has\s+)?(?:said|written|told\s+you)\b|"
    r"\b(?:what|which)\s+(?:model|llm)\s+(?:are\s+you|is\s+this)\b|"
    r"\b(?:the\s+)?(?:assistant|agent|ai)(?:'s|\u2019s)\s+(?:own\s+)?(?:system\s+prompt|instructions)\b|"
    r"\b(?:history|log|transcript)\s+of\s+(?:the|this|our|your)\s+(?:chat|conversation)\b", _I)
# A name read as words ("sys_prompt", "agentSystemPrompt", "history_of_chat"): who speaks, and what is asked of it.
_SELF_PROMPT_OWNER = frozenset({"system", "sys", "developer"})
_SELF_PROMPT_KIND = frozenset({"prompt", "prompts", "instruction", "instructions", "message", "messages", "msg"})
_SELF_CHAT = frozenset({"conversation", "chat", "dialogue", "dialog"})
_SELF_CHAT_KIND = frozenset({"history", "log", "logs", "transcript", "context", "summary"})
_SELF_CHAT_ELDER = frozenset({"previous", "prior", "earlier", "full", "entire", "whole", "complete"})
_SELF_NAME_FILLER = frozenset({"text", "content", "body", "string", "str", "value"})


def _self_name(name: Any) -> bool:
    # "systemPrompt", "system-prompt", "system.prompt" and "System Prompt" all ask the same.
    name = _normalize(str(name))  # full-width, zero-width and look-alike letters read as the plain name
    snake = re.sub(r"[\s.\-]+", "_", re.sub(r"([a-z])([A-Z])", r"\1_\2", name).strip())
    snake = re.sub(r"(?i)(?<![a-z])(sys|system)(prompt|msg|message)(?![a-z])", r"\1_\2", snake)  # "sysprompt", "systemprompt"
    if _SELF_FIELD_NAME.match(snake):
        return True
    parts = [w for w in snake.lower().split("_") if w]
    while len(parts) > 1 and parts[-1] in _SELF_NAME_FILLER:
        parts.pop()  # "system_prompt_text" asks what "system_prompt" asks
    words, last = set(parts), parts[-1] if parts else ""
    return bool(words & _SELF_PROMPT_OWNER and last in _SELF_PROMPT_KIND
                or "agent" in words and last in {"prompt", "instruction", "instructions"}
                or words & _SELF_CHAT and last in (_SELF_CHAT | _SELF_CHAT_KIND) and words & (_SELF_CHAT_KIND | _SELF_CHAT_ELDER)
                or words & {"previous", "prior", "earlier"} and last in {"messages", "conversation"}
                or "your" in words and last in {"instructions", "prompt"} and len(parts) == 2)


def _self_text(spec: Any) -> bool:
    return isinstance(spec, dict) and bool(_SELF_FIELD_TEXT.search(
        _normalize(" ".join(str(spec.get(k, "")) for k in ("title", "description")))))


_SCHEMA_CHILDREN = ("items", "additionalProperties", "unevaluatedProperties", "unevaluatedItems", "not", "if", "then",
                    "else", "contains", "propertyNames")
_SCHEMA_LISTS = ("allOf", "anyOf", "oneOf", "prefixItems", "items")  # "items" is a list in draft-07 tuples
_SELF_SCHEMA_MAPS = ("patternProperties", "dependentSchemas", "dependencies")  # $defs are reached by their $ref


def _asks_about_itself(spec: Any, root: dict[str, Any]) -> bool:
    """Whether ``spec`` or anything nested in it (properties, items, allOf/anyOf/oneOf, a local ``$ref``) is a
    self-disclosure parameter by name or description. Bounded: a hostile schema may be deep, wide or circular."""
    stack: list[Any] = [spec]
    visited = 0
    while stack and visited < 400:
        node = stack.pop()
        visited += 1
        if not isinstance(node, dict):  # no depth bound: the 400 nodes bound a deep schema as well
            continue
        if _self_text(node):
            return True
        ref = node.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/"):
            target: Any = root
            for part in unquote(ref[2:]).split("/")[:8]:
                target = target.get(part.replace("~1", "/").replace("~0", "~")) if isinstance(target, dict) else None
            stack.append(target)
        props = node.get("properties")
        if isinstance(props, dict):
            for i, (name, child) in enumerate(props.items()):
                if i >= 5000:  # a name is read whatever its place; only the children walked are bounded
                    break
                if _self_name(name):
                    return True
                if i < 200:
                    stack.append(child)
        for key in _SELF_SCHEMA_MAPS:
            mapping = node.get(key)
            if isinstance(mapping, dict):
                stack.extend(list(mapping.values())[:50])
        stack.extend(node.get(key) for key in _SCHEMA_CHILDREN)
        for key in _SCHEMA_LISTS:
            if isinstance(node.get(key), list):
                stack.extend(node[key][:50])
    return False


def self_disclosure_fields(schema: dict[str, Any]) -> set[str]:
    """Top-level parameters that ask the calling agent about itself: its model, system
    prompt or conversation, named or described so, or holding such a parameter in an object,
    array or ``$ref`` (the whole parameter is then the one named). No tool needs these to do
    its job; they are a leak channel."""
    properties = schema.get("properties") if isinstance(schema, dict) else None
    if not isinstance(properties, dict):
        return set()
    return {name for name, spec in properties.items() if _self_name(name) or _asks_about_itself(spec, schema)}


def _values_text(value: Any) -> str:
    """The values of a structured output without its keys, the fields of one object on one line, with
    ``|``, ``,`` and ``;`` read as spaces: an instruction split across fields or table cells reads as one.
    Iterative: an output nested a thousand levels deep must still be read, not raise."""
    out: list[str] = []
    stack: list[tuple[Iterator[Any], str]] = [(iter([value]), "")]  # the children left, the separator between them
    first = [True]
    while stack:
        children, separator = stack[-1]
        child = next(children, stack)  # the stack itself is no value: it marks the end
        if child is stack:
            stack.pop()
            first.pop()
            continue
        if not first[-1]:
            out.append(separator)
        first[-1] = False
        if isinstance(child, dict):
            stack.append((iter(child.values()), " "))
            first.append(True)
        elif isinstance(child, (list, tuple)):
            stack.append((iter(child), "\n"))
            first.append(True)
        elif isinstance(child, str):  # an id between two halves is no part of the sentence
            out.append(child)
    return "".join(out).translate(_AS_SPACE)


_AS_SPACE = str.maketrans("|,;", "   ")


def _joined_blocks(value: Any) -> list[str]:
    """For each list in ``value`` that holds two or more text blocks (``{"type": "text", "text": ...}`` or plain strings), the
    blocks joined with a space and with nothing. A client model reads adjacent blocks as one text, so a sentence may be split
    between them at a word or inside one. Each list costs two copies of its own text, so the total is linear."""
    out: list[str] = []
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, (list, tuple)):
            texts = [x["text"] if isinstance(x, dict) and isinstance(x.get("text"), str) else x for x in item]
            texts = [t for t in texts if isinstance(t, str)]
            if len(texts) > 1:
                out += [" ".join(texts), "".join(texts)]
            stack.extend(x for x in item if isinstance(x, (dict, list, tuple)))
    return out


def scan_output(value: Any, trusted: str = "") -> list[str]:
    text = leaf_text(value)
    found = _scan(text, _OUTPUT_RULES, trusted, hidden=True)
    if not isinstance(value, str) or text.translate(_AS_SPACE) != text:
        if (cells := _values_text(value)) != text:
            found += [name for name in _scan(cells, _OUTPUT_RULES, trusted) if name not in found]
    if not isinstance(value, str):
        for joined in _joined_blocks(value):
            found += [name for name in _scan(joined, _OUTPUT_RULES, trusted) if name not in found]
    return found


def scan_output_collapsed(value: Any, trusted: str = "") -> list[str]:
    """The output rules on the text with every line break read as a space, for an output
    ``scan_output`` passed. The rules stop at line ends to stay within one sentence, so one word per
    line, or a list after a colon ("send me the following:\n- your password"), hides an instruction
    from them. Weaker evidence: short UI or listing text ("Email\nPassword") reads as a sentence
    here too, so a hit asks before a value from the output is used, like a learned detector's flag,
    and never taints the session."""
    return [f"collapsed_{name}" for name in _scan(leaf_text(value), _OUTPUT_RULES, trusted, collapse=True)]
