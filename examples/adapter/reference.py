"""Local stdio conversation adapter fixture. It has no provider credentials."""

import json
import re
import sys


def reply(request):
    if request == {"describe": True}:
        return {"version": 1, "capabilities": ["conversation_text"]}
    if type(request.get("version")) is not int or request["version"] != 1:
        return {"error": "unsupported_version"}

    if set(request) != {"version", "binding", "correlation_id", "text"}:
        return {"error": "invalid_envelope"}
    binding = request["binding"]
    if not isinstance(binding, dict):
        return {"error": "invalid_envelope"}
    required = {"tenant", "adapter", "room"}
    if not required <= binding.keys() or binding.keys() - required - {"thread"}:
        return {"error": "invalid_envelope"}
    identifiers = [binding[key] for key in required] + [request["correlation_id"]]
    if binding.get("thread") is not None:
        identifiers.append(binding["thread"])
    if any(
        not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9_.-]{1,128}", value)
        for value in identifiers
    ):
        return {"error": "invalid_envelope"}
    message = request["text"]
    if not isinstance(message, str) or not message.strip() or len(message.encode()) > 16384:
        return {"error": "invalid_envelope"}

    return request


def main():
    # Bound each request, including JSON escaping. End the local session on overflow.
    while line := sys.stdin.buffer.readline(128 * 1024 + 1):
        if len(line) > 128 * 1024 or not line.endswith(b"\n"):
            break
        try:
            request = json.loads(line)
            response = reply(request) if isinstance(request, dict) else {"error": "invalid_envelope"}
        except (UnicodeError, ValueError, RecursionError):
            response = {"error": "invalid_envelope"}
        print(json.dumps(response), flush=True)


if __name__ == "__main__":
    main()
