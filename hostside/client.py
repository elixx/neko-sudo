"""HTTP client for the gate, written to fail closed.

Every failure mode — network error, timeout, non-JSON body, missing
fields, unexpected status — collapses into GateError. The runner treats
GateError as "deny" without exception.
"""

import json
import urllib.request


class GateError(Exception):
    pass


class UrllibTransport:
    """Default stdlib transport. One method per HTTP verb we need."""

    def __init__(self, timeout_s: float = 5.0):
        self.timeout_s = timeout_s

    def _request(self, url, method, payload, headers):
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        for key, value in headers.items():
            req.add_header(key, value)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=self.timeout_s) as response:
            return json.loads(response.read().decode("utf-8"))

    def post_json(self, path, payload, headers, timeout):
        return self._request(path, "POST", payload, headers)

    def get_json(self, path, headers, timeout):
        return self._request(path, "GET", None, headers)


def _require(response: dict, keys: set) -> dict:
    missing = keys - set(response)
    if missing:
        raise GateError(f"gate response missing fields: {sorted(missing)}")
    return response


class GateClient:
    def __init__(self, base_url: str, token: str, transport=None, timeout_s: float = 5.0):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.transport = transport or UrllibTransport(timeout_s)
        self.timeout_s = timeout_s

    def _headers(self):
        # Custom User-Agent: Cloudflare Bot Fight Mode bans the default
        # "Python-urllib/x" browser signature (error 1010) at the edge.
        return {
            "Authorization": f"Bearer {self.token}",
            "User-Agent": "neko-sudo/1.0",
        }

    def create(self, user: str, argv: list, cwd: str, ttl_s: int) -> dict:
        payload = {"user": user, "argv": argv, "cwd": cwd, "ttl_s": ttl_s}
        try:
            response = self.transport.post_json(
                f"{self.base_url}/v1/requests",
                payload,
                self._headers(),
                self.timeout_s,
            )
            return _require(response, {"id", "status", "digest", "expires_at"})
        except GateError:
            raise
        except Exception as exc:  # noqa: BLE001 - anything means deny
            raise GateError(f"create failed: {exc}") from exc

    def poll(self, request_id: str) -> dict:
        try:
            response = self.transport.get_json(
                f"{self.base_url}/v1/requests/{request_id}",
                self._headers(),
                self.timeout_s,
            )
            return _require(response, {"id", "status", "digest"})
        except GateError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise GateError(f"poll failed: {exc}") from exc
