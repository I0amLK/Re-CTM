from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol

from .errors import ReCTMError, invalid_argument


DEFAULT_THEOREM_SEARCH_URL = "https://leansearch.net/thm/search"
DEFAULT_TASK = (
    "Given a math statement, retrieve useful references, such as theorems, "
    "lemmas, and definitions, that are useful for solving the given problem."
)


class ResearchProvider(Protocol):
    def search_theorems(
        self,
        *,
        query: str,
        num_results: int,
        search_intent: str,
    ) -> dict[str, Any]: ...


@dataclass(frozen=True)
class HTTPResponse:
    status: int
    body: bytes
    content_type: str


class TheoremSearchClient:
    """Bounded HTTPS client for the theorem-search service used by Rethlas."""

    def __init__(
        self,
        endpoint: str = DEFAULT_THEOREM_SEARCH_URL,
        *,
        timeout_seconds: int = 30,
        max_response_bytes: int = 2 * 1024 * 1024,
        transport: Callable[[urllib.request.Request, int, int], HTTPResponse] | None = None,
    ) -> None:
        parsed = urllib.parse.urlsplit(endpoint)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ReCTMError(
                "INVALID_RESEARCH_ENDPOINT",
                "The theorem-search endpoint must be an absolute HTTPS URL without user info.",
                category="security",
            )
        self.endpoint = endpoint
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self.transport = transport or _default_transport

    def search_theorems(
        self,
        *,
        query: str,
        num_results: int = 10,
        search_intent: str = "theorem",
    ) -> dict[str, Any]:
        normalized_query = query.strip()
        if not normalized_query:
            raise invalid_argument("query is required")
        if not 1 <= num_results <= 50:
            raise invalid_argument("num_results must be between 1 and 50")
        if search_intent not in {
            "theorem",
            "construction",
            "example",
            "counterexample",
            "background",
        }:
            raise invalid_argument("unsupported search_intent", search_intent=search_intent)
        payload = json.dumps(
            {
                "query": normalized_query,
                "task": DEFAULT_TASK,
                "num_results": num_results,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        request = urllib.request.Request(
            self.endpoint,
            data=payload,
            method="POST",
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "Re-CTM/0.1 theorem-search",
            },
        )
        try:
            response = self.transport(
                request,
                self.timeout_seconds,
                self.max_response_bytes,
            )
        except ReCTMError:
            raise
        except Exception as exc:  # noqa: BLE001 - external integration boundary
            raise ReCTMError(
                "RESEARCH_SERVICE_UNAVAILABLE",
                "The theorem-search service could not be reached.",
                category="runtime",
                retryable=True,
                details={"exception_type": type(exc).__name__},
            ) from exc
        if response.status != 200:
            raise ReCTMError(
                "RESEARCH_SERVICE_ERROR",
                "The theorem-search service returned a non-success status.",
                category="runtime",
                retryable=response.status >= 500,
                details={"status": response.status},
            )
        if "json" not in response.content_type.lower():
            raise ReCTMError(
                "RESEARCH_SERVICE_PROTOCOL_ERROR",
                "The theorem-search service returned a non-JSON content type.",
                category="runtime",
            )
        try:
            raw = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ReCTMError(
                "RESEARCH_SERVICE_PROTOCOL_ERROR",
                "The theorem-search service returned invalid JSON.",
                category="runtime",
            ) from exc
        if not isinstance(raw, list):
            raise ReCTMError(
                "RESEARCH_SERVICE_PROTOCOL_ERROR",
                "The theorem-search response must be a JSON array.",
                category="runtime",
            )
        results: list[dict[str, str]] = []
        for item in raw[:num_results]:
            if not isinstance(item, Mapping):
                continue
            result = {
                "title": _bounded_text(item.get("title"), 1000),
                "theorem": _bounded_text(item.get("theorem"), 20_000),
                "arxiv_id": _bounded_text(item.get("arxiv_id"), 200),
                "theorem_id": _bounded_text(item.get("theorem_id"), 500),
                "paper_id": _bounded_text(item.get("paper_id"), 500),
            }
            if result["title"] or result["theorem"]:
                results.append(result)
        return {
            "query": normalized_query,
            "search_intent": search_intent,
            "count": len(results),
            "results": results,
            "endpoint": self.endpoint,
            "source_trust": "external_unverified",
            "usage_rule": (
                "Read the paper context and proof, expand local definitions, and verify applicability "
                "before relying on any returned statement."
            ),
        }


def _default_transport(
    request: urllib.request.Request,
    timeout_seconds: int,
    max_response_bytes: int,
) -> HTTPResponse:
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310
            body = response.read(max_response_bytes + 1)
            if len(body) > max_response_bytes:
                raise ReCTMError(
                    "RESEARCH_RESPONSE_TOO_LARGE",
                    "The theorem-search response exceeded the configured limit.",
                    category="runtime",
                )
            return HTTPResponse(
                status=int(response.status),
                body=body,
                content_type=str(response.headers.get("Content-Type") or ""),
            )
    except urllib.error.HTTPError as exc:
        return HTTPResponse(
            status=int(exc.code),
            body=exc.read(4096),
            content_type=str(exc.headers.get("Content-Type") or ""),
        )


def _bounded_text(value: Any, maximum: int) -> str:
    return str(value or "")[:maximum]
