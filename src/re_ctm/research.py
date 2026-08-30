from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol

from .errors import ReCTMError, invalid_argument


DEFAULT_THEOREM_SEARCH_URL = "https://leansearch.net/thm/search"
DEFAULT_PAPER_SEARCH_URL = "https://api.openalex.org/works"
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


class PaperResearchProvider(Protocol):
    def search_papers(
        self,
        *,
        query: str,
        author: str = "",
        title: str = "",
        keywords: str = "",
        num_results: int = 10,
    ) -> dict[str, Any]: ...

    def lookup_paper(self, *, identifier: str) -> dict[str, Any]: ...


@dataclass(frozen=True)
class HTTPResponse:
    status: int
    body: bytes
    content_type: str
    final_url: str = ""


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
        self.endpoint_host = parsed.hostname
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
                "User-Agent": "Re-CTM/0.2 theorem-search",
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
        if response.final_url:
            final = urllib.parse.urlsplit(response.final_url)
            if final.scheme != "https" or final.hostname != self.endpoint_host:
                raise ReCTMError(
                    "RESEARCH_REDIRECT_DENIED",
                    "The theorem-search response left the configured HTTPS trust domain.",
                    category="security",
                )
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


class PaperSearchClient:
    """Bounded bibliographic search over a fixed OpenAlex HTTPS endpoint."""

    def __init__(
        self,
        endpoint: str = DEFAULT_PAPER_SEARCH_URL,
        *,
        timeout_seconds: int = 30,
        max_response_bytes: int = 2 * 1024 * 1024,
        transport: Callable[[urllib.request.Request, int, int], HTTPResponse] | None = None,
    ) -> None:
        parsed = urllib.parse.urlsplit(endpoint)
        if parsed.scheme != "https" or parsed.hostname != "api.openalex.org" or parsed.username or parsed.password:
            raise ReCTMError(
                "INVALID_PAPER_SEARCH_ENDPOINT",
                "Paper search must use the fixed HTTPS api.openalex.org trust domain.",
                category="security",
            )
        self.endpoint = endpoint.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self.transport = transport or _default_transport

    def search_papers(
        self,
        *,
        query: str,
        author: str = "",
        title: str = "",
        keywords: str = "",
        num_results: int = 10,
    ) -> dict[str, Any]:
        if not 1 <= num_results <= 50:
            raise invalid_argument("num_results must be between 1 and 50")
        search_text = " ".join(
            item.strip() for item in (author, title, keywords, query) if item and item.strip()
        ).strip()
        if not search_text:
            raise invalid_argument("paper search requires query, author, title, or keywords")
        url = self.endpoint + "?" + urllib.parse.urlencode(
            {"search": search_text, "per-page": num_results}
        )
        raw = self._get_json(url)
        rows = raw.get("results") if isinstance(raw, Mapping) else None
        if not isinstance(rows, list):
            raise ReCTMError(
                "PAPER_SEARCH_PROTOCOL_ERROR",
                "OpenAlex paper search response did not contain a results array.",
                category="runtime",
            )
        results = [item for item in (_normalize_openalex_work(row) for row in rows[:num_results]) if item]
        return {
            "query": search_text,
            "count": len(results),
            "results": results,
            "endpoint": self.endpoint,
            "source_trust": "external_unverified",
            "usage_rule": "Bibliographic metadata is discovery evidence only; inspect source context before relying on mathematical claims.",
        }

    def lookup_paper(self, *, identifier: str) -> dict[str, Any]:
        value = identifier.strip()
        if not value:
            raise invalid_argument("paper identifier is required")
        if value.startswith("https://openalex.org/"):
            value = value.rsplit("/", 1)[-1]
        if value.upper().startswith("W") and value[1:].isdigit():
            url = self.endpoint + "/" + urllib.parse.quote(value.upper(), safe="")
        elif value.startswith("10."):
            doi = "https://doi.org/" + value
            url = self.endpoint + "/" + urllib.parse.quote(doi, safe="")
        else:
            raise invalid_argument("paper_lookup identifier must be an OpenAlex W-id or DOI")
        raw = self._get_json(url)
        result = _normalize_openalex_work(raw)
        if not result:
            raise ReCTMError("PAPER_LOOKUP_PROTOCOL_ERROR", "OpenAlex paper lookup returned no work.", category="runtime")
        return {
            "query": identifier,
            "count": 1,
            "results": [result],
            "endpoint": self.endpoint,
            "source_trust": "external_unverified",
            "usage_rule": "Bibliographic metadata is discovery evidence only; inspect source context before relying on mathematical claims.",
        }

    def _get_json(self, url: str) -> Any:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or parsed.hostname != "api.openalex.org":
            raise ReCTMError("PAPER_SEARCH_URL_DENIED", "Paper lookup left the fixed OpenAlex trust domain.", category="security")
        request = urllib.request.Request(
            url,
            method="GET",
            headers={"Accept": "application/json", "User-Agent": "Re-CTM/0.2 paper-search"},
        )
        try:
            response = self.transport(request, self.timeout_seconds, self.max_response_bytes)
        except ReCTMError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise ReCTMError(
                "PAPER_SEARCH_UNAVAILABLE",
                "The paper-search service could not be reached.",
                category="runtime",
                retryable=True,
                details={"exception_type": type(exc).__name__},
            ) from exc
        if response.final_url:
            final = urllib.parse.urlsplit(response.final_url)
            if final.scheme != "https" or final.hostname != "api.openalex.org":
                raise ReCTMError(
                    "PAPER_SEARCH_URL_DENIED",
                    "Paper retrieval redirect left the fixed OpenAlex trust domain.",
                    category="security",
                )
        if response.status != 200:
            raise ReCTMError(
                "PAPER_SEARCH_ERROR",
                "The paper-search service returned a non-success status.",
                category="runtime",
                retryable=response.status >= 500,
                details={"status": response.status},
            )
        if "json" not in response.content_type.lower():
            raise ReCTMError("PAPER_SEARCH_PROTOCOL_ERROR", "Paper search returned non-JSON content.", category="runtime")
        try:
            return json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ReCTMError("PAPER_SEARCH_PROTOCOL_ERROR", "Paper search returned invalid JSON.", category="runtime") from exc


class ResearchHub:
    def __init__(self, theorem: ResearchProvider, papers: PaperResearchProvider) -> None:
        self.theorem = theorem
        self.papers = papers

    def search_theorems(self, **kwargs: Any) -> dict[str, Any]:
        return self.theorem.search_theorems(**kwargs)

    def search_papers(self, **kwargs: Any) -> dict[str, Any]:
        return self.papers.search_papers(**kwargs)

    def lookup_paper(self, **kwargs: Any) -> dict[str, Any]:
        return self.papers.lookup_paper(**kwargs)


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
                final_url=str(response.geturl() or request.full_url),
            )
    except urllib.error.HTTPError as exc:
        return HTTPResponse(
            status=int(exc.code),
            body=exc.read(4096),
            content_type=str(exc.headers.get("Content-Type") or ""),
            final_url=str(exc.geturl() or request.full_url),
        )


def _bounded_text(value: Any, maximum: int) -> str:
    return str(value or "")[:maximum]


def _normalize_openalex_work(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    authorships = value.get("authorships")
    authors: list[str] = []
    if isinstance(authorships, list):
        for item in authorships[:50]:
            if isinstance(item, Mapping) and isinstance(item.get("author"), Mapping):
                name = _bounded_text(item["author"].get("display_name"), 500)
                if name:
                    authors.append(name)
    primary = value.get("primary_location") if isinstance(value.get("primary_location"), Mapping) else {}
    open_access = value.get("open_access") if isinstance(value.get("open_access"), Mapping) else {}
    doi = _bounded_text(value.get("doi"), 1000)
    if doi.startswith("https://doi.org/"):
        doi = doi.removeprefix("https://doi.org/")
    return {
        "title": _bounded_text(value.get("display_name") or value.get("title"), 2000),
        "paper_id": _bounded_text(value.get("id"), 1000).rsplit("/", 1)[-1],
        "doi": doi,
        "publication_year": value.get("publication_year"),
        "authors": authors,
        "source_uri": _bounded_text(value.get("id"), 2000),
        "landing_page_url": _bounded_text(primary.get("landing_page_url"), 2000),
        "open_access_url": _bounded_text(open_access.get("oa_url"), 2000),
    }
