from __future__ import annotations

import base64
import fnmatch
import hashlib
import hmac
import json
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .debug import DebugEventBus, token_fingerprint
from .enums import DomainStatus, WorkflowRole, WorkflowState
from .errors import ReCTMError
from .storage import StateStore


CAPABILITY_TOKEN_PATTERN = r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$"
CAPABILITY_TOKEN_MIN_LENGTH = 80
CAPABILITY_TOKEN_MAX_LENGTH = 8192


@dataclass(frozen=True)
class CapabilityClaims:
    nonce: str
    run_id: str
    owner_id: str
    domain_id: str
    role: WorkflowRole
    epoch: int
    issued_state: WorkflowState
    permissions: tuple[str, ...]
    issued_at: int
    expires_at: int

    def to_payload(self) -> dict[str, Any]:
        return {
            "v": 1,
            "nonce": self.nonce,
            "run_id": self.run_id,
            "owner_id": self.owner_id,
            "domain_id": self.domain_id,
            "role": self.role.value,
            "epoch": self.epoch,
            "state": self.issued_state.value,
            "permissions": list(self.permissions),
            "iat": self.issued_at,
            "exp": self.expires_at,
        }


class CapabilityAuthority:
    """Signed workflow capabilities. Native mode is intentionally absent."""

    def __init__(
        self,
        secret: bytes,
        store: StateStore,
        debug: DebugEventBus,
        *,
        default_ttl_seconds: int = 3600,
    ) -> None:
        if len(secret) < 32:
            raise ReCTMError(
                "CAPABILITY_SECRET_REQUIRED",
                "Capability signing requires at least 32 secret bytes.",
                category="security",
            )
        self.secret = secret
        self.store = store
        self.debug = debug
        self.default_ttl_seconds = default_ttl_seconds

    def issue(
        self,
        *,
        run_id: str,
        domain_id: str,
        role: WorkflowRole,
        permissions: Iterable[str],
        trace_id: str,
        ttl_seconds: int | None = None,
    ) -> str:
        run = self.store.get_run(run_id)
        domain = self.store.get_domain(domain_id)
        if domain["run_id"] != run_id or domain["role"] != role.value:
            raise ReCTMError(
                "DOMAIN_ROLE_MISMATCH",
                "Domain does not belong to the requested run and role.",
                category="security",
            )
        if domain["status"] != DomainStatus.OPEN.value:
            raise ReCTMError(
                "DOMAIN_NOT_OPEN",
                "Capabilities can be issued only for open domains.",
                category="conflict",
            )
        state = WorkflowState(run["state"])
        expected_role = role_for_state(state)
        if expected_role != role:
            raise ReCTMError(
                "ROLE_STATE_MISMATCH",
                "The requested role is not active in the current workflow state.",
                category="permission",
                details={"state": state.value, "expected_role": expected_role.value if expected_role else None},
            )
        now = int(time.time())
        ttl = ttl_seconds or self.default_ttl_seconds
        claims = CapabilityClaims(
            nonce=secrets.token_urlsafe(18),
            run_id=run_id,
            owner_id=str(run["owner_id"]),
            domain_id=domain_id,
            role=role,
            epoch=int(run["epoch"]),
            issued_state=state,
            permissions=tuple(sorted(set(str(item) for item in permissions))),
            issued_at=now,
            expires_at=now + ttl,
        )
        token = self._encode(claims.to_payload())
        self.store.insert_capability(
            nonce=claims.nonce,
            run_id=run_id,
            domain_id=domain_id,
            role=role.value,
            epoch=claims.epoch,
            issued_state=state.value,
            permissions=claims.permissions,
            issued_at=claims.issued_at,
            expires_at=claims.expires_at,
        )
        self.debug.emit(
            "capability.issued",
            "capability_authority",
            trace_id=trace_id,
            run_id=run_id,
            actor_role=role.value,
            domain_id=domain_id,
            decision="allow",
            reason="role_state_preconditions_satisfied",
            details={
                "capability_fingerprint": token_fingerprint(token),
                "permissions": list(claims.permissions),
                "expires_at": claims.expires_at,
            },
        )
        return token

    def validate(
        self,
        token: str,
        *,
        owner_id: str,
        action: str,
        resource: str,
        trace_id: str,
        expected_run_id: str | None = None,
    ) -> CapabilityClaims:
        fingerprint = token_fingerprint(token)
        try:
            payload = self._decode(token)
            claims = _claims_from_payload(payload)
            if expected_run_id is not None and claims.run_id != expected_run_id:
                raise _denied(
                    "CAPABILITY_RUN_MISMATCH",
                    "Capability and run_id must come from the same server-issued task envelope.",
                    expected_run_id=expected_run_id,
                    capability_run_id=claims.run_id,
                )
            record = self.store.get_capability(claims.nonce)
            if record is None:
                raise _denied("CAPABILITY_UNKNOWN", "Capability is not registered.")
            if not _record_matches_claims(record, claims):
                raise _denied(
                    "CAPABILITY_REGISTRY_MISMATCH",
                    "Persisted capability facts do not match the signed capability claims.",
                )
            if record["revoked"]:
                raise _denied(
                    "CAPABILITY_REVOKED",
                    "Capability has been revoked.",
                    reason=record.get("revoke_reason"),
                )
            now = int(time.time())
            if claims.expires_at < now or int(record["expires_at"]) < now:
                raise _denied("CAPABILITY_EXPIRED", "Capability has expired.")
            run = self.store.get_run(claims.run_id)
            if (
                claims.owner_id != owner_id
                or str(run["owner_id"]) != owner_id
            ):
                raise _denied(
                    "CAPABILITY_OWNER_MISMATCH",
                    "Capability is not bound to the authenticated OAuth principal.",
                )
            if int(run["epoch"]) != claims.epoch:
                raise _denied(
                    "CAPABILITY_STALE",
                    "Capability belongs to an earlier run epoch.",
                )
            current_state = WorkflowState(run["state"])
            if current_state != claims.issued_state:
                raise _denied(
                    "CAPABILITY_STATE_MISMATCH",
                    "Capability is not valid in the current workflow state.",
                    issued_state=claims.issued_state.value,
                    current_state=current_state.value,
                )
            domain = self.store.get_domain(claims.domain_id)
            if domain["status"] != DomainStatus.OPEN.value:
                raise _denied("DOMAIN_SEALED", "Capability domain is no longer open.")
            if domain["run_id"] != claims.run_id or domain["role"] != claims.role.value:
                raise _denied("CAPABILITY_DOMAIN_MISMATCH", "Capability/domain facts do not match.")
            required_permission = f"{action}:{resource}"
            if not any(
                fnmatch.fnmatchcase(required_permission, pattern)
                for pattern in claims.permissions
            ):
                raise _denied(
                    "ROLE_ACCESS_DENIED",
                    "Capability does not authorize this resource operation.",
                    action=action,
                    resource=resource,
                )
            authorize_role_resource(
                role=claims.role,
                state=current_state,
                action=action,
                resource=resource,
                domain=domain,
            )
        except ReCTMError as exc:
            self.debug.emit(
                "capability.denied",
                "capability_authority",
                trace_id=trace_id,
                run_id=_safe_payload_value(locals().get("payload"), "run_id"),
                actor_role=_safe_payload_value(locals().get("payload"), "role"),
                domain_id=_safe_payload_value(locals().get("payload"), "domain_id"),
                decision="deny",
                reason=exc.code,
                details={
                    "capability_fingerprint": fingerprint,
                    "action": action,
                    "resource": resource,
                    "error": exc.to_payload(),
                },
            )
            raise
        self.debug.emit(
            "capability.allowed",
            "capability_authority",
            trace_id=trace_id,
            run_id=claims.run_id,
            actor_role=claims.role.value,
            domain_id=claims.domain_id,
            decision="allow",
            reason="signed_capability_role_acl_and_state_passed",
            details={
                "capability_fingerprint": fingerprint,
                "action": action,
                "resource": resource,
            },
        )
        return claims

    def revoke(self, token: str, reason: str, *, trace_id: str) -> None:
        payload = self._decode(token)
        claims = _claims_from_payload(payload)
        self.store.revoke_capability(claims.nonce, reason)
        self.debug.emit(
            "capability.revoked",
            "capability_authority",
            trace_id=trace_id,
            run_id=claims.run_id,
            actor_role=claims.role.value,
            domain_id=claims.domain_id,
            decision="allow",
            reason=reason,
            details={"capability_fingerprint": token_fingerprint(token)},
        )

    def _encode(self, payload: Mapping[str, Any]) -> str:
        body = _b64url(json.dumps(dict(payload), sort_keys=True, separators=(",", ":")).encode("utf-8"))
        signature = _b64url(hmac.new(self.secret, body.encode("ascii"), hashlib.sha256).digest())
        return body + "." + signature

    def _decode(self, token: str) -> dict[str, Any]:
        if (
            not isinstance(token, str)
            or len(token) < CAPABILITY_TOKEN_MIN_LENGTH
            or len(token) > CAPABILITY_TOKEN_MAX_LENGTH
            or re.fullmatch(CAPABILITY_TOKEN_PATTERN, token) is None
        ):
            raise _denied(
                "CAPABILITY_INVALID",
                "Capability is malformed or has an invalid signature.",
            )
        try:
            body, signature = token.split(".", 1)
            expected = _b64url(
                hmac.new(self.secret, body.encode("ascii"), hashlib.sha256).digest()
            )
            if not hmac.compare_digest(signature, expected):
                raise ValueError("signature mismatch")
            payload = json.loads(_unb64url(body))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _denied("CAPABILITY_INVALID", "Capability is malformed or has an invalid signature.") from exc
        if not isinstance(payload, dict) or payload.get("v") != 1:
            raise _denied("CAPABILITY_INVALID", "Unsupported capability payload.")
        return payload


def role_for_state(state: WorkflowState) -> WorkflowRole | None:
    return {
        WorkflowState.ASSESS: WorkflowRole.GENERATOR,
        WorkflowState.EXPLORE: WorkflowRole.GENERATOR,
        WorkflowState.PROPOSE_PLANS: WorkflowRole.GENERATOR,
        WorkflowState.DIRECT_PROVING: WorkflowRole.GENERATOR,
        WorkflowState.IDENTIFY_FAILURES: WorkflowRole.GENERATOR,
        WorkflowState.REPLAN: WorkflowRole.GENERATOR,
        WorkflowState.BRANCH_RUN: WorkflowRole.BRANCH,
        WorkflowState.BRANCH_JOIN: WorkflowRole.JOIN,
        WorkflowState.ASSEMBLE: WorkflowRole.ASSEMBLER,
        WorkflowState.VERIFY: WorkflowRole.VERIFIER,
        WorkflowState.REPAIR: WorkflowRole.REPAIR,
        WorkflowState.FINALIZE: WorkflowRole.FINALIZER,
    }.get(state)


def default_permissions(role: WorkflowRole) -> tuple[str, ...]:
    permissions: dict[WorkflowRole, tuple[str, ...]] = {
        WorkflowRole.GENERATOR: (
            "read:problem",
            "read:references",
            "read:project:verified_dependencies",
            "read:steering",
            "read:memory:generation:*",
            "write:memory:generation:*",
            "search:memory:generation:*",
            "retrieve:external:theorems",
            "retrieve:external:research",
            "commit:workflow",
        ),
        WorkflowRole.BRANCH: (
            "read:problem",
            "read:references",
            "read:project:verified_dependencies",
            "read:snapshot",
            "read:branch:self",
            "write:branch:self",
            "read:memory:branch:*",
            "write:memory:branch:*",
            "search:memory:branch:*",
            "retrieve:external:theorems",
            "retrieve:external:research",
            "commit:workflow",
        ),
        WorkflowRole.JOIN: (
            "read:problem",
            "read:snapshot",
            "read:branch:sealed:*",
            "write:join_result",
            "write:memory:generation:*",
            "commit:workflow",
        ),
        WorkflowRole.ASSEMBLER: (
            "read:problem",
            "read:references",
            "read:project:verified_dependencies",
            "read:memory:generation:*",
            "read:join_result",
            "write:proof",
            "write:proof_manifest",
            "commit:workflow",
        ),
        WorkflowRole.VERIFIER: (
            "read:problem",
            "read:proof",
            "read:proof_manifest",
            "read:project:verified_dependencies",
            "read:references:approved",
            "read:references:candidates",
            "read:memory:verifier:*",
            "write:memory:verifier:*",
            "write:verification_report",
            "write:reference_audit",
            "retrieve:external:theorems",
            "retrieve:external:research",
            "commit:workflow",
        ),
        WorkflowRole.REPAIR: (
            "read:problem",
            "read:proof",
            "read:proof_manifest",
            "read:project:verified_dependencies",
            "read:verification_report",
            "read:memory:generation:*",
            "write:memory:generation:*",
            "write:proof",
            "write:proof_manifest",
            "retrieve:external:theorems",
            "retrieve:external:research",
            "commit:workflow",
        ),
        WorkflowRole.FINALIZER: ("commit:workflow",),
    }
    return permissions[role]


def authorize_role_resource(
    *,
    role: WorkflowRole,
    state: WorkflowState,
    action: str,
    resource: str,
    domain: Mapping[str, Any],
) -> None:
    expected = role_for_state(state)
    if expected != role:
        raise _denied(
            "ROLE_STATE_MISMATCH",
            "Role is not active in the current workflow state.",
            role=role.value,
            state=state.value,
        )
    if role == WorkflowRole.VERIFIER and (
        resource.startswith("memory:generation:")
        or resource.startswith("branch:")
        or resource in {"steering", "join_result", "snapshot"}
    ):
        raise _denied(
            "VERIFIER_DATA_FIREWALL",
            "Verifier cannot access generation-private resources.",
            resource=resource,
        )
    if role == WorkflowRole.BRANCH and resource.startswith("branch:"):
        branch_id = str(domain.get("metadata", {}).get("branch_id") or "")
        if resource not in {"branch:self", f"branch:{branch_id}"}:
            raise _denied(
                "CROSS_BRANCH_ACCESS_DENIED",
                "Branch domains cannot access another branch.",
                resource=resource,
                branch_id=branch_id,
            )
    if role != WorkflowRole.JOIN and resource.startswith("branch:sealed:"):
        raise _denied(
            "JOIN_ONLY_RESOURCE",
            "Sealed branch sets are visible only in the join domain.",
        )
    if role == WorkflowRole.FINALIZER and action != "commit":
        raise _denied(
            "FINALIZER_MECHANICAL_ONLY",
            "Finalizer does not expose model-controlled reads or writes.",
        )


def _claims_from_payload(payload: Mapping[str, Any]) -> CapabilityClaims:
    try:
        required_keys = {
            "v",
            "nonce",
            "run_id",
            "owner_id",
            "domain_id",
            "role",
            "epoch",
            "state",
            "permissions",
            "iat",
            "exp",
        }
        if set(payload) != required_keys:
            raise ValueError("claim keys")
        for key in ("nonce", "run_id", "owner_id", "domain_id", "role", "state"):
            if not isinstance(payload[key], str) or not payload[key]:
                raise ValueError(key)
        for key in ("epoch", "iat", "exp"):
            if not isinstance(payload[key], int) or isinstance(payload[key], bool):
                raise ValueError(key)
        permissions = payload["permissions"]
        if not isinstance(permissions, list) or not all(isinstance(item, str) for item in permissions):
            raise ValueError("permissions")
        if not permissions or any(not item for item in permissions):
            raise ValueError("permissions")
        if int(payload["epoch"]) < 0 or int(payload["iat"]) < 0 or int(payload["exp"]) <= int(payload["iat"]):
            raise ValueError("time or epoch")
        return CapabilityClaims(
            nonce=payload["nonce"],
            run_id=payload["run_id"],
            owner_id=payload["owner_id"],
            domain_id=payload["domain_id"],
            role=WorkflowRole(payload["role"]),
            epoch=payload["epoch"],
            issued_state=WorkflowState(payload["state"]),
            permissions=tuple(permissions),
            issued_at=payload["iat"],
            expires_at=payload["exp"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise _denied("CAPABILITY_INVALID", "Capability payload is incomplete.") from exc


def _denied(code: str, message: str, **details: Any) -> ReCTMError:
    return ReCTMError(code, message, category="permission", details=details)


def _record_matches_claims(record: Mapping[str, Any], claims: CapabilityClaims) -> bool:
    permissions = record.get("permissions")
    epoch = record.get("epoch")
    issued_at = record.get("issued_at")
    expires_at = record.get("expires_at")
    return (
        str(record.get("run_id") or "") == claims.run_id
        and str(record.get("domain_id") or "") == claims.domain_id
        and str(record.get("role") or "") == claims.role.value
        and isinstance(epoch, int)
        and not isinstance(epoch, bool)
        and epoch == claims.epoch
        and str(record.get("issued_state") or "") == claims.issued_state.value
        and isinstance(permissions, list)
        and tuple(permissions) == claims.permissions
        and isinstance(issued_at, int)
        and not isinstance(issued_at, bool)
        and issued_at == claims.issued_at
        and isinstance(expires_at, int)
        and not isinstance(expires_at, bool)
        and expires_at == claims.expires_at
    )


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64url(value: str) -> str:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding).decode("utf-8")


def _safe_payload_value(payload: Any, key: str) -> str | None:
    if isinstance(payload, Mapping):
        value = payload.get(key)
        return str(value) if value is not None else None
    return None
