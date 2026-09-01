from __future__ import annotations

import os
from dataclasses import dataclass

from .capabilities import CapabilityAuthority
from .config import Settings
from .debug import DebugEventBus, DebugObserver
from .latex import LatexGate
from .mcp import MCPDispatcher
from .native import (
    BubblewrapExecBackend,
    DisabledExecBackend,
    ExternalHelperExecBackend,
    NativeRuntime,
    NativeWorkspace,
)
from .oauth import OAuthService, OAuthStore
from .research import PaperSearchClient, ResearchHub, TheoremSearchClient
from .storage import StateStore
from .tools import ToolRuntime
from .toolchains import build_toolchain_exposure_plan
from .vault import PrivateVault
from .workflow import WorkflowEngine


@dataclass
class ReCTMApplication:
    settings: Settings
    debug: DebugEventBus
    state_store: StateStore
    oauth_store: OAuthStore
    oauth: OAuthService
    vault: PrivateVault
    workflow: WorkflowEngine
    native: NativeRuntime
    tools: ToolRuntime
    mcp: MCPDispatcher

    def close(self) -> None:
        self.native.close()
        self.state_store.close()
        self.oauth_store.close()


def build_application(
    settings: Settings,
    *,
    debug_observer: DebugObserver | None = None,
) -> ReCTMApplication:
    settings.validate()
    settings.ensure_directories()
    debug = DebugEventBus(
        settings.debug_root / "events.jsonl",
        settings.private_root,
        enabled=True,
        trace_payloads=settings.trace_payloads,
        observer=debug_observer,
    )
    state_store = StateStore(settings.private_root / "state.sqlite3")
    oauth_store = OAuthStore(settings.data_root / "oauth.sqlite3")
    vault = PrivateVault(settings.private_root)
    capability = CapabilityAuthority(
        settings.capability_secret,
        state_store,
        debug,
    )
    workflow = WorkflowEngine(
        state_store,
        vault,
        capability,
        debug,
        LatexGate(settings.latex_policy),
        ResearchHub(
            TheoremSearchClient(
                settings.theorem_search_url,
                timeout_seconds=settings.theorem_search_timeout_seconds,
            ),
            PaperSearchClient(timeout_seconds=settings.theorem_search_timeout_seconds),
        ),
    )
    workspace = NativeWorkspace(settings.workspace, private_root=settings.private_root)
    if settings.native_exec_backend == "external":
        assert settings.native_exec_helper is not None
        exec_backend = ExternalHelperExecBackend(settings.native_exec_helper)
        exec_backend.attest(
            workspace=settings.workspace,
            forbidden_paths=(settings.data_root, settings.private_root),
        )
    elif settings.native_exec_backend == "bubblewrap":
        exposure_plan = build_toolchain_exposure_plan(
            mode=settings.native_mode,
            workspace=settings.workspace,
            forbidden_paths=(settings.data_root, settings.private_root),
            explicit_roots=settings.native_exec_allow_roots,
            host_path=os.environ.get("PATH", ""),
        )
        exec_backend = BubblewrapExecBackend(
            exposure_plan=exposure_plan,
        )
        exec_backend.attest(
            workspace=settings.workspace,
            forbidden_paths=(settings.data_root, settings.private_root),
        )
        debug.emit(
            "native.toolchain_exposure_planned",
            "application",
            decision="allow",
            reason="validated_read_only_toolchain_mount_plan",
            details=exposure_plan.summary(include_paths=False),
        )
    else:
        exec_backend = DisabledExecBackend()
    native = NativeRuntime(
        workspace,
        settings.native_mode,
        debug,
        exec_backend=exec_backend,
    )
    oauth = OAuthService(
        server_url=settings.oauth_server_url,
        password=settings.oauth_password,
        token_secret=settings.token_secret,
        store=oauth_store,
        debug=debug,
    )
    tools = ToolRuntime(native, workflow, debug)
    mcp = MCPDispatcher(tools)
    return ReCTMApplication(
        settings=settings,
        debug=debug,
        state_store=state_store,
        oauth_store=oauth_store,
        oauth=oauth,
        vault=vault,
        workflow=workflow,
        native=native,
        tools=tools,
        mcp=mcp,
    )
