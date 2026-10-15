"""Pure MTM protocol-3 records and mathematical advisory state.

WorkflowEngine remains the sole authority for reading/writing private state.
"""
from .model import (ResearchAttempt, ResearchDecision, ResearchNode, ResearchSnapshot,
                    ResearchState, project)
from .normalize import ResearchNormalization, normalize_research
from .protocol import (ProtocolRecordStamp, ProtocolResearchScope, normalize_protocol3_plans,
                       normalize_protocol3_generation_record, normalize_protocol3_branch_payload,
                       normalize_protocol3_branch_obstructions, normalize_protocol3_failure_summary,
                       normalize_protocol3_replan_decision, protocol3_screening_fields,
                       protocol_node_id, stamp_protocol3_record)
from .view import MAX_RESEARCH_BASE_VIEW_BYTES, MAX_RESEARCH_TASK_VIEW_BYTES, select_advice, task_view

__all__ = ["ProtocolRecordStamp", "ProtocolResearchScope", "ResearchAttempt", "ResearchDecision", "ResearchNode", "ResearchSnapshot", "ResearchState", "ResearchNormalization", "normalize_research", "project", "task_view", "select_advice", "normalize_protocol3_plans", "normalize_protocol3_generation_record", "normalize_protocol3_branch_payload", "normalize_protocol3_branch_obstructions", "normalize_protocol3_failure_summary", "normalize_protocol3_replan_decision", "protocol3_screening_fields", "protocol_node_id", "stamp_protocol3_record", "MAX_RESEARCH_BASE_VIEW_BYTES", "MAX_RESEARCH_TASK_VIEW_BYTES"]
