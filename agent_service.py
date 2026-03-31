from __future__ import annotations

import json
import logging
import os
import re
import uuid
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

import psycopg2
import psycopg2.extras
import requests

from agent_prompts import FITBASEAI_SYSTEM_PROMPT, MAX_AGENT_TURNS, build_runtime_context_message
from agent_retrieval import extract_uploaded_text, ingest_document, search_retrieval_context, sync_free_research_sources
from agent_tools import (
    AGENT_TOOL_SPECS,
    BATCH_ACTION_LIMIT,
    execute_pending_action,
    execute_tool_call,
    maybe_prepare_batched_schedule_actions,
    maybe_prepare_direct_lookup,
    maybe_prepare_direct_schedule_action,
)
from helpers import (
    calculate_target_heart_rate,
    compute_injury_exclusions,
    get_connection,
    get_guidelines,
    get_user_level,
    parse_injury_payload,
)

logger = logging.getLogger(__name__)

DEFAULT_OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"
DEFAULT_OPENAI_RESPONSES_URL = "https://api.openai.com/v1/responses"
DEFAULT_AGENT_MODEL = "gpt-5-mini"
DEFAULT_MONTHLY_BUDGET_USD = Decimal("5.00")
DEFAULT_INTERNAL_STOP_USD = Decimal("4.25")
DEFAULT_MAX_OUTPUT_TOKENS = 500
DEFAULT_OPENAI_TIMEOUT_SECONDS = 60
DEFAULT_PLANNER_OUTPUT_TOKENS = 350

MULTI_REQUEST_START_PATTERN = re.compile(
    r"(?:^|(?:[,;]|\n+)\s*|\s+(?:and then|then|also|and|&)\s+)"
    r"(?:(?:please|can you|could you|would you)\s+)?"
    r"(?:swap|cancel|reschedule|schedule|book|assign|move|delete|remove|complete|mark|"
    r"what(?:'s| is)?|show|tell me|give me|how many|how often|who do i have|what do i have|do i have|am i|did i)\b",
    flags=re.IGNORECASE,
)

MULTI_REQUEST_PLANNER_INSTRUCTIONS = f"""
You split one FitBaseAI user message into standalone sub-requests.

Rules:
- Return JSON only. No markdown and no explanation.
- Preserve the user's original order.
- Rewrite each item so it stands alone with the explicit client, date, time, or exercise context needed from the original message.
- Do not invent missing details.
- If one sentence asks to schedule or book a session and also assign a workout to that same session, keep that as one combined request.
- If there are more than {BATCH_ACTION_LIMIT} clear requests, set "too_many" to true and return only the clearest first {BATCH_ACTION_LIMIT}.
- If there is really only one request, return an empty requests array.

Return exactly this JSON shape:
{{
  "too_many": false,
  "requests": [
    {{"text": "first standalone request"}},
    {{"text": "second standalone request"}}
  ]
}}
""".strip()

MODEL_PRICING_USD_PER_MILLION: dict[str, dict[str, Decimal]] = {
    "gpt-5-mini": {"input": Decimal("0.25"), "output": Decimal("2.00")},
    "gpt-5.4-mini": {"input": Decimal("0.75"), "output": Decimal("4.50")},
}

AGENT_USER_PROFILE_COLUMNS = """
id,
role,
username,
name,
last_name,
email,
trainer_id,
subscription_type,
status,
trial_end_date,
created_at,
last_login_at,
subscription_cancel_at,
sessions_remaining,
sessions_booked,
workouts_completed,
last_workout_completed,
exercise_history,
fitness_goals,
workout_duration,
age,
weight,
height_feet,
height_inches,
gender,
commitment,
injury,
injury_details,
cardio_restriction,
additional_notes,
gym_id,
gym_catalog_preference
""".strip()


def _get_openai_api_url() -> str:
    return os.getenv("OPENAI_API_URL", DEFAULT_OPENAI_API_URL)


def _get_openai_responses_url() -> str:
    return os.getenv("OPENAI_RESPONSES_URL", DEFAULT_OPENAI_RESPONSES_URL)


def _get_openai_api_key() -> str | None:
    return os.getenv("OPENAI_API_KEY")


def _get_agent_model() -> str:
    return os.getenv("AGENT_MODEL", DEFAULT_AGENT_MODEL)


def _get_monthly_budget_usd() -> Decimal:
    return Decimal(os.getenv("AGENT_MONTHLY_BUDGET_USD", str(DEFAULT_MONTHLY_BUDGET_USD)))


def _get_internal_stop_usd() -> Decimal:
    return Decimal(os.getenv("AGENT_INTERNAL_STOP_USD", str(DEFAULT_INTERNAL_STOP_USD)))


def _get_max_output_tokens() -> int:
    return int(os.getenv("AGENT_MAX_OUTPUT_TOKENS", str(DEFAULT_MAX_OUTPUT_TOKENS)))


def _get_openai_timeout_seconds() -> int:
    return int(os.getenv("OPENAI_TIMEOUT_SECONDS", str(DEFAULT_OPENAI_TIMEOUT_SECONDS)))


def _month_start_utc(today: date | None = None) -> datetime:
    today = today or datetime.now(timezone.utc).date()
    return datetime(today.year, today.month, 1, tzinfo=timezone.utc)


def _next_month_start_utc(today: date | None = None) -> datetime:
    today = today or datetime.now(timezone.utc).date()
    if today.month == 12:
        return datetime(today.year + 1, 1, 1, tzinfo=timezone.utc)
    return datetime(today.year, today.month + 1, 1, tzinfo=timezone.utc)


def _safe_json(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, list):
        return [_safe_json(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _safe_json(val) for key, val in value.items()}
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Decimal):
        return float(value)
    if hasattr(value, "isoformat"):
        try:
            return value.isoformat()
        except Exception:
            return str(value)
    return str(value)


def _safe_json_dump(value: Any) -> str:
    return json.dumps(value, default=_safe_json)


def _normalize_message_content(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts: list[str] = []
        for item in value:
            if isinstance(item, dict):
                if item.get("type") == "text":
                    parts.append(str(item.get("text") or ""))
                elif item.get("text"):
                    parts.append(str(item.get("text")))
            else:
                parts.append(str(item))
        return "\n".join(part for part in parts if part).strip()
    return str(value)


def _estimate_tokens_from_messages(messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None) -> int:
    serialized_messages = _safe_json_dump(messages)
    serialized_tools = _safe_json_dump(tools or [])
    rough_chars = len(serialized_messages) + len(serialized_tools)
    return max(1, rough_chars // 4)


def _pricing_for_model(model_name: str) -> dict[str, Decimal]:
    return MODEL_PRICING_USD_PER_MILLION.get(model_name, MODEL_PRICING_USD_PER_MILLION[DEFAULT_AGENT_MODEL])


def _estimate_cost_usd(model_name: str, input_tokens: int, output_tokens: int) -> Decimal:
    pricing = _pricing_for_model(model_name)
    input_cost = (Decimal(input_tokens) / Decimal("1000000")) * pricing["input"]
    output_cost = (Decimal(output_tokens) / Decimal("1000000")) * pricing["output"]
    return (input_cost + output_cost).quantize(Decimal("0.000001"))


def _normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return " ".join(str(value).split()).strip()


def _normalize_role(user_row: dict | None) -> str:
    return (_normalize_text((user_row or {}).get("role")) or "user").lower()


def _coerce_int(value: Any) -> int | None:
    try:
        if value in (None, ""):
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _format_person_name(row: dict | None) -> str:
    row = row or {}
    full = " ".join(
        part for part in [_normalize_text(row.get("name")), _normalize_text(row.get("last_name"))] if part
    ).strip()
    return full or _normalize_text(row.get("username")) or "Unknown"


def _split_fitness_goals(raw_goals: Any) -> list[str]:
    if raw_goals is None:
        return []
    if isinstance(raw_goals, list):
        return [_normalize_text(goal).title() for goal in raw_goals if _normalize_text(goal)]
    if isinstance(raw_goals, tuple):
        return [_normalize_text(goal).title() for goal in raw_goals if _normalize_text(goal)]
    return [
        goal.title()
        for goal in (_normalize_text(piece) for piece in str(raw_goals).split(","))
        if goal
    ]


def _format_height_label(height_feet: Any, height_inches: Any) -> str | None:
    feet = _coerce_int(height_feet)
    inches = _coerce_int(height_inches)
    if feet is None and inches is None:
        return None
    feet = feet or 0
    inches = inches or 0
    return f"{feet}'{inches}\""


def _format_weight_label(weight: Any) -> str | None:
    if weight in (None, ""):
        return None
    try:
        weight_value = float(weight)
    except (TypeError, ValueError):
        return None
    if weight_value.is_integer():
        return f"{int(weight_value)} lb"
    return f"{weight_value:.1f} lb"


def _format_date_label(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).strftime("%b %-d, %Y")
    if isinstance(value, date):
        return value.strftime("%b %-d, %Y")
    text = _normalize_text(value)
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return text
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).strftime("%b %-d, %Y")


def _load_user_profile_row(user_id: int) -> dict | None:
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                f"""
                SELECT {AGENT_USER_PROFILE_COLUMNS}
                  FROM users
                 WHERE id = %s
                """,
                (user_id,),
            )
            return cursor.fetchone()


def _load_coaching_target_row(actor_row: dict, page_context: dict | None) -> tuple[dict, str]:
    role = _normalize_role(actor_row)
    selected_client_id = _coerce_int((page_context or {}).get("selected_client_id"))
    if not selected_client_id or selected_client_id == actor_row.get("id"):
        return actor_row, "self"

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            if role == "trainer":
                cursor.execute(
                    "SELECT trainer_id FROM users WHERE id = %s",
                    (selected_client_id,),
                )
                link_row = cursor.fetchone()
                if not link_row or link_row.get("trainer_id") != actor_row.get("id"):
                    return actor_row, "self"
            cursor.execute(
                f"""
                SELECT {AGENT_USER_PROFILE_COLUMNS}
                  FROM users
                 WHERE id = %s
                """,
                (selected_client_id,),
            )
            target_row = cursor.fetchone()
    if not target_row:
        return actor_row, "self"
    return target_row, "selected_client"


def _load_recent_coaching_signals(target_user_id: int) -> dict[str, Any]:
    signals: dict[str, Any] = {
        "logged_workouts_30d": 0,
        "completed_sessions_30d": 0,
        "upcoming_sessions_14d": 0,
        "most_tracked_workout": None,
        "last_logged_workout_name": None,
        "last_logged_workout_at": None,
    }
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT COUNT(*)::int AS logged_workouts_30d
                  FROM user_exercise_history
                 WHERE user_id = %s
                   AND recorded_at >= CURRENT_TIMESTAMP - INTERVAL '30 days'
                """,
                (target_user_id,),
            )
            row = cursor.fetchone() or {}
            signals["logged_workouts_30d"] = int(row.get("logged_workouts_30d") or 0)

            cursor.execute(
                """
                SELECT w.name AS workout_name,
                       h.recorded_at
                  FROM user_exercise_history h
                  JOIN workouts w
                    ON w.id = h.workout_id
                 WHERE h.user_id = %s
                 ORDER BY h.recorded_at DESC
                 LIMIT 1
                """,
                (target_user_id,),
            )
            row = cursor.fetchone() or {}
            signals["last_logged_workout_name"] = row.get("workout_name")
            signals["last_logged_workout_at"] = _format_date_label(row.get("recorded_at"))

            cursor.execute(
                """
                SELECT w.name AS workout_name,
                       COUNT(*)::int AS tracked_count
                  FROM user_exercise_history h
                  JOIN workouts w
                    ON w.id = h.workout_id
                 WHERE h.user_id = %s
                 GROUP BY w.name
                 ORDER BY tracked_count DESC, w.name ASC
                 LIMIT 1
                """,
                (target_user_id,),
            )
            row = cursor.fetchone() or {}
            signals["most_tracked_workout"] = row.get("workout_name")

            cursor.execute(
                """
                SELECT COUNT(*)::int AS completed_sessions_30d
                  FROM trainer_schedule
                 WHERE client_id = %s
                   AND status = 'completed'
                   AND COALESCE(session_completed_at, end_time, start_time) >= CURRENT_TIMESTAMP - INTERVAL '30 days'
                """,
                (target_user_id,),
            )
            row = cursor.fetchone() or {}
            signals["completed_sessions_30d"] = int(row.get("completed_sessions_30d") or 0)

            cursor.execute(
                """
                SELECT COUNT(*)::int AS upcoming_sessions_14d
                  FROM trainer_schedule
                 WHERE client_id = %s
                   AND status = 'booked'
                   AND start_time >= CURRENT_TIMESTAMP
                   AND start_time < CURRENT_TIMESTAMP + INTERVAL '14 days'
                """,
                (target_user_id,),
            )
            row = cursor.fetchone() or {}
            signals["upcoming_sessions_14d"] = int(row.get("upcoming_sessions_14d") or 0)
    return signals


def _build_coaching_context(actor_row: dict, page_context: dict | None) -> dict[str, Any]:
    target_row, relationship = _load_coaching_target_row(actor_row, page_context)
    goals = _split_fitness_goals(target_row.get("fitness_goals"))
    exercise_history = _normalize_text(target_row.get("exercise_history"))
    user_level = get_user_level(exercise_history)
    guidelines = get_guidelines(exercise_history, goals) if exercise_history and goals else {}
    age = _coerce_int(target_row.get("age"))
    heart_rate_zone = calculate_target_heart_rate(age) if age is not None else None
    injury_profile = parse_injury_payload(target_row.get("injury"))
    cardio_restriction = bool(target_row.get("cardio_restriction")) or injury_profile.get("cardio")
    injury_regions = injury_profile.get("regions") or []
    injury_exclusions = sorted(compute_injury_exclusions(injury_regions, cardio_restriction))
    recent_signals = _load_recent_coaching_signals(target_row["id"])

    missing_profile_fields = []
    if age is None:
        missing_profile_fields.append("age")
    if not goals:
        missing_profile_fields.append("fitness_goals")
    if not exercise_history:
        missing_profile_fields.append("exercise_history")
    if not _normalize_text(target_row.get("commitment")):
        missing_profile_fields.append("commitment")

    return {
        "target_user_id": target_row.get("id"),
        "target_name": _format_person_name(target_row),
        "relationship": relationship,
        "role": _normalize_role(target_row),
        "age": age,
        "weight_label": _format_weight_label(target_row.get("weight")),
        "height_label": _format_height_label(target_row.get("height_feet"), target_row.get("height_inches")),
        "gender": _normalize_text(target_row.get("gender")),
        "exercise_history": exercise_history,
        "user_level": user_level,
        "fitness_goals": goals,
        "commitment": _normalize_text(target_row.get("commitment")),
        "workout_duration": _coerce_int(target_row.get("workout_duration")),
        "additional_notes": _normalize_text(target_row.get("additional_notes")),
        "injury_regions": injury_regions,
        "injury_details": _normalize_text(target_row.get("injury_details")),
        "cardio_restriction": cardio_restriction,
        "injury_exclusions": injury_exclusions,
        "guidelines": guidelines or {},
        "target_heart_rate_zone": heart_rate_zone,
        "workouts_completed_total": int(target_row.get("workouts_completed") or 0),
        "last_workout_completed": _format_date_label(target_row.get("last_workout_completed")),
        "recent_signals": recent_signals,
        "missing_profile_fields": missing_profile_fields,
    }


def ensure_agent_schema() -> None:
    statements = [
        """
        ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ
        """,
        """
        ALTER TABLE users ALTER COLUMN created_at SET DEFAULT CURRENT_TIMESTAMP
        """,
        """
        ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ
        """,
        """
        ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_cancel_at TIMESTAMPTZ
        """,
        """
        CREATE TABLE IF NOT EXISTS agent_threads (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            title TEXT,
            status TEXT NOT NULL DEFAULT 'active',
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS agent_messages (
            id BIGSERIAL PRIMARY KEY,
            thread_id TEXT NOT NULL REFERENCES agent_threads(id) ON DELETE CASCADE,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            role TEXT NOT NULL,
            content TEXT NOT NULL DEFAULT '',
            metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS agent_messages_thread_created_idx
            ON agent_messages (thread_id, created_at)
        """,
        """
        CREATE TABLE IF NOT EXISTS agent_actions (
            id TEXT PRIMARY KEY,
            thread_id TEXT NOT NULL REFERENCES agent_threads(id) ON DELETE CASCADE,
            requested_by INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            action_type TEXT NOT NULL,
            label TEXT,
            summary_text TEXT,
            arguments JSONB NOT NULL DEFAULT '{}'::jsonb,
            status TEXT NOT NULL DEFAULT 'pending',
            result_payload JSONB,
            confirmed_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            confirmed_at TIMESTAMPTZ,
            cancelled_at TIMESTAMPTZ
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS agent_actions_requester_status_idx
            ON agent_actions (requested_by, status, created_at DESC)
        """,
        """
        CREATE TABLE IF NOT EXISTS agent_budget_ledger (
            id BIGSERIAL PRIMARY KEY,
            thread_id TEXT REFERENCES agent_threads(id) ON DELETE SET NULL,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            provider TEXT NOT NULL DEFAULT 'openai',
            model TEXT NOT NULL,
            estimated_cost_usd NUMERIC(12, 6),
            actual_cost_usd NUMERIC(12, 6),
            input_tokens INTEGER,
            output_tokens INTEGER,
            metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS agent_budget_ledger_created_idx
            ON agent_budget_ledger (created_at DESC)
        """,
        """
        CREATE TABLE IF NOT EXISTS agent_documents (
            id BIGSERIAL PRIMARY KEY,
            document_kind TEXT NOT NULL,
            source_type TEXT NOT NULL DEFAULT 'manual',
            source_key TEXT NOT NULL UNIQUE,
            title TEXT NOT NULL,
            content_text TEXT NOT NULL,
            summary_text TEXT,
            source_url TEXT,
            source_label TEXT,
            published_at TIMESTAMPTZ,
            evidence_tier INTEGER NOT NULL DEFAULT 2,
            approval_status TEXT NOT NULL DEFAULT 'approved',
            metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
            content_hash TEXT,
            created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS agent_documents_kind_approval_idx
            ON agent_documents (document_kind, approval_status, COALESCE(published_at, updated_at, created_at) DESC)
        """,
        """
        CREATE TABLE IF NOT EXISTS agent_document_chunks (
            id BIGSERIAL PRIMARY KEY,
            document_id BIGINT NOT NULL REFERENCES agent_documents(id) ON DELETE CASCADE,
            chunk_index INTEGER NOT NULL,
            chunk_text TEXT NOT NULL,
            metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
        CREATE UNIQUE INDEX IF NOT EXISTS agent_document_chunks_unique_idx
            ON agent_document_chunks (document_id, chunk_index)
        """,
        """
        CREATE TABLE IF NOT EXISTS agent_research_sync_runs (
            id BIGSERIAL PRIMARY KEY,
            triggered_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMPTZ
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS agent_cached_summaries (
            id BIGSERIAL PRIMARY KEY,
            summary_key TEXT NOT NULL UNIQUE,
            owner_user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            scope TEXT NOT NULL DEFAULT 'global',
            summary_text TEXT,
            data JSONB NOT NULL DEFAULT '{}'::jsonb,
            computed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMPTZ
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS agent_risk_flags (
            id BIGSERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            owner_user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            risk_level TEXT NOT NULL DEFAULT 'watch',
            reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
            status TEXT NOT NULL DEFAULT 'active',
            computed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS agent_risk_flags_owner_status_idx
            ON agent_risk_flags (owner_user_id, status, computed_at DESC)
        """,
    ]
    try:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                for statement in statements:
                    cursor.execute(statement)
            conn.commit()
    except Exception:
        logger.exception("Agent schema bootstrap failed")


def _load_user_row(user_id: int) -> dict | None:
    return _load_user_profile_row(user_id)


def create_thread(user_id: int, *, title: str | None = None) -> str:
    thread_id = str(uuid.uuid4())
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO agent_threads (id, user_id, title)
                VALUES (%s, %s, %s)
                """,
                (thread_id, user_id, title),
            )
            conn.commit()
    return thread_id


def _touch_thread(thread_id: str) -> None:
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE agent_threads
                   SET updated_at = CURRENT_TIMESTAMP
                 WHERE id = %s
                """,
                (thread_id,),
            )
            conn.commit()


def _store_message(thread_id: str, user_id: int | None, role: str, content: str, metadata: dict[str, Any] | None = None) -> int:
    safe_metadata = _safe_json(metadata or {})
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO agent_messages (thread_id, user_id, role, content, metadata)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    thread_id,
                    user_id,
                    role,
                    content or "",
                    psycopg2.extras.Json(safe_metadata),
                ),
            )
            row_id = cursor.fetchone()[0]
            conn.commit()
    _touch_thread(thread_id)
    return row_id


def get_thread_messages(user_id: int, thread_id: str) -> list[dict[str, Any]]:
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT m.id, m.role, m.content, m.metadata, m.created_at
                  FROM agent_messages m
                  JOIN agent_threads t
                    ON t.id = m.thread_id
                 WHERE m.thread_id = %s
                   AND t.user_id = %s
                 ORDER BY m.created_at ASC, m.id ASC
                """,
                (thread_id, user_id),
            )
            rows = cursor.fetchall() or []
    return [
        {
            "id": row.get("id"),
            "role": row.get("role"),
            "content": row.get("content") or "",
            "metadata": row.get("metadata") or {},
            "created_at": row.get("created_at").isoformat() if row.get("created_at") else None,
        }
        for row in rows
    ]


def get_latest_thread(user_id: int) -> dict[str, Any] | None:
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT id, title, created_at, updated_at
                  FROM agent_threads
                 WHERE user_id = %s
                 ORDER BY updated_at DESC, created_at DESC, id DESC
                 LIMIT 1
                """,
                (user_id,),
            )
            row = cursor.fetchone()
    if not row:
        return None
    return {
        "id": row.get("id"),
        "title": row.get("title"),
        "created_at": row.get("created_at").isoformat() if row.get("created_at") else None,
        "updated_at": row.get("updated_at").isoformat() if row.get("updated_at") else None,
    }


def clear_history(user_id: int) -> dict[str, Any]:
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                DELETE FROM agent_threads
                 WHERE user_id = %s
                RETURNING id
                """,
                (user_id,),
            )
            deleted_rows = cursor.fetchall() or []
            conn.commit()
    return {
        "deleted_thread_count": len(deleted_rows),
    }


def _load_recent_thread_history(user_id: int, thread_id: str) -> list[dict[str, str]]:
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT m.role, m.content
                  FROM agent_messages m
                  JOIN agent_threads t
                    ON t.id = m.thread_id
                 WHERE m.thread_id = %s
                   AND t.user_id = %s
                   AND m.role IN ('user', 'assistant')
                 ORDER BY m.created_at DESC, m.id DESC
                 LIMIT %s
                """,
                (thread_id, user_id, MAX_AGENT_TURNS * 2),
            )
            rows = cursor.fetchall() or []
    ordered = list(reversed(rows))
    return [{"role": row["role"], "content": row["content"] or ""} for row in ordered]


def _budget_spend_total() -> Decimal:
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT COALESCE(SUM(COALESCE(actual_cost_usd, estimated_cost_usd, 0)), 0)::text AS spend_total
                  FROM agent_budget_ledger
                 WHERE created_at >= %s
                   AND created_at < %s
                """,
                (_month_start_utc(), _next_month_start_utc()),
            )
            row = cursor.fetchone() or {}
    return Decimal(row.get("spend_total") or "0")


def _record_budget_entry(
    *,
    thread_id: str | None,
    user_id: int | None,
    model: str,
    estimated_cost_usd: Decimal | None,
    actual_cost_usd: Decimal | None,
    input_tokens: int | None,
    output_tokens: int | None,
    metadata: dict[str, Any] | None = None,
) -> None:
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO agent_budget_ledger (
                    thread_id,
                    user_id,
                    model,
                    estimated_cost_usd,
                    actual_cost_usd,
                    input_tokens,
                    output_tokens,
                    metadata
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    thread_id,
                    user_id,
                    model,
                    estimated_cost_usd,
                    actual_cost_usd,
                    input_tokens,
                    output_tokens,
                    psycopg2.extras.Json(metadata or {}),
                ),
            )
            conn.commit()


def _budget_status(estimated_next_cost: Decimal = Decimal("0")) -> dict[str, Any]:
    spent = _budget_spend_total()
    monthly_budget = _get_monthly_budget_usd()
    internal_stop = _get_internal_stop_usd()
    blocked = spent + estimated_next_cost > internal_stop
    percent = float((spent / monthly_budget) * Decimal("100")) if monthly_budget > 0 else 0.0
    return {
        "spent_usd": float(spent),
        "budget_usd": float(monthly_budget),
        "internal_stop_usd": float(internal_stop),
        "blocked": blocked,
        "percent_used": round(percent, 2),
    }


def _create_pending_action(thread_id: str, requested_by: int, tool_result: dict[str, Any]) -> dict[str, Any]:
    action_id = str(uuid.uuid4())
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO agent_actions (
                    id,
                    thread_id,
                    requested_by,
                    action_type,
                    label,
                    summary_text,
                    arguments,
                    status
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, 'pending')
                """,
                (
                    action_id,
                    thread_id,
                    requested_by,
                    tool_result.get("action_type"),
                    tool_result.get("label"),
                    tool_result.get("summary"),
                    psycopg2.extras.Json(tool_result.get("arguments") or {}),
                ),
            )
            conn.commit()
    return {
        "id": action_id,
        "action_type": tool_result.get("action_type"),
        "label": tool_result.get("label"),
        "summary": tool_result.get("summary"),
        "arguments": tool_result.get("arguments") or {},
        "status": "pending",
    }


def _create_pending_actions(thread_id: str, requested_by: int, tool_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [_create_pending_action(thread_id, requested_by, tool_result) for tool_result in tool_results]


def _render_blocked_message() -> str:
    return (
        "FitBaseAI is paused for the rest of this billing cycle because the internal API budget stop was reached. "
        "You can still use the rest of the app normally."
    )


def _call_openai_chat(
    messages: list[dict[str, Any]],
    *,
    include_tools: bool = True,
    tool_choice: str = "auto",
) -> tuple[dict[str, Any], Decimal]:
    api_key = _get_openai_api_key()
    model_name = _get_agent_model()
    max_output_tokens = _get_max_output_tokens()
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not configured.")
    tools_payload = AGENT_TOOL_SPECS if include_tools else []
    estimated_input_tokens = _estimate_tokens_from_messages(messages, tools_payload)
    estimated_cost = _estimate_cost_usd(model_name, estimated_input_tokens, max_output_tokens)
    budget = _budget_status(estimated_cost)
    if budget["blocked"]:
        raise PermissionError("Internal budget stop reached.")

    payload: dict[str, Any] = {
        "model": model_name,
        "messages": messages,
        "max_completion_tokens": max_output_tokens,
    }
    if include_tools:
        payload["tools"] = AGENT_TOOL_SPECS
        payload["tool_choice"] = tool_choice

    response = requests.post(
        _get_openai_api_url(),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=_get_openai_timeout_seconds(),
    )
    if response.status_code >= 400:
        raise RuntimeError(f"OpenAI request failed: {response.status_code} {response.text[:500]}")
    return response.json(), estimated_cost


def _messages_to_responses_input(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    response_input: list[dict[str, Any]] = []
    for message in messages:
        role = _normalize_text(message.get("role")).lower()
        if role not in {"user", "assistant"}:
            continue
        content = _normalize_message_content(message.get("content"))
        if not content:
            continue
        response_input.append({"role": role, "content": content})
    return response_input


def _extract_response_output_text(response_json: dict[str, Any]) -> str:
    direct_output = _normalize_message_content(response_json.get("output_text"))
    if direct_output:
        return direct_output

    output_items = response_json.get("output") or []
    parts: list[str] = []
    for item in output_items:
        if not isinstance(item, dict):
            continue
        if item.get("type") != "message":
            continue
        content_items = item.get("content") or []
        for content_item in content_items:
            if not isinstance(content_item, dict):
                continue
            content_type = content_item.get("type")
            if content_type in {"output_text", "text"}:
                text_value = content_item.get("text")
                if text_value:
                    parts.append(str(text_value))
    return "\n".join(part for part in parts if part).strip()


def _call_openai_responses(
    *,
    instructions: str,
    input_messages: list[dict[str, Any]],
    reasoning_effort: str = "low",
    max_output_tokens_override: int | None = None,
) -> tuple[dict[str, Any], Decimal]:
    api_key = _get_openai_api_key()
    model_name = _get_agent_model()
    if max_output_tokens_override is None:
        max_output_tokens = max(_get_max_output_tokens(), 700)
    else:
        max_output_tokens = max(100, int(max_output_tokens_override))
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not configured.")

    payload: dict[str, Any] = {
        "model": model_name,
        "instructions": instructions,
        "input": input_messages,
        "max_output_tokens": max_output_tokens,
    }
    if reasoning_effort:
        payload["reasoning"] = {"effort": reasoning_effort}

    estimated_input_tokens = _estimate_tokens_from_messages(
        [{"role": "system", "content": instructions}, *input_messages],
        None,
    )
    estimated_cost = _estimate_cost_usd(model_name, estimated_input_tokens, max_output_tokens)
    budget = _budget_status(estimated_cost)
    if budget["blocked"]:
        raise PermissionError("Internal budget stop reached.")

    response = requests.post(
        _get_openai_responses_url(),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=_get_openai_timeout_seconds(),
    )
    if response.status_code >= 400:
        raise RuntimeError(f"OpenAI responses request failed: {response.status_code} {response.text[:500]}")
    return response.json(), estimated_cost


def _message_likely_contains_multiple_requests(message_text: str) -> bool:
    raw_text = str(message_text or "")
    if not _normalize_text(raw_text):
        return False
    matches = list(MULTI_REQUEST_START_PATTERN.finditer(raw_text))
    return len(matches) >= 2


def _extract_json_object_from_text(raw_text: str) -> dict[str, Any] | None:
    text = _normalize_message_content(raw_text)
    if not text:
        return None
    match = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if not match:
        return None
    try:
        parsed = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _plan_batched_requests(
    *,
    thread_id: str,
    user_id: int,
    message_text: str,
) -> dict[str, Any] | None:
    try:
        response_json, estimated_cost = _call_openai_responses(
            instructions=MULTI_REQUEST_PLANNER_INSTRUCTIONS,
            input_messages=[{"role": "user", "content": _normalize_text(message_text)}],
            reasoning_effort="low",
            max_output_tokens_override=DEFAULT_PLANNER_OUTPUT_TOKENS,
        )
        _record_chat_usage(
            response_json=response_json,
            estimated_cost=estimated_cost,
            thread_id=thread_id,
            user_id=user_id,
            metadata={"endpoint": "responses", "mode": "batch_planner"},
        )
        planner_payload = _extract_json_object_from_text(_extract_response_output_text(response_json))
        if not planner_payload:
            logger.warning(
                "Batch planner returned unparseable output for thread %s user %s. status=%s keys=%s",
                thread_id,
                user_id,
                response_json.get("status"),
                sorted(response_json.keys()),
            )
            return None
        request_rows = planner_payload.get("requests") or []
        requests_list: list[str] = []
        for item in request_rows:
            if not isinstance(item, dict):
                continue
            request_text = _normalize_text(item.get("text"))
            if request_text:
                requests_list.append(request_text)
        if len(requests_list) < 2:
            return None
        return {
            "too_many": bool(planner_payload.get("too_many")),
            "requests": requests_list[:BATCH_ACTION_LIMIT],
        }
    except Exception:
        logger.exception("Batch planner failed")
        return None


def _record_chat_usage(
    *,
    response_json: dict[str, Any],
    estimated_cost: Decimal,
    thread_id: str,
    user_id: int,
    metadata: dict[str, Any] | None = None,
) -> None:
    model_name = _get_agent_model()
    usage = response_json.get("usage") or {}
    input_tokens = int(usage.get("prompt_tokens") or usage.get("input_tokens") or 0)
    output_tokens = int(usage.get("completion_tokens") or usage.get("output_tokens") or 0)
    actual_cost = _estimate_cost_usd(model_name, input_tokens, output_tokens)
    output_details = usage.get("output_tokens_details") or {}
    merged_metadata = dict(metadata or {})
    if output_details:
        merged_metadata["output_tokens_details"] = output_details
    if response_json.get("incomplete_details"):
        merged_metadata["incomplete_details"] = response_json.get("incomplete_details")
    if response_json.get("status"):
        merged_metadata["response_status"] = response_json.get("status")
    _record_budget_entry(
        thread_id=thread_id,
        user_id=user_id,
        model=model_name,
        estimated_cost_usd=estimated_cost,
        actual_cost_usd=actual_cost,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        metadata=merged_metadata or {"endpoint": "chat_completions"},
    )


def _tool_result_to_tool_message(result: dict[str, Any]) -> str:
    return _safe_json_dump(result)


def _fallback_tool_response(tool_result: dict[str, Any], pending_action: dict[str, Any] | None = None) -> str:
    if pending_action:
        return ""
    if not tool_result.get("success"):
        return tool_result.get("error") or "I couldn't complete that request."

    metric_key = tool_result.get("metric_key")
    if metric_key == "estimated_one_rep_max":
        best_display = tool_result.get("metric_display") or tool_result.get("estimated_one_rep_max_display")
        name = tool_result.get("exercise_name")
        target = tool_result.get("target_name")
        value_mode = tool_result.get("value_mode") or "strength"
        if best_display:
            reply_options = tool_result.get("reply_options") or []
            if reply_options:
                return f"I found the exact match below for {target}. Select it for more details."
            if value_mode == "cardio":
                return f"{target}'s best time for {name} is {best_display}."
            if value_mode == "time_hold":
                return f"{target}'s best hold time for {name} is {best_display}."
            if value_mode == "bodyweight_reps":
                return f"{target}'s best reps for {name} is {best_display}."
            return f"{target}'s EST. 1RM for {name} is {best_display}."
        best = tool_result.get("best_estimated_one_rep_max")
        return f"{target}'s EST. 1RM for {name} is {best} lbs."
    if metric_key == "most_tracked_workout":
        return f"{tool_result.get('target_name')}'s most tracked workout is {tool_result.get('workout_name')} with {tool_result.get('tracked_count')} tracked entries."
    if metric_key == "today_schedule":
        items = tool_result.get("items") or []
        date_label = tool_result.get("target_date_label") or tool_result.get("target_date")
        is_self_schedule = bool(tool_result.get("is_self_schedule"))
        if not items:
            return f"You have no sessions on {date_label}." if is_self_schedule else f"{tool_result.get('target_name')} has no sessions on {date_label}."
        lead_line = (
            f"You have {len(items)} session{'s' if len(items) != 1 else ''} on {date_label}"
            if is_self_schedule
            else f"{tool_result.get('target_name')} has {len(items)} session{'s' if len(items) != 1 else ''} on {date_label}"
        )
        bullet_lines = []
        for item in items:
            item_date_label = item.get("date_label")
            counterpart_name = item.get("counterpart_name")
            time_range_label = item.get("time_window_label") or item.get("time_range_label") or item.get("time_label") or item.get("start_time")
            status_label = (_normalize_text(item.get("status")) or "booked").lower()
            if counterpart_name and item_date_label and time_range_label:
                line = f"• {counterpart_name} on {item_date_label} from {time_range_label}"
            elif counterpart_name and time_range_label:
                line = f"• {counterpart_name} from {time_range_label}"
            elif item_date_label and time_range_label:
                line = f"• {item_date_label} from {time_range_label}"
            else:
                line = f"• {time_range_label}"
            if status_label and status_label != "booked":
                line += f" ({status_label})"
            bullet_lines.append(line)
        return f"{lead_line}:\n\n" + "\n".join(bullet_lines)
    if metric_key == "next_session":
        return f"The next session for {tool_result.get('target_name')} is {tool_result.get('time_label')} with {tool_result.get('counterpart_name')}."
    if metric_key == "trainer_top_sessions_this_month":
        return f"{tool_result.get('trainer_name')} has trained the most completed sessions this month with {tool_result.get('session_count')}."
    if metric_key == "new_users_this_month":
        qualifier = " so far" if not tool_result.get("is_partial") else " so far, but some older rows are missing created_at data"
        return f"{tool_result.get('new_user_count')} new users signed up this month{qualifier}."
    if metric_key == "client_performance_summary":
        return (
            f"{tool_result.get('target_name')} has completed {tool_result.get('workouts_completed')} workouts and has "
            f"{tool_result.get('sessions_left')} sessions left."
        )
    if metric_key == "trainer_roster_summary":
        return f"{tool_result.get('trainer_name')} currently has {tool_result.get('total_clients')} linked clients."
    if metric_key == "schedule_window_summary":
        target_name = tool_result.get("target_name")
        session_count = int(tool_result.get("session_count") or 0)
        window_label = tool_result.get("window_label") or "that window"
        status_scope = (tool_result.get("status_scope") or "active").lower()
        is_self_schedule = bool(tool_result.get("is_self_schedule"))
        if status_scope == "completed":
            lead_intro = f"You completed {session_count} "
            zero_intro = f"You completed 0 sessions with {target_name} {window_label}."
        elif status_scope == "cancelled":
            lead_intro = f"You have {session_count} cancelled "
            zero_intro = f"You have 0 cancelled sessions with {target_name} {window_label}."
        else:
            if is_self_schedule:
                lead_intro = f"You have {session_count} "
                zero_intro = f"You have 0 sessions {window_label}."
            else:
                lead_intro = f"You have {session_count} "
                zero_intro = f"You have 0 sessions booked with {target_name} {window_label}."
        if session_count == 0:
            return zero_intro
        session_word = "session" if session_count == 1 else "sessions"
        items = tool_result.get("items") or []
        slot_labels = []
        for item in items:
            time_range_label = item.get("time_window_label") or item.get("time_range_label")
            weekday_label = item.get("weekday_label")
            item_date_label = item.get("date_label")
            counterpart_name = item.get("counterpart_name")
            if time_range_label and weekday_label and counterpart_name and is_self_schedule and status_scope not in {"completed", "cancelled"}:
                slot_labels.append(f"{counterpart_name} on {item_date_label} from {time_range_label}")
            elif time_range_label and weekday_label:
                slot_labels.append(f"{weekday_label}, {item_date_label} from {time_range_label}")
            elif time_range_label:
                slot_labels.append(time_range_label)
        if status_scope == "completed":
            lead_line = f"{lead_intro}{session_word} with {target_name} {window_label}"
        elif status_scope == "cancelled":
            lead_line = f"{lead_intro}{session_word} with {target_name} {window_label}"
        else:
            if is_self_schedule:
                lead_line = f"{lead_intro}{session_word} {window_label}"
            else:
                lead_line = f"{lead_intro}{session_word} booked with {target_name} {window_label}"
        if not slot_labels:
            return f"{lead_line}."
        bullet_lines = "\n".join(f"• {label}" for label in slot_labels)
        return f"{lead_line}:\n\n{bullet_lines}"
    if metric_key == "platform_summary":
        return f"The platform currently has {tool_result.get('total_users')} users and {tool_result.get('total_workouts_completed')} completed workouts."
    if metric_key == "trial_status":
        return f"{tool_result.get('target_name')} is on the {tool_result.get('subscription_type')} plan."
    return "I found the exact app data and I’m ready to use it."


def _message_likely_needs_tools(message_text: str) -> bool:
    normalized = _normalize_text(message_text).lower()
    if not normalized:
        return False

    exact_metric_patterns = (
        r"\bbest time\b\s+(?:for|of|on)\b",
        r"\bbest time\b\s+(?!for\b|of\b|on\b)[a-z0-9]",
        r"\bbest time\b[?.!]*$",
        r"\bmax time\b\s+(?:for|of|on)\b",
        r"\bmax time\b\s+(?!for\b|of\b|on\b)[a-z0-9]",
        r"\bmax time\b[?.!]*$",
        r"\b1rm\b",
        r"\bone rep max\b",
        r"\bestimated 1rm\b",
        r"\bmax\b\s+(?:for|of|on)\b",
        r"\bmax\b\s+(?!for\b|of\b|on\b)[a-z0-9]",
        r"\bmax\b[?.!]*$",
        r"\bpr\b\s+(?:for|of|on)\b",
        r"\bpr\b\s+(?!for\b|of\b|on\b)[a-z0-9]",
        r"\bpr\b[?.!]*$",
        r"\bpersonal record\b\s+(?:for|of|on)\b",
        r"\bpersonal record\b\s+(?!for\b|of\b|on\b)[a-z0-9]",
        r"\bpersonal record\b[?.!]*$",
        r"\brecord\b\s+(?:for|of|on)\b",
        r"\brecord\b\s+(?!for\b|of\b|on\b)[a-z0-9]",
        r"\brecord\b[?.!]*$",
        r"\bmost tracked workout\b",
        r"\bhow many clients\b",
        r"\bmy roster\b",
        r"\broster\b",
        r"\bschedule\b",
        r"\bcalendar\b",
        r"\bnext session\b",
        r"\bsession(s)? (today|tomorrow|this week|this month)\b",
        r"\blast week\b",
        r"\b(last|past|next)\s+\d+\s+(day|days|week|weeks|month|months|year|years)\b",
        r"\b(this|last|next)\s+(month|year)\b",
        r"\bthis coming week\b",
        r"\bcoming week\b",
        r"\bnext week\b",
        r"\bhow many days\b.*\btraining with\b",
        r"\bhow many days\b.*\btrain with\b",
        r"\bhow many days\b.*\btrained with\b",
        r"\bhow many days\b.*\bdid i train with\b",
        r"\bhow many sessions\b.*\bwith\b",
        r"\bsessions booked with\b",
        r"\btrainer has trained the most sessions\b",
        r"\bmost sessions this month\b",
        r"\bnew users\b",
        r"\bsigned up\b",
        r"\bplatform\b",
        r"\btrial status\b",
        r"\bsessions remaining\b",
        r"\bsessions left\b",
        r"\bworkouts completed\b",
        r"\bat[- ]risk\b",
        r"\bclient performance\b",
    )
    if any(re.search(pattern, normalized) for pattern in exact_metric_patterns):
        return True

    workflow_terms = (
        "book ",
        "schedule ",
        "reschedule",
        "cancel ",
        "complete ",
        "mark ",
        "delete ",
        "remove ",
        "swap ",
        "assign ",
        "block ",
        "move ",
    )
    if any(term in normalized for term in workflow_terms):
        if any(token in normalized for token in ("session", "calendar", "schedule", "workout", "time off")):
            return True

    return False


def _build_base_messages(
    *,
    user_row: dict,
    page_context: dict[str, Any] | None,
    retrieval_context: dict[str, Any] | None,
    coaching_context: dict[str, Any] | None,
    recent_history: list[dict[str, str]] | None,
) -> list[dict[str, Any]]:
    base_messages: list[dict[str, Any]] = [
        {"role": "system", "content": FITBASEAI_SYSTEM_PROMPT},
        {
            "role": "system",
            "content": build_runtime_context_message(
                user_row,
                page_context or {},
                retrieval_context or {},
                coaching_context or {},
            ),
        },
    ]
    if recent_history:
        base_messages.extend(recent_history)
    return base_messages


def _extract_assistant_text(response_json: dict[str, Any]) -> str:
    choice = ((response_json.get("choices") or [{}])[0]) or {}
    message_payload = choice.get("message") or {}
    return _normalize_message_content(message_payload.get("content"))


def _run_direct_model_answer(
    *,
    thread_id: str,
    user_id: int,
    messages: list[dict[str, Any]],
    fallback_instruction: str,
) -> str:
    instruction_parts = []
    input_messages: list[dict[str, Any]] = []
    for message in messages:
        role = _normalize_text(message.get("role")).lower()
        if role == "system":
            content = _normalize_message_content(message.get("content"))
            if content:
                instruction_parts.append(content)
        elif role in {"user", "assistant"}:
            input_messages.append({"role": role, "content": _normalize_message_content(message.get("content"))})
    instruction_parts.append(fallback_instruction)
    direct_response_json, direct_estimated_cost = _call_openai_responses(
        instructions="\n\n".join(part for part in instruction_parts if part),
        input_messages=_messages_to_responses_input(input_messages),
        reasoning_effort="low",
    )
    _record_chat_usage(
        response_json=direct_response_json,
        estimated_cost=direct_estimated_cost,
        thread_id=thread_id,
        user_id=user_id,
        metadata={"endpoint": "responses", "mode": "direct_answer"},
    )
    assistant_text = _extract_response_output_text(direct_response_json)
    if not assistant_text:
        logger.warning(
            "Direct model answer returned no assistant text for thread %s user %s. status=%s incomplete=%s keys=%s usage=%s",
            thread_id,
            user_id,
            direct_response_json.get("status"),
            direct_response_json.get("incomplete_details"),
            sorted(direct_response_json.keys()),
            direct_response_json.get("usage"),
        )
    return assistant_text


def _parse_commitment_days(commitment_text: str | None) -> int | None:
    text = _normalize_text(commitment_text)
    if not text:
        return None
    match = next(iter(re.findall(r"(\d+)", text)), None)
    return _coerce_int(match)


def _coaching_intro(coaching_context: dict[str, Any]) -> str:
    if (coaching_context or {}).get("relationship") == "selected_client":
        target_name = _normalize_text((coaching_context or {}).get("target_name")) or "that client's"
        return f"Based on {target_name}'s current profile"
    return "Based on your current profile"


def _frequency_guidance_answer(coaching_context: dict[str, Any]) -> str:
    level = _coerce_int(coaching_context.get("user_level")) or 1
    goals = set(coaching_context.get("fitness_goals") or [])
    commitment_days = _parse_commitment_days(coaching_context.get("commitment"))

    if level <= 1:
        low, high = 2, 3
    elif level == 2:
        low, high = 3, 4
    else:
        low, high = 4, 5

    if {"Lose Weight", "Increase Endurance", "Feel Better"} & goals:
        low = max(low, 3)
        high = min(high + 1, 6)
    if "Increase Strength" in goals:
        low = max(low, 3)
    if "Gain Muscle" in goals:
        low = max(low, 3)
        high = max(high, 4)

    intro = _coaching_intro(coaching_context)
    if commitment_days is not None:
        if commitment_days < low:
            return (
                f"{intro}, start with {commitment_days} day{'s' if commitment_days != 1 else ''} per week right now "
                f"because consistency matters more than forcing extra days. If that feels sustainable, build toward "
                f"{low}-{high} days per week over time."
            )
        recommended = min(max(commitment_days, low), high)
        return (
            f"{intro}, aim for about {recommended} days per week right now. That fits your current commitment and "
            f"training background well. If recovery is good and you stay consistent, you can build toward {high} days."
        )

    return (
        f"{intro}, a good target is about {low}-{high} days per week. Start at the lower end if recovery or consistency "
        f"has been shaky, and move up only when that feels sustainable."
    )


def _workout_duration_answer(coaching_context: dict[str, Any]) -> str:
    preferred_duration = _coerce_int(coaching_context.get("workout_duration"))
    intro = _coaching_intro(coaching_context)
    if preferred_duration:
        return (
            f"{intro}, about {preferred_duration} minutes is a strong target right now. That is enough time to train "
            f"well without making the plan harder to stick to."
        )
    return (
        f"{intro}, a good range is about 30-60 minutes depending on your goal, recovery, and schedule. Shorter, "
        f"consistent workouts beat longer workouts you cannot stick to."
    )


def _heart_rate_answer(coaching_context: dict[str, Any]) -> str | None:
    zone = coaching_context.get("target_heart_rate_zone") or {}
    if not zone:
        return None
    intro = _coaching_intro(coaching_context)
    return (
        f"{intro}, aim for roughly {zone.get('lower_bound')}-{zone.get('upper_bound')} bpm for most steady cardio work. "
        f"Estimated max heart rate is about {zone.get('max_heart_rate')} bpm."
    )


def _guidelines_answer(coaching_context: dict[str, Any]) -> str | None:
    guidelines = coaching_context.get("guidelines") or {}
    if not guidelines:
        return None
    intro = _coaching_intro(coaching_context)
    return (
        f"{intro}, use about {guidelines.get('Sets')} sets, {guidelines.get('Reps')} reps, and {guidelines.get('Rest')} "
        f"rest between sets as your default guideline."
    )


def _deterministic_coaching_fallback(message_text: str, coaching_context: dict[str, Any]) -> str | None:
    normalized = _normalize_text(message_text).lower()
    if not normalized:
        return None

    if (
        ("how many days" in normalized or "days per week" in normalized)
        and ("work out" in normalized or "workout" in normalized or "train" in normalized or "exercise" in normalized)
    ):
        return _frequency_guidance_answer(coaching_context)

    if (
        ("how long" in normalized or "duration" in normalized or "minutes" in normalized)
        and ("workout" in normalized or "session" in normalized or "train" in normalized)
    ):
        return _workout_duration_answer(coaching_context)

    if "heart rate" in normalized or "bpm" in normalized or "zone" in normalized:
        return _heart_rate_answer(coaching_context)

    if ("rest" in normalized and "set" in normalized) or ("sets" in normalized and "reps" in normalized):
        return _guidelines_answer(coaching_context)

    return None


def _render_general_answer_fallback(message_text: str | None = None, coaching_context: dict[str, Any] | None = None) -> str:
    deterministic = _deterministic_coaching_fallback(message_text or "", coaching_context or {})
    if deterministic:
        return deterministic
    return (
        "I couldn't generate a clear coaching answer just now. "
        "Try asking again, or ask a more specific training, nutrition, recovery, or wellbeing question."
    )


def _sentence_split(text: str) -> list[str]:
    cleaned = re.sub(r"\s+", " ", (text or "")).strip()
    if not cleaned:
        return []
    return [
        segment.strip()
        for segment in re.split(r"(?<=[.!?])\s+", cleaned)
        if segment and segment.strip()
    ]


def _postprocess_general_coaching_answer(text: str) -> str:
    if not text:
        return text

    cleaned = text.replace("—", "-").strip()
    cleaned = re.sub(r"^(great question|good question|short answer)\s*[-,:]?\s*", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(
        r"\b(If you want,? I can|If you'd like,? I can|Let me know if you want me to|Which do you want me to|Would you like me to)\b.*$",
        "",
        cleaned,
        flags=re.IGNORECASE | re.DOTALL,
    ).strip()
    cleaned = re.sub(
        r"\b(Why .*|How to .*|When to .*|Recovery and monitoring.*)\b.*$",
        "",
        cleaned,
        flags=re.IGNORECASE | re.DOTALL,
    ).strip()

    if "\n-" in cleaned or "\n•" in cleaned:
        cleaned = re.sub(r"\n[\-\u2022]\s*", " ", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()

    sentences = _sentence_split(cleaned)
    if not sentences:
        return cleaned

    trimmed = " ".join(sentences[:3]).strip()
    trimmed = re.sub(r"\s+", " ", trimmed).strip()
    return trimmed


def _build_planned_request_response_text(
    *,
    lookup_texts: list[str],
    unresolved_items: list[str],
    pending_action_count: int,
) -> str:
    sections: list[str] = []
    if pending_action_count:
        sections.append("Handling those requests... Review each one below.")
    if lookup_texts:
        if pending_action_count:
            sections.append("\n\n".join(lookup_texts))
        else:
            sections.append("\n\n".join(lookup_texts))
    if unresolved_items:
        unresolved_block = "I still need one detail for:\n" + "\n".join(f"• {item}" for item in unresolved_items)
        sections.append(unresolved_block)
    return "\n\n".join(section for section in sections if section).strip()


def _handle_planned_request_batch(
    *,
    thread_id: str,
    user_id: int,
    message_text: str,
    user_row: dict[str, Any],
    page_context: dict[str, Any] | None,
    recent_history: list[dict[str, str]] | None,
) -> dict[str, Any] | None:
    if not _message_likely_contains_multiple_requests(message_text):
        return None

    plan = _plan_batched_requests(
        thread_id=thread_id,
        user_id=user_id,
        message_text=message_text,
    )
    if not plan:
        return None

    request_texts = plan.get("requests") or []
    if len(request_texts) < 2:
        return None

    lookup_texts: list[str] = []
    unresolved_items: list[str] = []
    pending_action_results: list[dict[str, Any]] = []
    reply_options: list[dict[str, Any]] = []
    chosen_tool_result: dict[str, Any] | None = None

    if plan.get("too_many"):
        unresolved_items.append(
            f"I can handle up to {BATCH_ACTION_LIMIT} clear requests at a time. I planned the first {BATCH_ACTION_LIMIT} below."
        )

    for request_text in request_texts:
        direct_lookup_result = maybe_prepare_direct_lookup(
            request_text,
            user_row,
            page_context or {},
            recent_history,
        )
        if direct_lookup_result:
            if direct_lookup_result.get("success"):
                lookup_texts.append(_fallback_tool_response(direct_lookup_result, None))
                if not reply_options:
                    reply_options = direct_lookup_result.get("reply_options") or []
                    if reply_options:
                        chosen_tool_result = direct_lookup_result
            else:
                unresolved_items.append(f"{request_text}: {direct_lookup_result.get('error') or 'I could not resolve that lookup.'}")
            continue

        direct_batch_result = maybe_prepare_batched_schedule_actions(
            request_text,
            user_row,
            page_context or {},
            recent_history,
        )
        if direct_batch_result:
            if direct_batch_result.get("success"):
                batch_items = direct_batch_result.get("items") or []
                if len(pending_action_results) + len(batch_items) > BATCH_ACTION_LIMIT:
                    unresolved_items.append(
                        f"{request_text}: I can handle up to {BATCH_ACTION_LIMIT} requests at a time. Split the rest into another message."
                    )
                else:
                    pending_action_results.extend(batch_items)
            else:
                unresolved_items.append(
                    f"{request_text}: {direct_batch_result.get('error') or 'I could not break that into a separate request.'}"
                )
            continue

        direct_schedule_result = maybe_prepare_direct_schedule_action(
            request_text,
            user_row,
            page_context or {},
            recent_history,
        )
        if direct_schedule_result:
            if direct_schedule_result.get("success") and direct_schedule_result.get("kind") == "pending_action":
                if len(pending_action_results) >= BATCH_ACTION_LIMIT:
                    unresolved_items.append(
                        f"{request_text}: I can handle up to {BATCH_ACTION_LIMIT} requests at a time. Split the rest into another message."
                    )
                else:
                    pending_action_results.append(direct_schedule_result)
            else:
                unresolved_items.append(
                    f"{request_text}: {direct_schedule_result.get('error') or 'I could not prepare that task.'}"
                )
            continue

        unresolved_items.append(f"{request_text}: I couldn't clearly resolve that part yet.")

    if not lookup_texts and not pending_action_results and not unresolved_items:
        return None

    pending_actions_payload = (
        _create_pending_actions(thread_id, user_id, pending_action_results)
        if pending_action_results
        else []
    )
    assistant_text = _build_planned_request_response_text(
        lookup_texts=lookup_texts,
        unresolved_items=unresolved_items,
        pending_action_count=len(pending_actions_payload),
    )
    tool_result_payload = {
        "kind": "planned_request_batch",
        "planned_requests": request_texts,
        "reply_options": reply_options,
    }
    if plan.get("too_many"):
        tool_result_payload["too_many"] = True
    if chosen_tool_result:
        tool_result_payload = {
            **chosen_tool_result,
            **tool_result_payload,
            "reply_options": reply_options or chosen_tool_result.get("reply_options") or [],
        }

    return _finalize_assistant_message(
        thread_id,
        user_id,
        assistant_text,
        citations=[],
        pending_actions=pending_actions_payload,
        tool_result=tool_result_payload,
    )


def _finalize_assistant_message(
    thread_id: str,
    user_id: int,
    assistant_text: str,
    *,
    citations: list[dict[str, Any]] | None = None,
    pending_action: dict[str, Any] | None = None,
    pending_actions: list[dict[str, Any]] | None = None,
    tool_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    safe_citations = _safe_json(citations or [])
    safe_pending_action = _safe_json(pending_action)
    safe_pending_actions = _safe_json(pending_actions or [])
    safe_tool_result = _safe_json(tool_result)
    metadata = {
        "citations": safe_citations,
        "pending_action": safe_pending_action,
        "pending_actions": safe_pending_actions,
        "tool_result": safe_tool_result,
    }
    _store_message(thread_id, user_id, "assistant", assistant_text, metadata)
    return {
        "thread_id": thread_id,
        "message": assistant_text,
        "citations": safe_citations,
        "pending_action": safe_pending_action,
        "pending_actions": safe_pending_actions,
        "tool_result": safe_tool_result,
        "budget": _budget_status(),
    }


def chat_with_fitbaseai(
    *,
    user_id: int,
    message_text: str,
    page_context: dict[str, Any] | None = None,
    thread_id: str | None = None,
) -> dict[str, Any]:
    user_row = _load_user_row(user_id)
    if not user_row:
        raise ValueError("User not found.")

    cleaned_message = (message_text or "").strip()
    if not cleaned_message:
        raise ValueError("Message is empty.")

    if not thread_id:
        thread_id = create_thread(user_id, title=cleaned_message[:80])
    _store_message(thread_id, user_id, "user", cleaned_message, {"page_context": page_context or {}})

    recent_history = _load_recent_thread_history(user_id, thread_id)

    planned_batch_response = _handle_planned_request_batch(
        thread_id=thread_id,
        user_id=user_id,
        message_text=cleaned_message,
        user_row=user_row,
        page_context=page_context or {},
        recent_history=recent_history,
    )
    if planned_batch_response:
        return planned_batch_response

    direct_lookup_result = maybe_prepare_direct_lookup(
        cleaned_message,
        user_row,
        page_context or {},
        recent_history,
    )
    if direct_lookup_result:
        direct_text = _fallback_tool_response(direct_lookup_result, None)
        return _finalize_assistant_message(
            thread_id,
            user_id,
            direct_text,
            citations=[],
            tool_result=direct_lookup_result,
        )

    direct_batch_result = maybe_prepare_batched_schedule_actions(
        cleaned_message,
        user_row,
        page_context or {},
        recent_history,
    )
    if direct_batch_result:
        if not direct_batch_result.get("success"):
            return _finalize_assistant_message(
                thread_id,
                user_id,
                direct_batch_result.get("error") or "I couldn't break that into separate requests.",
                citations=[],
                tool_result=direct_batch_result,
            )
        batch_items = direct_batch_result.get("items") or []
        pending_actions_payload = _create_pending_actions(thread_id, user_id, batch_items)
        return _finalize_assistant_message(
            thread_id,
            user_id,
            "Handling those requests... Review each one below.",
            citations=[],
            pending_actions=pending_actions_payload,
            tool_result=direct_batch_result,
        )

    direct_schedule_result = maybe_prepare_direct_schedule_action(
        cleaned_message,
        user_row,
        page_context or {},
        recent_history,
    )
    if direct_schedule_result:
        pending_action_payload = None
        if direct_schedule_result.get("kind") == "pending_action" and direct_schedule_result.get("success"):
            pending_action_payload = _create_pending_action(thread_id, user_id, direct_schedule_result)
        direct_text = _fallback_tool_response(direct_schedule_result, pending_action_payload)
        return _finalize_assistant_message(
            thread_id,
            user_id,
            direct_text,
            citations=[],
            pending_action=pending_action_payload,
            tool_result=direct_schedule_result,
        )

    retrieval_context = search_retrieval_context(cleaned_message)
    coaching_context = _build_coaching_context(user_row, page_context or {})
    base_messages = _build_base_messages(
        user_row=user_row,
        page_context=page_context or {},
        retrieval_context=retrieval_context,
        coaching_context=coaching_context,
        recent_history=recent_history,
    )

    tool_result_for_fallback: dict[str, Any] | None = None
    pending_action_payload: dict[str, Any] | None = None
    citations = retrieval_context.get("citations") or []
    messages = base_messages
    direct_answer_instruction = (
        "Answer the user's last message directly in plain language. "
        "Do not call tools unless exact live app data is required. "
        "If the question is general coaching, training, nutrition, recovery, or wellbeing guidance, "
        "personalize the answer to the coaching target profile in the runtime context, "
        "use the stored goals, commitment, injuries, and guidelines when they are relevant, "
        "and give a concise helpful answer. "
        "Default to 1-2 sentences, never exceed 3 sentences unless the user asked for more detail, "
        "and do not add unsolicited follow-up offers."
    )

    try:
        if not _message_likely_needs_tools(cleaned_message):
            assistant_text = _run_direct_model_answer(
                thread_id=thread_id,
                user_id=user_id,
                messages=messages,
                fallback_instruction=direct_answer_instruction,
            )
            if not assistant_text:
                assistant_text = _render_general_answer_fallback(cleaned_message, coaching_context)
            else:
                assistant_text = _postprocess_general_coaching_answer(assistant_text)
            return _finalize_assistant_message(
                thread_id,
                user_id,
                assistant_text,
                citations=citations,
            )

        for _ in range(4):
            response_json, estimated_cost = _call_openai_chat(messages)
            _record_chat_usage(
                response_json=response_json,
                estimated_cost=estimated_cost,
                thread_id=thread_id,
                user_id=user_id,
                metadata={"endpoint": "chat_completions", "mode": "tool_enabled"},
            )

            choice = ((response_json.get("choices") or [{}])[0]) or {}
            message_payload = choice.get("message") or {}
            assistant_text = _normalize_message_content(message_payload.get("content"))
            tool_calls = message_payload.get("tool_calls") or []
            if not tool_calls:
                if not assistant_text:
                    logger.warning(
                        "Tool-enabled response returned no tool calls and no assistant text for thread %s user %s. Response keys=%s",
                        thread_id,
                        user_id,
                        sorted(response_json.keys()),
                    )
                    assistant_text = _run_direct_model_answer(
                        thread_id=thread_id,
                        user_id=user_id,
                        messages=messages,
                        fallback_instruction=direct_answer_instruction,
                    )
                elif assistant_text:
                    assistant_text = _postprocess_general_coaching_answer(assistant_text)
                if not assistant_text and tool_result_for_fallback:
                    assistant_text = _fallback_tool_response(tool_result_for_fallback, pending_action_payload)
                if not assistant_text:
                    assistant_text = _render_general_answer_fallback(cleaned_message, coaching_context)
                elif not tool_result_for_fallback:
                    assistant_text = _postprocess_general_coaching_answer(assistant_text)
                return _finalize_assistant_message(
                    thread_id,
                    user_id,
                    assistant_text,
                    citations=citations,
                    pending_action=pending_action_payload,
                    tool_result=tool_result_for_fallback,
                )

            assistant_message_for_history = {"role": "assistant", "content": assistant_text or "", "tool_calls": tool_calls}
            messages.append(assistant_message_for_history)

            for tool_call in tool_calls:
                function_payload = tool_call.get("function") or {}
                tool_name = function_payload.get("name")
                raw_arguments = function_payload.get("arguments") or "{}"
                try:
                    arguments = json.loads(raw_arguments)
                except json.JSONDecodeError:
                    arguments = {}
                tool_result = execute_tool_call(tool_name, arguments, user_row, page_context or {})
                tool_result_for_fallback = tool_result
                if tool_result.get("kind") == "pending_action" and tool_result.get("success"):
                    pending_action_payload = _create_pending_action(thread_id, user_id, tool_result)
                    enriched_tool_result = {
                        **tool_result,
                        "pending_action": pending_action_payload,
                    }
                    assistant_text = _fallback_tool_response(enriched_tool_result, pending_action_payload)
                    return _finalize_assistant_message(
                        thread_id,
                        user_id,
                        assistant_text,
                        citations=citations,
                        pending_action=pending_action_payload,
                        tool_result=enriched_tool_result,
                    )
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tool_call.get("id"),
                        "content": _tool_result_to_tool_message(tool_result),
                    }
                )

        fallback_text = _fallback_tool_response(tool_result_for_fallback or {}, pending_action_payload)
        return _finalize_assistant_message(
            thread_id,
            user_id,
            fallback_text,
            citations=citations,
            pending_action=pending_action_payload,
            tool_result=tool_result_for_fallback,
        )
    except PermissionError:
        blocked_text = _render_blocked_message()
        return _finalize_assistant_message(thread_id, user_id, blocked_text, citations=citations)
    except Exception as exc:
        logger.exception("Agent chat failed")
        if tool_result_for_fallback:
            fallback_text = _fallback_tool_response(tool_result_for_fallback, pending_action_payload)
            return _finalize_assistant_message(
                thread_id,
                user_id,
                fallback_text,
                citations=citations,
                pending_action=pending_action_payload,
                tool_result=tool_result_for_fallback,
            )
        deterministic_fallback = _deterministic_coaching_fallback(cleaned_message, coaching_context)
        if deterministic_fallback:
            return _finalize_assistant_message(thread_id, user_id, deterministic_fallback, citations=citations)
        error_text = "FitBaseAI hit a temporary issue and could not finish that request just now."
        return _finalize_assistant_message(thread_id, user_id, error_text, citations=citations)


def _load_action_for_user(action_id: str, user_id: int) -> dict | None:
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT a.*
                  FROM agent_actions a
                  JOIN agent_threads t
                    ON t.id = a.thread_id
                 WHERE a.id = %s
                   AND t.user_id = %s
                """,
                (action_id, user_id),
            )
            return cursor.fetchone()


def confirm_agent_action(*, user_id: int, action_id: str) -> dict[str, Any]:
    action_row = _load_action_for_user(action_id, user_id)
    if not action_row:
        raise ValueError("Pending action not found.")
    if action_row.get("status") != "pending":
        raise ValueError("That action is no longer pending.")
    user_row = _load_user_row(user_id)
    if not user_row:
        raise ValueError("User not found.")

    result = execute_pending_action(action_row, user_row)
    new_status = "completed" if result.get("success") else "failed"
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE agent_actions
                   SET status = %s,
                       confirmed_by = %s,
                       confirmed_at = CURRENT_TIMESTAMP,
                       updated_at = CURRENT_TIMESTAMP,
                       result_payload = %s
                 WHERE id = %s
                """,
                (
                    new_status,
                    user_id,
                    psycopg2.extras.Json(result),
                    action_id,
                ),
            )
            conn.commit()
    assistant_text = result.get("message") or (result.get("error") or "The requested action could not be completed.")
    _store_message(
        action_row["thread_id"],
        user_id,
        "assistant",
        assistant_text,
        {"action_result": result, "action_id": action_id, "action_status": "completed"},
    )
    return {
        "success": result.get("success", False),
        "message": assistant_text,
        "result": result,
        "budget": _budget_status(),
    }


def cancel_agent_action(*, user_id: int, action_id: str) -> dict[str, Any]:
    action_row = _load_action_for_user(action_id, user_id)
    if not action_row:
        raise ValueError("Pending action not found.")
    if action_row.get("status") != "pending":
        raise ValueError("That action is no longer pending.")

    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE agent_actions
                   SET status = 'cancelled',
                       cancelled_at = CURRENT_TIMESTAMP,
                       updated_at = CURRENT_TIMESTAMP
                 WHERE id = %s
                """,
                (action_id,),
            )
            conn.commit()
    assistant_text = "Okay. I cancelled that pending request."
    _store_message(
        action_row["thread_id"],
        user_id,
        "assistant",
        assistant_text,
        {"action_id": action_id, "action_status": "cancelled"},
    )
    return {"success": True, "message": assistant_text, "budget": _budget_status()}


def ingest_manuscript_upload(*, user_id: int, file_storage) -> dict[str, Any]:
    filename, text = extract_uploaded_text(file_storage)
    return ingest_document(
        created_by=user_id,
        document_kind="manuscript",
        title=filename,
        content_text=text,
        source_type="manual_upload",
        source_key=f"manuscript:{filename.lower()}",
        source_label="Manual manuscript upload",
        evidence_tier=2,
        approval_status="approved",
        metadata={"filename": filename},
    )


def run_research_sync(*, user_id: int | None) -> dict[str, Any]:
    return sync_free_research_sources(triggered_by_user_id=user_id)


def get_agent_admin_summary() -> dict[str, Any]:
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT
                    COALESCE(SUM(CASE WHEN document_kind = 'manuscript' THEN 1 ELSE 0 END), 0)::int AS manuscript_count,
                    COALESCE(SUM(CASE WHEN document_kind = 'research' THEN 1 ELSE 0 END), 0)::int AS research_count
                  FROM agent_documents
                """
            )
            counts = cursor.fetchone() or {}
            cursor.execute(
                """
                SELECT status, created_at, completed_at, metadata
                  FROM agent_research_sync_runs
                 ORDER BY created_at DESC
                 LIMIT 1
                """
            )
            sync_row = cursor.fetchone()
    budget = _budget_status()
    return {
        "budget": budget,
        "manuscript_count": counts.get("manuscript_count") or 0,
        "research_count": counts.get("research_count") or 0,
        "latest_sync": {
            "status": sync_row.get("status") if sync_row else None,
            "created_at": sync_row.get("created_at").isoformat() if sync_row and sync_row.get("created_at") else None,
            "completed_at": sync_row.get("completed_at").isoformat() if sync_row and sync_row.get("completed_at") else None,
            "metadata": sync_row.get("metadata") if sync_row else None,
        },
    }
