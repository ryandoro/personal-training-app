from __future__ import annotations

import importlib
import json
import logging
import math
import re
from datetime import date, datetime, time, timedelta, timezone
from typing import Any
from zoneinfo import ZoneInfo

import psycopg2
import psycopg2.extras

from helpers import (
    CUSTOM_WORKOUT_TOKEN,
    HOME_WORKOUT_TOKEN,
    generate_workout,
    get_connection,
    get_user_level,
)

logger = logging.getLogger(__name__)

LOOKUP_TOOL_NAME = "lookup_fitbase_data"
ACTION_TOOL_NAME = "prepare_fitbase_action"
KNOWN_WORKOUT_CATEGORIES = (
    "Chest and Triceps",
    "Back and Biceps",
    "Shoulders and Abs",
    "Arms",
    "Legs",
    "Upper Body",
    "Full Body",
    "Cardio",
    CUSTOM_WORKOUT_TOKEN,
    HOME_WORKOUT_TOKEN,
)
WORKOUT_CATEGORY_ALIASES = (
    (r"\bchest\s*(?:and|&)\s*triceps\b", "Chest and Triceps"),
    (r"\bback\s*(?:and|&)\s*biceps\b", "Back and Biceps"),
    (r"\bshoulders?\s*(?:and|&)\s*abs\b", "Shoulders and Abs"),
    (r"\barms?\b", "Arms"),
    (r"\blegs?\b", "Legs"),
    (r"\bupper[\s-]*body\b", "Upper Body"),
    (r"\bfull[\s-]*body\b", "Full Body"),
    (r"\bcardio\b", "Cardio"),
)
CUSTOM_WORKOUT_COMPONENTS = (
    (r"\bchest\b", "CHEST", "Chest"),
    (r"\btriceps?\b", "TRICEPS", "Triceps"),
    (r"\bback\b", "BACK", "Back"),
    (r"\bbiceps?\b", "BICEPS", "Biceps"),
    (r"\bshoulders?\b", "SHOULDERS", "Shoulders"),
    (r"\babs?\b", "ABS", "Abs"),
    (r"\blegs?\b", "LEGS", "Legs"),
    (r"\bcardio\b", "CARDIO", "Cardio"),
)
DEFAULT_CUSTOM_DURATION_CHOICES = (20, 30, 45, 60)
DEFAULT_ASSIGNED_WORKOUT_DURATION_MINUTES = 60
BATCH_ACTION_LIMIT = 3
_BATCH_REQUEST_SPLIT_PATTERN = re.compile(
    r"(?:\s*(?:;|\n+|[.!?]+)\s*|\s+(?:and then|then|also|and|&)\s+)(?=(?:please\s+)?(?:swap|switch|cancel|reschedule|schedule|book|assign|move|delete|remove|complete|mark)\b)",
    flags=re.IGNORECASE,
)


def _load_app_module():
    return importlib.import_module("app")


def _coerce_int(value: Any) -> int | None:
    try:
        if value in (None, ""):
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _coerce_float(value: Any) -> float | None:
    try:
        if value in (None, ""):
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return re.sub(r"\s+", " ", str(value)).strip()


def _format_duration_seconds(total_seconds: Any) -> str | None:
    numeric = _coerce_float(total_seconds)
    if numeric is None:
        return None
    total = int(round(numeric))
    if total < 0:
        return None
    minutes = total // 60
    seconds = total % 60
    return f"{minutes}:{seconds:02d}"


def _format_metric_display(value_mode: str, value: Any) -> str | None:
    numeric = _coerce_float(value)
    if numeric is None:
        return None
    if value_mode == "time_hold":
        return _format_duration_seconds(numeric)
    if value_mode == "cardio":
        rounded = str(int(round(numeric))) if abs(numeric - round(numeric)) < 0.01 else f"{numeric:.1f}".rstrip("0").rstrip(".")
        return f"{rounded} min"
    if value_mode == "bodyweight_reps":
        return f"{int(round(numeric))} reps"
    rounded = str(int(round(numeric))) if abs(numeric - round(numeric)) < 0.01 else f"{numeric:.1f}".rstrip("0").rstrip(".")
    return f"{rounded} lbs"


def _missing_metric_display(value_mode: str) -> str:
    if value_mode in {"cardio", "time_hold"}:
        return "No best time yet"
    if value_mode == "bodyweight_reps":
        return "No best reps yet"
    return "No EST. 1RM yet"


def _normalize_role(user_row: dict | None) -> str:
    return (_normalize_text((user_row or {}).get("role")) or "user").lower()


def _tzinfo_from_page(page_context: dict | None) -> timezone | ZoneInfo:
    page_context = page_context or {}
    timezone_name = _normalize_text(page_context.get("timezone"))
    if timezone_name:
        try:
            return ZoneInfo(timezone_name)
        except Exception:
            pass
    return datetime.now().astimezone().tzinfo or timezone.utc


def _parse_local_date(raw_value: str | None, page_context: dict | None) -> date:
    tz_info = _tzinfo_from_page(page_context)
    if not raw_value:
        return datetime.now(tz_info).date()
    cleaned = re.sub(r"(\d{1,2})(st|nd|rd|th)\b", r"\1", _normalize_text(raw_value), flags=re.IGNORECASE)
    candidate_formats = (
        "%Y-%m-%d",
        "%m/%d/%Y",
        "%m/%d/%y",
        "%B %d, %Y",
        "%B %d %Y",
        "%b %d, %Y",
        "%b %d %Y",
    )
    for fmt in candidate_formats:
        try:
            return datetime.strptime(cleaned, fmt).date()
        except ValueError:
            continue
    current_year = datetime.now(tz_info).year
    yearless_formats = (
        "%m/%d",
        "%B %d",
        "%b %d",
    )
    for fmt in yearless_formats:
        try:
            parsed = datetime.strptime(cleaned, fmt).date()
            return parsed.replace(year=current_year)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(cleaned).date()
    except ValueError as exc:
        raise ValueError("Use a date like 2026-03-31 or March 31, 2026.") from exc


def _day_bounds(target_day: date, page_context: dict | None) -> tuple[datetime, datetime]:
    tz_info = _tzinfo_from_page(page_context)
    start_local = datetime.combine(target_day, time.min).replace(tzinfo=tz_info)
    end_local = start_local + timedelta(days=1)
    return start_local.astimezone(timezone.utc), end_local.astimezone(timezone.utc)


def _date_range_bounds(start_day: date, end_day_exclusive: date, page_context: dict | None) -> tuple[datetime, datetime]:
    tz_info = _tzinfo_from_page(page_context)
    start_local = datetime.combine(start_day, time.min).replace(tzinfo=tz_info)
    end_local = datetime.combine(end_day_exclusive, time.min).replace(tzinfo=tz_info)
    return start_local.astimezone(timezone.utc), end_local.astimezone(timezone.utc)


def _start_of_week(target_day: date) -> date:
    return target_day - timedelta(days=target_day.weekday())


def _start_of_month(target_day: date) -> date:
    return date(target_day.year, target_day.month, 1)


def _start_of_year(target_day: date) -> date:
    return date(target_day.year, 1, 1)


def _last_day_of_month(year: int, month: int) -> int:
    if month == 12:
        next_month = date(year + 1, 1, 1)
    else:
        next_month = date(year, month + 1, 1)
    return (next_month - timedelta(days=1)).day


def _add_months(target_day: date, months: int) -> date:
    month_index = (target_day.year * 12 + (target_day.month - 1)) + months
    year = month_index // 12
    month = month_index % 12 + 1
    day = min(target_day.day, _last_day_of_month(year, month))
    return date(year, month, day)


def _add_years(target_day: date, years: int) -> date:
    year = target_day.year + years
    day = min(target_day.day, _last_day_of_month(year, target_day.month))
    return date(year, target_day.month, day)


def _parse_agent_datetime(raw_value: str | None, page_context: dict | None, *, field: str) -> datetime:
    cleaned = _normalize_text(raw_value)
    if not cleaned:
        raise ValueError(f"Missing {field}.")
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", cleaned):
        raise ValueError(f"{field.title()} needs a time, not just a date.")
    try:
        parsed = datetime.fromisoformat(cleaned.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"Invalid {field}. Use ISO 8601 like 2026-03-31T10:00:00-05:00.") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_tzinfo_from_page(page_context))
    parsed = parsed.astimezone(timezone.utc).replace(second=0, microsecond=0)
    if parsed.minute % 15 != 0:
        raise ValueError("Times must align to 15-minute increments.")
    return parsed


def _format_person_name(row: dict | None) -> str:
    row = row or {}
    primary_name = _normalize_text(row.get("name")) or _normalize_text(row.get("client_name")) or _normalize_text(row.get("trainer_name"))
    primary_last_name = _normalize_text(row.get("last_name")) or _normalize_text(row.get("client_last_name")) or _normalize_text(row.get("trainer_last_name"))
    pieces = [primary_name, primary_last_name]
    full = " ".join(piece for piece in pieces if piece)
    return (
        full
        or _normalize_text(row.get("username"))
        or _normalize_text(row.get("client_username"))
        or _normalize_text(row.get("trainer_username"))
        or "Unknown"
    )


def _format_time_range(start_dt: datetime | None, end_dt: datetime | None, page_context: dict | None) -> str | None:
    if not start_dt:
        return None
    tz_info = _tzinfo_from_page(page_context)
    local_start = start_dt.astimezone(tz_info)
    if not end_dt:
        return local_start.strftime("%b %-d, %Y at %-I:%M %p")
    local_end = end_dt.astimezone(tz_info)
    return f"{local_start.strftime('%b %-d, %Y')} from {local_start.strftime('%-I:%M %p')} to {local_end.strftime('%-I:%M %p')}"


def _format_time_range_with_weekday(start_dt: datetime | None, end_dt: datetime | None, page_context: dict | None) -> str | None:
    if not start_dt:
        return None
    tz_info = _tzinfo_from_page(page_context)
    local_start = start_dt.astimezone(tz_info)
    if not end_dt:
        return local_start.strftime("%a, %b %-d, %Y at %-I:%M %p")
    local_end = end_dt.astimezone(tz_info)
    return f"{local_start.strftime('%a, %b %-d, %Y')} from {local_start.strftime('%-I:%M %p')} to {local_end.strftime('%-I:%M %p')}"


def _format_clock_label(dt: datetime | None, page_context: dict | None) -> str | None:
    if not dt:
        return None
    return dt.astimezone(_tzinfo_from_page(page_context)).strftime("%-I:%M %p")


def _format_date_label(dt: datetime | None, page_context: dict | None) -> str | None:
    if not dt:
        return None
    return dt.astimezone(_tzinfo_from_page(page_context)).strftime("%b %-d, %Y")


def _format_time_window_label(start_dt: datetime | None, end_dt: datetime | None, page_context: dict | None) -> str | None:
    if not start_dt:
        return None
    tz_info = _tzinfo_from_page(page_context)
    local_start = start_dt.astimezone(tz_info)
    if not end_dt:
        return local_start.strftime("%-I:%M %p")
    local_end = end_dt.astimezone(tz_info)
    return f"{local_start.strftime('%-I:%M %p')} - {local_end.strftime('%-I:%M %p')}"


def _indefinite_article(label: str | None) -> str:
    cleaned = _normalize_text(label)
    if not cleaned:
        return "A"
    return "An" if cleaned[0].lower() in {"a", "e", "i", "o", "u"} else "A"


def _format_reschedule_summary(
    old_start: datetime | None,
    old_end: datetime | None,
    new_start: datetime | None,
    new_end: datetime | None,
    page_context: dict | None,
) -> str:
    old_slot = _format_time_range_with_weekday(old_start, old_end, page_context)
    new_slot = _format_time_range_with_weekday(new_start, new_end, page_context)
    if old_slot and new_slot:
        return f"Move the session currently set for {old_slot}.\nNew session time: {new_slot}."
    return f"Move the session from {_format_time_window_label(old_start, old_end, page_context)} to {_format_time_window_label(new_start, new_end, page_context)}."


def _format_reschedule_result_message(
    client_row: dict,
    old_start: datetime | None,
    old_end: datetime | None,
    new_start: datetime | None,
    new_end: datetime | None,
    page_context: dict | None,
) -> str:
    client_name = _format_person_name(client_row)
    old_slot = _format_time_range_with_weekday(old_start, old_end, page_context)
    new_slot = _format_time_range_with_weekday(new_start, new_end, page_context)
    if old_slot and new_slot:
        return f"Moved {client_name}'s session from {old_slot}.\nNew session time: {new_slot}."
    return (
        f"Moved {client_name}'s session from "
        f"{_format_time_window_label(old_start, old_end, page_context)} "
        f"to {_format_time_window_label(new_start, new_end, page_context)}."
    )


def _format_swap_summary(
    first_client_row: dict,
    first_start: datetime | None,
    first_end: datetime | None,
    second_client_row: dict,
    second_start: datetime | None,
    second_end: datetime | None,
    page_context: dict | None,
) -> str:
    first_client_name = _format_person_name(first_client_row)
    second_client_name = _format_person_name(second_client_row)
    first_slot = _format_time_range(first_start, first_end, page_context)
    second_slot = _format_time_range(second_start, second_end, page_context)
    if first_client_row.get("id") == second_client_row.get("id"):
        return f"Swap {first_client_name}'s session on {first_slot} with the session on {second_slot}."
    return f"Swap {first_client_name}'s session on {first_slot} with {second_client_name}'s session on {second_slot}."


def _format_swap_result_message(
    first_client_row: dict,
    first_start: datetime | None,
    first_end: datetime | None,
    second_client_row: dict,
    second_start: datetime | None,
    second_end: datetime | None,
    page_context: dict | None,
) -> str:
    first_client_name = _format_person_name(first_client_row)
    second_client_name = _format_person_name(second_client_row)
    first_slot = _format_time_range(first_start, first_end, page_context)
    second_slot = _format_time_range(second_start, second_end, page_context)
    if first_client_row.get("id") == second_client_row.get("id"):
        return f"Swapped {first_client_name}'s session on {first_slot} with the session on {second_slot}."
    return f"Swapped {first_client_name}'s session on {first_slot} with {second_client_name}'s session on {second_slot}."


def _format_booking_result_message(
    client_row: dict,
    result_row: dict[str, Any] | None,
    page_context: dict | None,
    *,
    workout_message: str | None = None,
) -> str:
    client_name = _format_person_name(client_row)
    result_row = result_row or {}
    start_dt = _coerce_datetime_value(result_row.get("start_time"))
    end_dt = _coerce_datetime_value(result_row.get("end_time"))
    slot_label = _format_time_range_with_weekday(start_dt, end_dt, page_context)
    base_message = f"Booked {client_name} on {slot_label}." if slot_label else f"Booked {client_name}."
    if workout_message:
        return f"{base_message}{workout_message}"
    return base_message


def _coerce_datetime_value(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    cleaned = _normalize_text(value)
    if not cleaned:
        return None
    try:
        parsed = datetime.fromisoformat(cleaned.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _format_status_result_message(
    client_row: dict,
    result_row: dict[str, Any] | None,
    page_context: dict | None,
    target_status: str,
    *,
    logged_workout_label: str | None = None,
    session_log_error: str | None = None,
) -> str:
    client_name = _format_person_name(client_row)
    result_row = result_row or {}
    start_dt = _coerce_datetime_value(result_row.get("start_time"))
    end_dt = _coerce_datetime_value(result_row.get("end_time"))
    slot_label = _format_time_range(start_dt, end_dt, page_context)
    if target_status == "completed":
        base_message = (
            f"Marked {client_name}'s session on {slot_label} as completed."
            if slot_label
            else f"Marked {client_name}'s session as completed."
        )
        if logged_workout_label:
            return f"{base_message} {_indefinite_article(logged_workout_label)} {logged_workout_label} workout was logged for this session."
        if session_log_error:
            return f"{base_message} No workout was logged for this session."
        return base_message
    if target_status == "cancelled":
        return f"Marked {client_name}'s session on {slot_label} as cancelled." if slot_label else f"Marked {client_name}'s session as cancelled."
    if target_status == "booked":
        return f"Marked {client_name}'s session on {slot_label} as booked." if slot_label else f"Marked {client_name}'s session as booked."
    if target_status == "deleted":
        return f"Deleted {client_name}'s session on {slot_label} from the calendar." if slot_label else f"Deleted {client_name}'s session from the calendar."
    return f"Updated {client_name}'s session." if not slot_label else f"Updated {client_name}'s session on {slot_label}."


def _format_workout_optimization_message(
    client_row: dict,
    *,
    target_scope: str,
    page_context: dict | None,
    start_dt: datetime | None = None,
    end_dt: datetime | None = None,
    changed: bool = True,
) -> str:
    client_name = _format_person_name(client_row)
    if target_scope == "session":
        slot_label = _format_time_range_with_weekday(start_dt, end_dt, page_context)
        if changed:
            if slot_label:
                return f"Organized {client_name}'s workout on {slot_label}."
            return f"Organized {client_name}'s workout."
        if slot_label:
            return f"{client_name}'s workout on {slot_label} is already organized."
        return f"{client_name}'s workout is already organized."
    if changed:
        return f"Organized {client_name}'s workout."
    return f"{client_name}'s workout is already organized."


def _load_user_row(user_id: int) -> dict | None:
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT id,
                       role,
                       username,
                       name,
                       last_name,
                       email,
                       trainer_id,
                       subscription_type,
                       status,
                       trial_end_date,
                       sessions_remaining,
                       sessions_booked,
                       workouts_completed,
                       last_workout_completed,
                       exercise_history,
                       workout_duration,
                       created_at,
                       last_login_at,
                       subscription_cancel_at,
                       gym_id,
                       gym_catalog_preference
                  FROM users
                 WHERE id = %s
                """,
                (user_id,),
            )
            return cursor.fetchone()


def _resolve_client_row(
    cursor,
    actor_row: dict,
    *,
    client_id: int | None = None,
    client_name: str | None = None,
    page_context: dict | None = None,
) -> tuple[dict | None, str | None]:
    role = _normalize_role(actor_row)
    if role == "user":
        if client_id and client_id != actor_row.get("id"):
            return None, "Members can only access their own data."
        return actor_row, None

    resolved_client_id = client_id or _coerce_int((page_context or {}).get("selected_client_id"))
    if resolved_client_id:
        if resolved_client_id == actor_row.get("id"):
            return actor_row, None
        if role == "trainer":
            app_module = _load_app_module()
            link_row = app_module._ensure_trainer_client_link(cursor, actor_row["id"], resolved_client_id, role)
            if not link_row:
                return None, "That client is not linked to your roster."
        cursor.execute(
            """
            SELECT id,
                   role,
                   username,
                   name,
                   last_name,
                   email,
                   trainer_id,
                   subscription_type,
                   status,
                   trial_end_date,
                   sessions_remaining,
                   sessions_booked,
                   workouts_completed,
                   last_workout_completed,
                   exercise_history,
                   workout_duration,
                   created_at,
                   last_login_at,
                   subscription_cancel_at
              FROM users
             WHERE id = %s
            """,
            (resolved_client_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None, "Client not found."
        return row, None

    cleaned_name = _normalize_text(client_name)
    if not cleaned_name:
        return None, "Client context is required."

    params = [f"%{cleaned_name}%"] * 4
    query = [
        """
        SELECT id,
               role,
               username,
               name,
               last_name,
               email,
               trainer_id,
               subscription_type,
               status,
               trial_end_date,
               sessions_remaining,
               sessions_booked,
               workouts_completed,
               last_workout_completed,
               exercise_history,
               workout_duration,
               created_at,
               last_login_at,
               subscription_cancel_at
          FROM users
         WHERE (
                username ILIKE %s
                OR name ILIKE %s
                OR last_name ILIKE %s
                OR (COALESCE(name, '') || ' ' || COALESCE(last_name, '')) ILIKE %s
         )
        """
    ]
    if role == "trainer":
        query.append("AND trainer_id = %s")
        params.append(actor_row["id"])
    query.append("ORDER BY name NULLS LAST, last_name NULLS LAST, username LIMIT 3")
    cursor.execute("\n".join(query), params)
    rows = cursor.fetchall() or []
    if not rows:
        return None, "No matching client was found."
    if len(rows) > 1:
        labels = ", ".join(_format_person_name(row) for row in rows)
        return None, f"That matches multiple clients: {labels}. Be more specific."
    return rows[0], None


def _resolve_target_user_for_lookup(
    metric_key: str,
    arguments: dict[str, Any],
    actor_row: dict,
    page_context: dict | None,
) -> tuple[dict | None, str | None]:
    actor_role = _normalize_role(actor_row)
    if metric_key in {"trainer_top_sessions_this_month", "new_users_this_month", "platform_summary", "risk_flags_summary"}:
        if actor_role != "admin":
            return None, "Only admins can access that platform-wide metric."
        return actor_row, None
    if metric_key in {"today_schedule", "schedule_window_summary", "next_session"}:
        explicit_client_id = _coerce_int(arguments.get("client_id"))
        explicit_client_name = _normalize_text(arguments.get("client_name"))
        selected_client_id = _coerce_int((page_context or {}).get("selected_client_id"))
        if not explicit_client_id and not explicit_client_name and not selected_client_id:
            return actor_row, None
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            client_row, error = _resolve_client_row(
                cursor,
                actor_row,
                client_id=_coerce_int(arguments.get("client_id")),
                client_name=arguments.get("client_name"),
                page_context=page_context,
            )
            return client_row, error


def _message_refers_to_actor_self(message_text: str) -> bool:
    lowered = f" {_normalize_text(message_text).lower()} "
    return any(token in lowered for token in (" my ", " me ", " my own "))


def _extract_one_rep_max_exercise_query(message_text: str, actor_row: dict, page_context: dict | None) -> str | None:
    normalized = _normalize_text(message_text)
    if not normalized:
        return None

    patterns = (
        r"\bbest time\b\s*(?:for|of|on)\s+(.+?)[?.!]*$",
        r"\b(?:est(?:imated)?\.?\s*)?1rm\b\s*(?:for|of|on)\s+(.+?)[?.!]*$",
        r"\bone[\s-]?rep max\b\s*(?:for|of|on)\s+(.+?)[?.!]*$",
        r"\bmax\b\s*(?:for|of|on)\s+(.+?)[?.!]*$",
        r"\bpr\b\s*(?:for|of|on)\s+(.+?)[?.!]*$",
        r"\bpersonal record\b\s*(?:for|of|on)\s+(.+?)[?.!]*$",
        r"\brecord\b\s*(?:for|of|on)\s+(.+?)[?.!]*$",
        r"\bmax time\b\s*(?:for|of|on)\s+(.+?)[?.!]*$",
        r"\bmax\b\s+(?!for\b|of\b|on\b)(.+?)[?.!]*$",
        r"\bpr\b\s+(?!for\b|of\b|on\b)(.+?)[?.!]*$",
        r"\bpersonal record\b\s+(?!for\b|of\b|on\b)(.+?)[?.!]*$",
        r"\brecord\b\s+(?!for\b|of\b|on\b)(.+?)[?.!]*$",
        r"\bbest time\b\s+(?!for\b|of\b|on\b)(.+?)[?.!]*$",
        r"\bmax time\b\s+(?!for\b|of\b|on\b)(.+?)[?.!]*$",
        r"\b(.+?)\s+\bbest time\b[?.!]*$",
        r"\b(.+?)\s+\b(?:est(?:imated)?\.?\s*)?1rm\b[?.!]*$",
        r"\b(.+?)\s+\bone[\s-]?rep max\b[?.!]*$",
        r"\b(.+?)\s+\bmax\b[?.!]*$",
        r"\b(.+?)\s+\bpr\b[?.!]*$",
        r"\b(.+?)\s+\bpersonal record\b[?.!]*$",
        r"\b(.+?)\s+\brecord\b[?.!]*$",
    )

    captured = None
    for pattern in patterns:
        match = re.search(pattern, normalized, flags=re.IGNORECASE)
        if match:
            captured = _normalize_text(match.group(1))
            break

    if not captured:
        return None

    target_row = _match_client_from_message(actor_row, message_text, page_context)
    removable_tokens = [
        _format_person_name(actor_row),
        _normalize_text(actor_row.get("username")),
        _normalize_text(actor_row.get("name")),
        _normalize_text(actor_row.get("last_name")),
    ]
    if target_row:
        removable_tokens.extend(
            [
                _format_person_name(target_row),
                _normalize_text(target_row.get("username")),
                _normalize_text(target_row.get("name")),
                _normalize_text(target_row.get("last_name")),
            ]
        )
    for token in removable_tokens:
        if not token:
            continue
        captured = re.sub(
            r"(?<!\w)" + re.escape(token) + r"(?:'s|s)?(?!\w)",
            " ",
            captured,
            flags=re.IGNORECASE,
        )

    captured = re.sub(
        r"\b(?:what(?:'s| is)?|show|tell|give|pull|get|me|my|latest|current|estimated|est|max|1rm|one[\s-]?rep max|pr|personal record|record|best|time|minute|minutes|min|mins|second|seconds|sec|secs|for|of|on)\b",
        " ",
        captured,
        flags=re.IGNORECASE,
    )
    captured = re.sub(r"\b(?:the|a|an)\b", " ", captured, flags=re.IGNORECASE)
    captured = _normalize_text(captured.strip(" ?.!,:;"))
    return captured or None


def _message_likely_is_exercise_query(message_text: str) -> bool:
    normalized = _normalize_text(message_text)
    if not normalized:
        return False
    if re.search(
        r"\b(1rm|one[\s-]?rep max|schedule|reschedule|swap|book|cancel|complete|delete|assign|session|calendar|workout|organize|reorganize|optimize|rearrange|group|efficient|efficiency)\b",
        normalized,
        flags=re.IGNORECASE,
    ):
        return False
    return len(re.findall(r"[A-Za-z0-9]+", normalized)) >= 2


def _latest_prior_user_message(recent_history: list[dict[str, str]] | None, current_message: str) -> str | None:
    if not recent_history:
        return None
    normalized_current = _normalize_text(current_message)
    seen_current = False
    for entry in reversed(recent_history):
        if entry.get("role") != "user":
            continue
        content = _normalize_text(entry.get("content"))
        if not seen_current and content == normalized_current:
            seen_current = True
            continue
        if content:
            return content
    return None


def _compute_search_result_metric(row: dict[str, Any]) -> dict[str, Any]:
    app_module = _load_app_module()
    workout_name = _normalize_text(row.get("name"))
    category_label = _normalize_text(row.get("category"))
    is_cardio = category_label.lower() == "cardio"
    is_time_hold = app_module._is_plank_exercise(workout_name)
    is_bodyweight_name = app_module._is_bodyweight_exercise(workout_name)

    max_weight = _coerce_float(row.get("max_weight"))
    max_reps = _coerce_float(row.get("max_reps"))
    value_mode = "strength"
    metric_value = None
    est_one_rm = None

    if is_cardio:
        value_mode = "cardio"
        metric_value = max_reps
    elif is_time_hold:
        value_mode = "time_hold"
        metric_value = int(round(max_reps)) if max_reps is not None else None
    elif is_bodyweight_name:
        value_mode = "bodyweight_reps"
        metric_value = int(round(max_reps)) if max_reps is not None else None
    else:
        est_one_rm = app_module._estimate_one_rep_max(max_weight, max_reps)
        metric_value = est_one_rm

    metric_display = _format_metric_display(value_mode, metric_value)
    return {
        "value_mode": value_mode,
        "metric_value": metric_value,
        "metric_display": metric_display,
        "estimated_one_rep_max": est_one_rm,
        "estimated_one_rep_max_display": metric_display if value_mode == "strength" else None,
    }


def _normalize_exercise_name_for_match(value: str | None) -> str:
    cleaned = _normalize_text(value).lower()
    if not cleaned:
        return ""
    cleaned = re.sub(r"[^a-z0-9]+", " ", cleaned)
    cleaned = re.sub(r"\b(?:the|a|an)\b", " ", cleaned)
    cleaned = re.sub(r"\bpull\s*ups?\b", "pullup", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\bpush\s*ups?\b", "pushup", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\bchin\s*ups?\b", "chinup", cleaned, flags=re.IGNORECASE)
    return _normalize_text(cleaned)


def _search_workout_results_for_one_rep_max(target_row: dict, actor_row: dict, exercise_query: str) -> list[dict[str, Any]]:
    app_module = _load_app_module()
    search_query = re.sub(r"\bpull[\s-]*ups?\b", "pull up", _normalize_text(exercise_query), flags=re.IGNORECASE)
    search_query = re.sub(r"\bpush[\s-]*ups?\b", "push up", search_query, flags=re.IGNORECASE)
    search_query = re.sub(r"\bchin[\s-]*ups?\b", "chin up", search_query, flags=re.IGNORECASE)
    name_clause, name_params = app_module._build_name_search_clause(search_query)
    if not name_params:
        return []
    catalog_mode, catalog_gym_id = app_module._catalog_scope_from_user_row(actor_row)
    catalog_clause, catalog_params = app_module._catalog_filter_sql("w", catalog_mode, catalog_gym_id)

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                f"""
                SELECT w.id AS workout_id,
                       w.name,
                       w.description,
                       w.category,
                       uep.max_weight,
                       uep.max_reps,
                       uep.notes
                  FROM workouts w
             LEFT JOIN user_exercise_progress uep
                    ON uep.workout_id = w.id
                   AND uep.user_id = %s
                 WHERE {name_clause}
                   AND {catalog_clause}
                 ORDER BY CASE w.movement_type
                              WHEN 'compound' THEN 1
                              WHEN 'accessory' THEN 2
                              ELSE 3
                          END,
                          w.name
                 LIMIT 25
                """,
                (target_row["id"], *name_params, *catalog_params),
            )
            rows = cursor.fetchall() or []

    enriched_rows: list[dict[str, Any]] = []
    for row in rows:
        metric_info = _compute_search_result_metric(row)
        enriched_rows.append(
            {
                **row,
                **metric_info,
            }
        )
    return enriched_rows


def _build_estimated_one_rep_max_reply_options(
    actor_row: dict,
    target_row: dict,
    matches: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    options: list[dict[str, Any]] = []
    target_name = _format_person_name(target_row)
    for row in matches[:3]:
        workout_name = _normalize_text(row.get("name"))
        if not workout_name:
            continue
        options.append(
            {
                "kind": "exercise_detail",
                "label": workout_name,
                "metric_label": row.get("metric_display") or _missing_metric_display(row.get("value_mode") or "strength"),
                "workout_id": row.get("workout_id") or row.get("id"),
                "target_user_id": target_row.get("id"),
                "target_name": target_name,
            }
        )
    return options


def _lookup_estimated_one_rep_max(target_row: dict, arguments: dict[str, Any], actor_row: dict) -> dict[str, Any]:
    exercise_query = _normalize_text(arguments.get("exercise_query"))
    if not exercise_query:
        return {"success": False, "error": "Ask for an exercise name to calculate estimated 1RM."}
    results = _search_workout_results_for_one_rep_max(target_row, actor_row, exercise_query)
    target_name = _format_person_name(target_row)
    normalized_query = _normalize_exercise_name_for_match(exercise_query)

    if not results:
        return {
            "success": False,
            "error": f"No exercise results were found for {exercise_query} for {target_name}.",
        }

    exact_matches = [
        row
        for row in results
        if _normalize_exercise_name_for_match(row.get("name")) == normalized_query
    ]
    if len(exact_matches) == 1:
        results = exact_matches

    if len(results) == 1:
        row = results[0]
        metric_display = row.get("metric_display")
        detail_options = _build_estimated_one_rep_max_reply_options(actor_row, target_row, [row])
        if not metric_display:
            return {
                "success": False,
                "error": f"I found the exact match below for {target_name}. Select it for more details.",
                "reply_options": detail_options,
            }
        return {
            "success": True,
            "metric_key": "estimated_one_rep_max",
            "target_user_id": target_row["id"],
            "target_name": target_name,
            "exercise_name": row.get("name"),
            "exercise_query": exercise_query,
            "estimated_one_rep_max_display": row.get("estimated_one_rep_max_display"),
            "metric_display": metric_display,
            "value_mode": row.get("value_mode") or "strength",
            "metric_value": row.get("metric_value"),
            "best_estimated_one_rep_max": row.get("estimated_one_rep_max"),
            "best_entry": row,
            "reply_options": detail_options,
        }

    if len(results) <= 3:
        return {
            "success": False,
            "error": (
                f"I found multiple likely matches for {target_name}. "
                "Select one below for more details."
            ),
            "reply_options": _build_estimated_one_rep_max_reply_options(actor_row, target_row, results),
        }

    preview_rows = results[:3]
    return {
        "success": False,
        "error": (
            f"I found several likely matches for {target_name}. "
            "Select one below for more details, or be more specific."
        ),
        "reply_options": _build_estimated_one_rep_max_reply_options(actor_row, target_row, preview_rows),
    }


def _lookup_most_tracked_workout(target_row: dict) -> dict[str, Any]:
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT w.id AS workout_id,
                       w.name AS workout_name,
                       w.category,
                       COUNT(*)::int AS tracked_count,
                       MAX(h.recorded_at) AS last_tracked_at
                  FROM user_exercise_history h
                  JOIN workouts w
                    ON w.id = h.workout_id
                 WHERE h.user_id = %s
                 GROUP BY w.id, w.name, w.category
                 ORDER BY tracked_count DESC, last_tracked_at DESC, w.name ASC
                 LIMIT 1
                """,
                (target_row["id"],),
            )
            row = cursor.fetchone()

    if not row:
        return {"success": False, "error": "No tracked workout history was found yet."}

    return {
        "success": True,
        "metric_key": "most_tracked_workout",
        "target_user_id": target_row["id"],
        "target_name": _format_person_name(target_row),
        "workout_name": row.get("workout_name"),
        "category": row.get("category"),
        "tracked_count": row.get("tracked_count"),
        "last_tracked_at": row.get("last_tracked_at").isoformat() if row.get("last_tracked_at") else None,
    }


def _query_schedule_rows(
    *,
    actor_row: dict,
    target_row: dict | None,
    start_dt: datetime,
    end_dt: datetime,
    next_only: bool = False,
) -> list[dict]:
    actor_role = _normalize_role(actor_row)
    target_user_id = (target_row or actor_row).get("id")
    params: list[Any] = [end_dt, start_dt]
    where_clauses = ["ts.start_time < %s", "ts.end_time > %s"]
    join_clause = "JOIN users c ON c.id = ts.client_id JOIN users t ON t.id = ts.trainer_id"
    select_clause = """
        SELECT ts.id,
               ts.trainer_id,
               ts.client_id,
               ts.start_time,
               ts.end_time,
               ts.status,
               ts.note,
               ts.session_category,
               ts.session_id,
               ts.session_completed_at,
               ts.is_self_booked,
               c.name AS client_name,
               c.last_name AS client_last_name,
               c.username AS client_username,
               t.name AS trainer_name,
               t.last_name AS trainer_last_name,
               t.username AS trainer_username
          FROM trainer_schedule ts
    """

    if actor_role == "user":
        where_clauses.append("ts.client_id = %s")
        params.append(actor_row["id"])
    elif target_row and target_row.get("id") != actor_row.get("id"):
        where_clauses.append("ts.client_id = %s")
        params.append(target_user_id)
        if actor_role == "trainer":
            where_clauses.append("ts.trainer_id = %s")
            params.append(actor_row["id"])
    else:
        where_clauses.append("ts.trainer_id = %s")
        params.append(actor_row["id"])

    limit_clause = "LIMIT 1" if next_only else ""
    order_clause = "ORDER BY ts.start_time ASC"
    query = f"""
        {select_clause}
        {join_clause}
         WHERE {' AND '.join(where_clauses)}
        {order_clause}
        {limit_clause}
    """
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(query, params)
            return cursor.fetchall() or []


def _resolve_schedule_event_row(
    cursor,
    *,
    actor_row: dict,
    client_row: dict,
    action_type: str,
    arguments: dict[str, Any],
    page_context: dict | None,
) -> tuple[dict | None, str | None]:
    actor_role = _normalize_role(actor_row)
    event_id = _coerce_int(arguments.get("event_id"))
    if event_id:
        cursor.execute(
            """
            SELECT id,
                   trainer_id,
                   client_id,
                   start_time,
                   end_time,
                   status,
                   note,
                   session_category,
                   session_payload
              FROM trainer_schedule
             WHERE id = %s
            """,
            (event_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None, "Scheduled session not found."
        if actor_role != "admin" and row.get("trainer_id") != actor_row.get("id"):
            return None, "You do not have access to that scheduled session."
        if row.get("client_id") != client_row.get("id"):
            return None, "That scheduled session belongs to a different client."
        return row, None

    target_date_raw = arguments.get("target_date")
    start_time_raw = arguments.get("source_start_time") or arguments.get("start_time")
    target_day = None
    explicit_start_dt = None
    if start_time_raw:
        try:
            explicit_start_dt = _parse_agent_datetime(start_time_raw, page_context, field="start time")
            target_day = explicit_start_dt.astimezone(_tzinfo_from_page(page_context)).date()
        except ValueError:
            explicit_start_dt = None
    if target_day is None and target_date_raw:
        try:
            target_day = _parse_local_date(target_date_raw, page_context)
        except ValueError as exc:
            return None, str(exc)
    if target_day is None:
        return None, "I need the session date or a specific session to do that."

    start_window, end_window = _day_bounds(target_day, page_context)
    params: list[Any] = [client_row["id"], start_window, end_window]
    trainer_clause = ""
    if actor_role != "admin":
        trainer_clause = " AND trainer_id = %s"
        params.append(actor_row["id"])
    include_cancelled = action_type in {"delete_session", "set_session_booked"}
    cancelled_clause = "" if include_cancelled else " AND status <> 'cancelled'"

    cursor.execute(
        f"""
        SELECT id,
               trainer_id,
               client_id,
               start_time,
               end_time,
               status,
               note,
               session_category,
               session_payload
          FROM trainer_schedule
         WHERE client_id = %s
           AND start_time >= %s
           AND start_time < %s
           {trainer_clause}
           {cancelled_clause}
         ORDER BY start_time ASC
        """,
        params,
    )
    rows = cursor.fetchall() or []
    if explicit_start_dt:
        rows = [row for row in rows if row.get("start_time") == explicit_start_dt]
    if action_type in {"cancel_session", "reschedule_session", "assign_workout", "complete_session"}:
        booked_rows = [row for row in rows if (row.get("status") or "").lower() == "booked"]
        if booked_rows:
            rows = booked_rows
    elif action_type == "set_session_booked":
        non_booked_rows = [row for row in rows if (row.get("status") or "").lower() != "booked"]
        if non_booked_rows:
            rows = non_booked_rows

    if not rows:
        date_label = target_day.strftime("%b %-d, %Y")
        return None, f"No matching session was found for {_format_person_name(client_row)} on {date_label}."
    if len(rows) > 1:
        labels = ", ".join(_format_clock_label(row.get("start_time"), page_context) or row.get("start_time").isoformat() for row in rows[:4])
        return None, (
            f"I found multiple sessions for {_format_person_name(client_row)} on {target_day.isoformat()}: {labels}. "
            "Tell me which time you want."
        )
    return rows[0], None


def _lookup_today_schedule(actor_row: dict, target_row: dict, page_context: dict | None, arguments: dict[str, Any]) -> dict[str, Any]:
    target_day = _parse_local_date(arguments.get("target_date"), page_context)
    start_dt, end_dt = _day_bounds(target_day, page_context)
    rows = _query_schedule_rows(actor_row=actor_row, target_row=target_row, start_dt=start_dt, end_dt=end_dt)
    actor_role = _normalize_role(actor_row)
    is_self_schedule = target_row.get("id") == actor_row.get("id")
    if is_self_schedule and actor_role in {"trainer", "admin"}:
        rows = [row for row in rows if not row.get("is_self_booked")]
    rows = [row for row in rows if (_normalize_text(row.get("status")) or "booked").lower() != "cancelled"]
    tz_info = _tzinfo_from_page(page_context)
    today_local = datetime.now(tz_info).date()
    day_descriptor = "today"
    if target_day == today_local + timedelta(days=1):
        day_descriptor = "tomorrow"
    elif target_day == today_local - timedelta(days=1):
        day_descriptor = "yesterday"
    items = []
    for row in rows:
        counterpart = {
            "id": row.get("trainer_id") if target_row.get("id") == row.get("client_id") else row.get("client_id"),
            "name": row.get("trainer_name") if target_row.get("id") == row.get("client_id") else row.get("client_name"),
            "last_name": row.get("trainer_last_name") if target_row.get("id") == row.get("client_id") else row.get("client_last_name"),
            "username": row.get("trainer_username") if target_row.get("id") == row.get("client_id") else row.get("client_username"),
        }
        items.append(
            {
                "event_id": row.get("id"),
                "start_time": row.get("start_time").isoformat() if row.get("start_time") else None,
                "end_time": row.get("end_time").isoformat() if row.get("end_time") else None,
                "day_header_label": row.get("start_time").astimezone(tz_info).strftime("%A, %b %-d, %Y") if row.get("start_time") else None,
                "date_label": _format_date_label(row.get("start_time"), page_context),
                "time_label": _format_clock_label(row.get("start_time"), page_context),
                "time_range_label": _format_time_range(row.get("start_time"), row.get("end_time"), page_context),
                "time_window_label": _format_time_window_label(row.get("start_time"), row.get("end_time"), page_context),
                "status": row.get("status"),
                "note": row.get("note"),
                "session_category": row.get("session_category"),
                "counterpart_name": _format_person_name(counterpart),
            }
        )
    return {
        "success": True,
        "metric_key": "today_schedule",
        "target_user_id": target_row["id"],
        "target_name": _format_person_name(target_row),
        "target_date": target_day.isoformat(),
        "target_date_label": target_day.strftime("%a, %b %-d, %Y"),
        "target_day_descriptor": day_descriptor,
        "is_self_schedule": is_self_schedule,
        "items": items,
        "count": len(items),
    }


def _extract_schedule_window_key_from_message(message_text: str) -> str | None:
    lowered = _normalize_text(message_text).lower()
    if "yesterday" in lowered:
        return "yesterday"
    if "last week" in lowered:
        return "last_week"
    if any(token in lowered for token in ("this coming week", "coming week", "next week", "upcoming week")):
        return "next_week"
    if "this week" in lowered:
        return "this_week"
    if "next month" in lowered or "coming month" in lowered:
        return "next_month"
    if "last month" in lowered:
        return "last_month"
    if "this month" in lowered:
        return "this_month"
    if "next year" in lowered or "coming year" in lowered:
        return "next_year"
    if "last year" in lowered:
        return "last_year"
    if "this year" in lowered:
        return "this_year"
    if "tomorrow" in lowered:
        return "tomorrow"
    if "today" in lowered:
        return "today"
    return None


def _build_relative_schedule_range(
    message_text: str,
    page_context: dict | None,
) -> dict[str, Any] | None:
    lowered = _normalize_text(message_text).lower()
    tz_info = _tzinfo_from_page(page_context)
    today_local = datetime.now(tz_info).date()

    explicit_window_key = _extract_schedule_window_key_from_message(message_text)
    if explicit_window_key:
        return {"window_key": explicit_window_key}

    relative_match = re.search(
        r"\b(?P<direction>last|past|next)\s+(?P<count>\d+)\s+(?P<unit>days?|weeks?|months?|years?)\b",
        lowered,
    )
    if relative_match:
        direction = relative_match.group("direction")
        count = max(1, int(relative_match.group("count")))
        unit = relative_match.group("unit")

        if direction in {"last", "past"}:
            if unit.startswith("day"):
                start_day = today_local - timedelta(days=count - 1)
            elif unit.startswith("week"):
                start_day = today_local - timedelta(weeks=count)
            elif unit.startswith("month"):
                start_day = _add_months(today_local, -count)
            else:
                start_day = _add_years(today_local, -count)
            end_day_exclusive = today_local + timedelta(days=1)
        else:
            start_day = today_local
            if unit.startswith("day"):
                end_day_exclusive = today_local + timedelta(days=count)
            elif unit.startswith("week"):
                end_day_exclusive = today_local + timedelta(weeks=count)
            elif unit.startswith("month"):
                end_day_exclusive = _add_months(today_local, count)
            else:
                end_day_exclusive = _add_years(today_local, count)

        start_dt, end_dt = _date_range_bounds(start_day, end_day_exclusive, page_context)
        label = f"{direction} {count} {unit}"
        return {
            "window_start": start_dt.isoformat(),
            "window_end": end_dt.isoformat(),
            "window_label": label,
        }

    explicit_range_match = re.search(
        r"\bfrom\s+(?P<start>(?:\d{4}-\d{2}-\d{2})|(?:\d{1,2}/\d{1,2}/\d{2,4})|(?:[A-Za-z]{3,9}\s+\d{1,2}(?:st|nd|rd|th)?(?:,\s*\d{4})?))\s+to\s+(?P<end>(?:\d{4}-\d{2}-\d{2})|(?:\d{1,2}/\d{1,2}/\d{2,4})|(?:[A-Za-z]{3,9}\s+\d{1,2}(?:st|nd|rd|th)?(?:,\s*\d{4})?))\b",
        _normalize_text(message_text),
        flags=re.IGNORECASE,
    )
    if explicit_range_match:
        start_day = _parse_local_date(explicit_range_match.group("start"), page_context)
        end_day = _parse_local_date(explicit_range_match.group("end"), page_context)
        if end_day < start_day:
            start_day, end_day = end_day, start_day
        start_dt, end_dt = _date_range_bounds(start_day, end_day + timedelta(days=1), page_context)
        return {
            "window_start": start_dt.isoformat(),
            "window_end": end_dt.isoformat(),
            "window_label": f"from {start_day.strftime('%b %-d, %Y')} to {end_day.strftime('%b %-d, %Y')}",
        }

    return None


def _infer_schedule_status_scope(message_text: str) -> str:
    lowered = _normalize_text(message_text).lower()
    if any(token in lowered for token in ("cancelled", "canceled")):
        return "cancelled"
    if any(token in lowered for token in (
        "did i train with",
        "did i work out with",
        "did i workout with",
        "trained with",
        "worked out with",
        "workout with",
        "mark as completed",
        "marked completed",
        "completed session",
        "completed sessions",
    )):
        return "completed"
    if any(token in lowered for token in (
        "am i training with",
        "booked with",
        "sessions booked",
        "scheduled with",
        "upcoming session",
        "upcoming sessions",
    )):
        return "booked"
    return "active"


def _lookup_next_session(actor_row: dict, target_row: dict, page_context: dict | None) -> dict[str, Any]:
    now_utc = datetime.now(timezone.utc)
    end_dt = now_utc + timedelta(days=365)
    rows = _query_schedule_rows(actor_row=actor_row, target_row=target_row, start_dt=now_utc, end_dt=end_dt, next_only=True)
    if not rows:
        return {
            "success": False,
            "error": "No upcoming session was found.",
        }
    row = rows[0]
    counterpart = {
        "id": row.get("trainer_id") if target_row.get("id") == row.get("client_id") else row.get("client_id"),
        "name": row.get("trainer_name") if target_row.get("id") == row.get("client_id") else row.get("client_name"),
        "last_name": row.get("trainer_last_name") if target_row.get("id") == row.get("client_id") else row.get("client_last_name"),
        "username": row.get("trainer_username") if target_row.get("id") == row.get("client_id") else row.get("client_username"),
    }
    return {
        "success": True,
        "metric_key": "next_session",
        "target_user_id": target_row["id"],
        "target_name": _format_person_name(target_row),
        "event_id": row.get("id"),
        "start_time": row.get("start_time").isoformat() if row.get("start_time") else None,
        "end_time": row.get("end_time").isoformat() if row.get("end_time") else None,
        "status": row.get("status"),
        "session_category": row.get("session_category"),
        "counterpart_name": _format_person_name(counterpart),
        "time_label": _format_time_range(row.get("start_time"), row.get("end_time"), page_context),
    }


def _month_bounds(page_context: dict | None) -> tuple[datetime, datetime]:
    tz_info = _tzinfo_from_page(page_context)
    now_local = datetime.now(tz_info)
    start_local = datetime(now_local.year, now_local.month, 1, tzinfo=tz_info)
    if now_local.month == 12:
        end_local = datetime(now_local.year + 1, 1, 1, tzinfo=tz_info)
    else:
        end_local = datetime(now_local.year, now_local.month + 1, 1, tzinfo=tz_info)
    return start_local.astimezone(timezone.utc), end_local.astimezone(timezone.utc)


def _week_bounds(page_context: dict | None, *, offset_weeks: int = 0) -> tuple[datetime, datetime]:
    tz_info = _tzinfo_from_page(page_context)
    today_local = datetime.now(tz_info).date()
    week_start_date = today_local - timedelta(days=today_local.weekday()) + timedelta(weeks=offset_weeks)
    start_local = datetime.combine(week_start_date, time.min).replace(tzinfo=tz_info)
    end_local = start_local + timedelta(days=7)
    return start_local.astimezone(timezone.utc), end_local.astimezone(timezone.utc)


def _normalize_schedule_window_key(raw_value: Any) -> str:
    normalized = _normalize_text(raw_value).lower().replace(" ", "_")
    if normalized in {
        "today",
        "tomorrow",
        "yesterday",
        "this_week",
        "last_week",
        "next_week",
        "this_month",
        "last_month",
        "next_month",
        "this_year",
        "last_year",
        "next_year",
    }:
        return normalized
    if normalized in {"coming_week", "upcoming_week", "this_coming_week"}:
        return "next_week"
    if normalized in {"coming_month", "upcoming_month", "this_coming_month"}:
        return "next_month"
    if normalized in {"coming_year", "upcoming_year", "this_coming_year"}:
        return "next_year"
    if normalized in {"previous_week", "prior_week"}:
        return "last_week"
    if normalized in {"previous_month", "prior_month"}:
        return "last_month"
    if normalized in {"previous_year", "prior_year"}:
        return "last_year"
    return ""


def _schedule_window_bounds(window_key: str, page_context: dict | None) -> tuple[datetime, datetime, str] | None:
    normalized = _normalize_schedule_window_key(window_key)
    tz_info = _tzinfo_from_page(page_context)
    today_local = datetime.now(tz_info).date()
    if normalized == "today":
        target_day = today_local
        start_dt, end_dt = _day_bounds(target_day, page_context)
        return start_dt, end_dt, "today"
    if normalized == "yesterday":
        target_day = today_local - timedelta(days=1)
        start_dt, end_dt = _day_bounds(target_day, page_context)
        return start_dt, end_dt, "yesterday"
    if normalized == "tomorrow":
        target_day = today_local + timedelta(days=1)
        start_dt, end_dt = _day_bounds(target_day, page_context)
        return start_dt, end_dt, "tomorrow"
    if normalized == "this_week":
        start_dt, end_dt = _week_bounds(page_context, offset_weeks=0)
        return start_dt, end_dt, "this week"
    if normalized == "last_week":
        start_dt, end_dt = _week_bounds(page_context, offset_weeks=-1)
        return start_dt, end_dt, "last week"
    if normalized == "next_week":
        start_dt, end_dt = _week_bounds(page_context, offset_weeks=1)
        return start_dt, end_dt, "this coming week"
    if normalized == "this_month":
        start_day = _start_of_month(today_local)
        end_day = _start_of_month(_add_months(today_local, 1))
        start_dt, end_dt = _date_range_bounds(start_day, end_day, page_context)
        return start_dt, end_dt, "this month"
    if normalized == "last_month":
        start_day = _start_of_month(_add_months(today_local, -1))
        end_day = _start_of_month(today_local)
        start_dt, end_dt = _date_range_bounds(start_day, end_day, page_context)
        return start_dt, end_dt, "last month"
    if normalized == "next_month":
        start_day = _start_of_month(_add_months(today_local, 1))
        end_day = _start_of_month(_add_months(today_local, 2))
        start_dt, end_dt = _date_range_bounds(start_day, end_day, page_context)
        return start_dt, end_dt, "next month"
    if normalized == "this_year":
        start_day = _start_of_year(today_local)
        end_day = _start_of_year(_add_years(today_local, 1))
        start_dt, end_dt = _date_range_bounds(start_day, end_day, page_context)
        return start_dt, end_dt, "this year"
    if normalized == "last_year":
        start_day = _start_of_year(_add_years(today_local, -1))
        end_day = _start_of_year(today_local)
        start_dt, end_dt = _date_range_bounds(start_day, end_day, page_context)
        return start_dt, end_dt, "last year"
    if normalized == "next_year":
        start_day = _start_of_year(_add_years(today_local, 1))
        end_day = _start_of_year(_add_years(today_local, 2))
        start_dt, end_dt = _date_range_bounds(start_day, end_day, page_context)
        return start_dt, end_dt, "next year"
    return None


def _lookup_schedule_window_summary(
    actor_row: dict,
    target_row: dict,
    page_context: dict | None,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    start_raw = _normalize_text(arguments.get("window_start"))
    end_raw = _normalize_text(arguments.get("window_end"))
    custom_label = _normalize_text(arguments.get("window_label"))
    bounds = None
    if start_raw and end_raw:
        try:
            start_dt = _parse_agent_datetime(start_raw, page_context, field="window_start")
            end_dt = _parse_agent_datetime(end_raw, page_context, field="window_end")
        except ValueError as exc:
            return {"success": False, "error": str(exc)}
        if end_dt <= start_dt:
            return {"success": False, "error": "The schedule range end must be after the start."}
        bounds = (start_dt, end_dt, custom_label or "that range")
    else:
        bounds = _schedule_window_bounds(arguments.get("window_key"), page_context)
    if not bounds:
        return {
            "success": False,
            "error": "I need a valid time range like today, last week, next month, last 3 months, or a from/to date range.",
        }
    start_dt, end_dt, window_label = bounds
    rows = _query_schedule_rows(actor_row=actor_row, target_row=target_row, start_dt=start_dt, end_dt=end_dt)
    actor_role = _normalize_role(actor_row)
    is_self_schedule = target_row.get("id") == actor_row.get("id")
    if is_self_schedule and actor_role in {"trainer", "admin"}:
        rows = [row for row in rows if not row.get("is_self_booked")]
    status_scope = _normalize_text(arguments.get("status_scope")).lower() or "active"
    if status_scope == "completed":
        active_rows = [row for row in rows if (_normalize_text(row.get("status")) or "booked").lower() == "completed"]
    elif status_scope == "booked":
        active_rows = [row for row in rows if (_normalize_text(row.get("status")) or "booked").lower() == "booked"]
    elif status_scope == "cancelled":
        active_rows = [row for row in rows if (_normalize_text(row.get("status")) or "booked").lower() == "cancelled"]
    else:
        active_rows = [
            row for row in rows
            if (_normalize_text(row.get("status")) or "booked").lower() != "cancelled"
        ]
    tz_info = _tzinfo_from_page(page_context)
    distinct_days = sorted(
        {
            row.get("start_time").astimezone(tz_info).date().isoformat()
            for row in active_rows
            if row.get("start_time")
        }
    )
    items = [
        {
            "event_id": row.get("id"),
            "status": row.get("status"),
            "weekday_label": row.get("start_time").astimezone(tz_info).strftime("%a") if row.get("start_time") else None,
            "day_header_label": row.get("start_time").astimezone(tz_info).strftime("%A, %b %-d, %Y") if row.get("start_time") else None,
            "date_label": _format_date_label(row.get("start_time"), page_context),
            "time_range_label": _format_time_range(row.get("start_time"), row.get("end_time"), page_context),
            "time_window_label": _format_time_window_label(row.get("start_time"), row.get("end_time"), page_context),
            "session_category": row.get("session_category"),
            "counterpart_name": _format_person_name(
                {
                    "id": row.get("trainer_id") if target_row.get("id") == row.get("client_id") else row.get("client_id"),
                    "name": row.get("trainer_name") if target_row.get("id") == row.get("client_id") else row.get("client_name"),
                    "last_name": row.get("trainer_last_name") if target_row.get("id") == row.get("client_id") else row.get("client_last_name"),
                    "username": row.get("trainer_username") if target_row.get("id") == row.get("client_id") else row.get("client_username"),
                }
            ),
        }
        for row in active_rows
    ]
    return {
        "success": True,
        "metric_key": "schedule_window_summary",
        "target_user_id": target_row["id"],
        "target_name": _format_person_name(target_row),
        "window_key": _normalize_schedule_window_key(arguments.get("window_key")),
        "window_label": window_label,
        "status_scope": status_scope,
        "window_start": start_dt.isoformat(),
        "window_end": end_dt.isoformat(),
        "session_count": len(active_rows),
        "training_day_count": len(distinct_days),
        "day_labels": distinct_days,
        "is_self_schedule": is_self_schedule,
        "items": items,
    }


def _lookup_top_trainer_this_month(page_context: dict | None) -> dict[str, Any]:
    month_start, month_end = _month_bounds(page_context)
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT ts.trainer_id,
                       u.name,
                       u.last_name,
                       u.username,
                       COUNT(*)::int AS session_count
                  FROM trainer_schedule ts
                  JOIN users u
                    ON u.id = ts.trainer_id
                 WHERE ts.status = 'completed'
                   AND ts.start_time >= %s
                   AND ts.start_time < %s
                 GROUP BY ts.trainer_id, u.name, u.last_name, u.username
                 ORDER BY session_count DESC, u.name NULLS LAST, u.last_name NULLS LAST, u.username
                 LIMIT 1
                """,
                (month_start, month_end),
            )
            row = cursor.fetchone()
    if not row:
        return {"success": False, "error": "No completed trainer sessions were found this month."}
    return {
        "success": True,
        "metric_key": "trainer_top_sessions_this_month",
        "trainer_id": row.get("trainer_id"),
        "trainer_name": _format_person_name(row),
        "session_count": row.get("session_count"),
        "window_start": month_start.isoformat(),
        "window_end": month_end.isoformat(),
    }


def _users_created_at_status(cursor) -> tuple[bool, bool]:
    cursor.execute(
        """
        SELECT EXISTS (
            SELECT 1
              FROM information_schema.columns
             WHERE table_schema = 'public'
               AND table_name = 'users'
               AND column_name = 'created_at'
        ) AS has_created_at
        """
    )
    has_created_at = bool((cursor.fetchone() or {}).get("has_created_at"))
    if not has_created_at:
        return False, False
    cursor.execute("SELECT COUNT(*)::int AS null_count FROM users WHERE created_at IS NULL")
    null_count = int((cursor.fetchone() or {}).get("null_count") or 0)
    return True, null_count > 0


def _lookup_new_users_this_month(page_context: dict | None) -> dict[str, Any]:
    month_start, month_end = _month_bounds(page_context)
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            has_created_at, has_nulls = _users_created_at_status(cursor)
            if not has_created_at:
                return {"success": False, "error": "Exact new-user counts are unavailable because users.created_at is missing."}
            cursor.execute(
                """
                SELECT COUNT(*)::int AS new_user_count
                  FROM users
                 WHERE created_at IS NOT NULL
                   AND created_at >= %s
                   AND created_at < %s
                """,
                (month_start, month_end),
            )
            row = cursor.fetchone() or {}
    return {
        "success": True,
        "metric_key": "new_users_this_month",
        "new_user_count": int(row.get("new_user_count") or 0),
        "window_start": month_start.isoformat(),
        "window_end": month_end.isoformat(),
        "is_partial": bool(has_nulls),
    }


def _lookup_trial_status(target_row: dict) -> dict[str, Any]:
    return {
        "success": True,
        "metric_key": "trial_status",
        "target_user_id": target_row["id"],
        "target_name": _format_person_name(target_row),
        "subscription_type": target_row.get("subscription_type"),
        "status": target_row.get("status"),
        "trial_end_date": target_row.get("trial_end_date").isoformat() if target_row.get("trial_end_date") else None,
        "subscription_cancel_at": target_row.get("subscription_cancel_at").isoformat() if target_row.get("subscription_cancel_at") else None,
    }


def _lookup_client_performance_summary(actor_row: dict, target_row: dict) -> dict[str, Any]:
    trainer_id = actor_row["id"] if _normalize_role(actor_row) in {"trainer", "admin"} else target_row.get("trainer_id")
    workouts_completed = int(target_row.get("workouts_completed") or 0)
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT COUNT(*)::int AS completed_count
                  FROM trainer_schedule
                 WHERE trainer_id = %s
                   AND client_id = %s
                   AND status = 'completed'
                """,
                (trainer_id, target_row["id"]),
            )
            completed_row = cursor.fetchone() or {}
            app_module = _load_app_module()
            session_summary = app_module._resolve_client_session_summary(
                cursor,
                trainer_id,
                target_row["id"],
                target_row.get("sessions_booked") or 0,
                completed_row.get("completed_count") or 0,
                target_row.get("sessions_remaining"),
            )
    return {
        "success": True,
        "metric_key": "client_performance_summary",
        "target_user_id": target_row["id"],
        "target_name": _format_person_name(target_row),
        "workouts_completed": workouts_completed,
        "last_workout_completed": target_row.get("last_workout_completed"),
        "sessions_total": session_summary.get("sessions_total"),
        "sessions_left": session_summary.get("sessions_left"),
        "sessions_booked": int(target_row.get("sessions_booked") or 0),
        "sessions_completed": int(completed_row.get("completed_count") or 0),
    }


def _lookup_current_user_summary(actor_row: dict, page_context: dict | None) -> dict[str, Any]:
    summary = _lookup_client_performance_summary(actor_row, actor_row)
    next_session = _lookup_next_session(actor_row, actor_row, page_context)
    summary["next_session"] = next_session if next_session.get("success") else None
    summary["metric_key"] = "current_user_summary"
    return summary


def _lookup_trainer_roster_summary(actor_row: dict) -> dict[str, Any]:
    if _normalize_role(actor_row) not in {"trainer", "admin"}:
        return {"success": False, "error": "Trainer roster summaries require trainer or admin access."}
    app_module = _load_app_module()
    context = app_module._build_trainer_dashboard_context(actor_row["id"], actor_row)
    trainer_stats = context.get("trainer_stats") or {}
    clients = context.get("clients") or []
    return {
        "success": True,
        "metric_key": "trainer_roster_summary",
        "trainer_id": actor_row["id"],
        "trainer_name": _format_person_name(actor_row),
        "total_clients": trainer_stats.get("total_clients") or 0,
        "sessions_completed_all_time": trainer_stats.get("sessions_completed_all_time") or 0,
        "sessions_completed": trainer_stats.get("sessions_completed") or 0,
        "client_count": len(clients),
        "top_clients": [
            {
                "client_id": client.get("id"),
                "name": _format_person_name(client),
                "workouts_completed": client.get("workouts_completed") or 0,
                "sessions_left": client.get("sessions_left"),
            }
            for client in clients[:5]
        ],
    }


def _lookup_platform_summary() -> dict[str, Any]:
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT COUNT(*)::int AS total_users,
                       COALESCE(SUM(COALESCE(workouts_completed, 0)), 0)::int AS total_workouts_completed,
                       COALESCE(SUM(CASE WHEN role = 'trainer' THEN 1 ELSE 0 END), 0)::int AS total_trainers,
                       COALESCE(SUM(CASE WHEN status IN ('invited', 'pending') THEN 1 ELSE 0 END), 0)::int AS pending_invites,
                       COALESCE(SUM(CASE WHEN trial_end_date IS NOT NULL AND trial_end_date >= CURRENT_DATE THEN 1 ELSE 0 END), 0)::int AS active_trials
                  FROM users
                """
            )
            return {"success": True, "metric_key": "platform_summary", **(cursor.fetchone() or {})}


def _lookup_risk_flags_summary(actor_row: dict) -> dict[str, Any]:
    now_utc = datetime.now(timezone.utc)
    stale_login_cutoff = now_utc - timedelta(days=14)
    stale_workout_cutoff = now_utc - timedelta(days=14)
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT id,
                       name,
                       last_name,
                       username,
                       trial_end_date,
                       last_login_at,
                       subscription_cancel_at,
                       last_workout_completed
                  FROM users
                 WHERE role = 'user'
                   AND (
                        subscription_cancel_at IS NOT NULL
                        OR (last_login_at IS NULL OR last_login_at < %s)
                        OR (trial_end_date IS NOT NULL AND trial_end_date <= CURRENT_DATE + INTERVAL '3 days')
                        OR (last_workout_completed IS NULL OR last_workout_completed < %s::date)
                   )
                 ORDER BY subscription_cancel_at DESC NULLS LAST, trial_end_date ASC NULLS LAST, last_login_at ASC NULLS FIRST
                 LIMIT 25
                """,
                (stale_login_cutoff, stale_workout_cutoff.date()),
            )
            rows = cursor.fetchall() or []
    return {
        "success": True,
        "metric_key": "risk_flags_summary",
        "count": len(rows),
        "members": [
            {
                "user_id": row.get("id"),
                "name": _format_person_name(row),
                "trial_end_date": row.get("trial_end_date").isoformat() if row.get("trial_end_date") else None,
                "last_login_at": row.get("last_login_at").isoformat() if row.get("last_login_at") else None,
                "subscription_cancel_at": row.get("subscription_cancel_at").isoformat() if row.get("subscription_cancel_at") else None,
                "last_workout_completed": row.get("last_workout_completed").isoformat() if row.get("last_workout_completed") else None,
            }
            for row in rows
        ],
    }


def lookup_fitbase_data(arguments: dict[str, Any], actor_row: dict, page_context: dict | None) -> dict[str, Any]:
    metric_key = _normalize_text(arguments.get("metric_key")).lower()
    if not metric_key:
        return {"success": False, "error": "Missing metric_key."}

    if metric_key in {"trainer_top_sessions_this_month", "new_users_this_month", "platform_summary", "risk_flags_summary"}:
        if _normalize_role(actor_row) != "admin":
            return {"success": False, "error": "Only admins can access that platform-wide metric."}
    if metric_key == "current_user_summary":
        return _lookup_current_user_summary(actor_row, page_context)
    if metric_key == "trainer_top_sessions_this_month":
        return _lookup_top_trainer_this_month(page_context)
    if metric_key == "new_users_this_month":
        return _lookup_new_users_this_month(page_context)
    if metric_key == "platform_summary":
        return _lookup_platform_summary()
    if metric_key == "risk_flags_summary":
        return _lookup_risk_flags_summary(actor_row)

    target_row, error = _resolve_target_user_for_lookup(metric_key, arguments, actor_row, page_context)
    if error:
        return {"success": False, "error": error}
    if not target_row:
        return {"success": False, "error": "I could not resolve the requested user context."}

    if metric_key == "estimated_one_rep_max":
        return _lookup_estimated_one_rep_max(target_row, arguments, actor_row)
    if metric_key == "most_tracked_workout":
        return _lookup_most_tracked_workout(target_row)
    if metric_key == "today_schedule":
        return _lookup_today_schedule(actor_row, target_row, page_context, arguments)
    if metric_key == "schedule_window_summary":
        return _lookup_schedule_window_summary(actor_row, target_row, page_context, arguments)
    if metric_key == "next_session":
        return _lookup_next_session(actor_row, target_row, page_context)
    if metric_key == "trial_status":
        return _lookup_trial_status(target_row)
    if metric_key == "client_performance_summary":
        return _lookup_client_performance_summary(actor_row, target_row)
    if metric_key == "trainer_roster_summary":
        return _lookup_trainer_roster_summary(actor_row)

    return {"success": False, "error": f"Unsupported metric_key: {metric_key}"}


def maybe_prepare_direct_lookup(
    message_text: str,
    actor_row: dict,
    page_context: dict | None,
    recent_history: list[dict[str, str]] | None = None,
) -> dict[str, Any] | None:
    lowered = _normalize_text(message_text).lower()
    if "workout" in lowered and any(marker in lowered for marker in ("organize", "reorganize", "optimize", "rearrange", "group", "efficient", "efficiency")):
        return None
    prior_user_message = _latest_prior_user_message(recent_history, message_text)
    one_rm_markers = (
        r"\bbest time\b\s+(?:for|of|on)\b",
        r"\bbest time\b\s+(?!for\b|of\b|on\b)[a-z0-9]",
        r"\bbest time\b[?.!]*$",
        r"\bmax time\b\s+(?:for|of|on)\b",
        r"\bmax time\b\s+(?!for\b|of\b|on\b)[a-z0-9]",
        r"\bmax time\b[?.!]*$",
        r"\b1rm\b",
        r"\bone rep max\b",
        r"\bestimated 1rm\b",
        r"\best\.?\s*1rm\b",
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
    )
    references_one_rep_max = any(re.search(pattern, lowered, flags=re.IGNORECASE) for pattern in one_rm_markers)
    contextual_one_rep_max = (
        not references_one_rep_max
        and _message_likely_is_exercise_query(message_text)
        and prior_user_message
        and any(re.search(pattern, prior_user_message, flags=re.IGNORECASE) for pattern in one_rm_markers)
    )

    if references_one_rep_max or contextual_one_rep_max:
        source_message = message_text if references_one_rep_max else prior_user_message or message_text
        arguments: dict[str, Any] = {
            "metric_key": "estimated_one_rep_max",
            "exercise_query": (
                _extract_one_rep_max_exercise_query(message_text, actor_row, page_context)
                if references_one_rep_max
                else _normalize_text(message_text)
            ),
        }
        target_client = _match_client_from_message(actor_row, source_message, page_context)
        if target_client:
            arguments["client_id"] = target_client["id"]
            arguments["client_name"] = _format_person_name(target_client)
        elif _message_refers_to_actor_self(source_message):
            arguments["client_id"] = actor_row.get("id")
            arguments["client_name"] = _format_person_name(actor_row)
        return lookup_fitbase_data(arguments, actor_row, page_context)

    range_arguments = _build_relative_schedule_range(message_text, page_context)
    if not range_arguments:
        explicit_target_day = _extract_relative_or_named_date(message_text, page_context)
        if explicit_target_day:
            start_dt, end_dt = _date_range_bounds(
                explicit_target_day,
                explicit_target_day + timedelta(days=1),
                page_context,
            )
            range_arguments = {
                "window_start": start_dt.isoformat(),
                "window_end": end_dt.isoformat(),
                "window_label": f"on {explicit_target_day.strftime('%A, %b %-d, %Y')}",
            }
        else:
            return None

    asks_for_count = any(phrase in lowered for phrase in (
        "how many",
        "how often",
        "how many days",
        "how many sessions",
        "days am i training",
        "sessions booked",
    ))
    asks_for_schedule_overview = (
        not asks_for_count
        and any(token in lowered for token in ("schedule", "calendar"))
        and any(phrase in lowered for phrase in (
            "what's",
            "what is",
            "show",
            "tell me",
            "give me",
            "do i have",
            "who do i have",
            "what do i have",
            "my schedule",
            "my calendar",
        ))
        and not any(token in lowered for token in (
            "book ",
            "reschedule",
            "cancel ",
            "complete ",
            "mark ",
            "delete ",
            "remove ",
            "swap ",
            "assign ",
            "move ",
        ))
    )
    mentions_training = any(phrase in lowered for phrase in (
        "training with",
        "train with",
        "trained with",
        "did i train with",
        "am i training with",
        "session",
        "sessions",
        "booked",
        "calendar",
        "schedule",
    ))
    if asks_for_schedule_overview:
        arguments: dict[str, Any] = {
            **range_arguments,
        }
        target_client = _match_client_from_message(actor_row, message_text, page_context)
        if target_client:
            arguments["client_id"] = target_client["id"]
            arguments["client_name"] = _format_person_name(target_client)
        elif _message_refers_to_actor_self(message_text):
            arguments["client_id"] = actor_row.get("id")
            arguments["client_name"] = _format_person_name(actor_row)

        single_day_window_key = _normalize_schedule_window_key(range_arguments.get("window_key"))
        if single_day_window_key in {"today", "tomorrow", "yesterday"}:
            bounds = _schedule_window_bounds(single_day_window_key, page_context)
            if not bounds:
                return None
            start_dt, _, _ = bounds
            arguments["metric_key"] = "today_schedule"
            arguments["target_date"] = start_dt.astimezone(_tzinfo_from_page(page_context)).date().isoformat()
        else:
            arguments["metric_key"] = "schedule_window_summary"
            arguments["status_scope"] = _infer_schedule_status_scope(message_text)
        return lookup_fitbase_data(arguments, actor_row, page_context)

    if not (asks_for_count and mentions_training):
        return None

    arguments: dict[str, Any] = {
        "metric_key": "schedule_window_summary",
        "status_scope": _infer_schedule_status_scope(message_text),
        **range_arguments,
    }

    role = _normalize_role(actor_row)
    target_client = _match_client_from_message(actor_row, message_text, page_context)
    if target_client:
        arguments["client_id"] = target_client["id"]
        arguments["client_name"] = _format_person_name(target_client)
    elif role in {"trainer", "admin"} and "with" in lowered:
        return None

    return lookup_fitbase_data(arguments, actor_row, page_context)


def _prepare_schedule_action(arguments: dict[str, Any], actor_row: dict, page_context: dict | None) -> dict[str, Any]:
    app_module = _load_app_module()
    actor_role = _normalize_role(actor_row)
    if actor_role not in {"trainer", "admin"}:
        return {"success": False, "error": "Scheduling actions require trainer or admin access."}

    action_type = _normalize_text(arguments.get("action_type")).lower()
    if not action_type:
        return {"success": False, "error": "Missing action_type."}

    if action_type == "block_time_off":
        try:
            start_dt = _parse_agent_datetime(arguments.get("start_time"), page_context, field="start time")
            end_dt = (
                _parse_agent_datetime(arguments.get("end_time"), page_context, field="end time")
                if arguments.get("end_time")
                else start_dt + timedelta(minutes=int(arguments.get("duration_minutes") or 60))
            )
            app_module._validate_time_window(start_dt, end_dt)
        except ValueError as exc:
            return {"success": False, "error": str(exc)}

        with get_connection() as conn:
            with conn.cursor() as cursor:
                conflict, message = app_module._time_off_conflicts(cursor, actor_row["id"], start_dt, end_dt)
        if conflict:
            return {"success": False, "error": message}
        title = _normalize_text(arguments.get("title")) or "Personal Time"
        return {
            "success": True,
            "kind": "pending_action",
            "action_type": action_type,
            "label": f"Block {title}",
            "summary": f"Block {title} on {_format_time_range(start_dt, end_dt, page_context)}.",
            "arguments": {
                "title": title,
                "note": _normalize_text(arguments.get("note")) or None,
                "start_time": start_dt.isoformat(),
                "end_time": end_dt.isoformat(),
            },
        }

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            client_row, error = _resolve_client_row(
                cursor,
                actor_row,
                client_id=_coerce_int(arguments.get("client_id")),
                client_name=arguments.get("client_name"),
                page_context=page_context,
            )
            if error:
                return {"success": False, "error": error}
            if not client_row:
                return {"success": False, "error": "I could not resolve the client for that action."}

            if action_type == "optimize_workout_layout":
                target_scope = _normalize_text(arguments.get("target_scope")).lower()
                explicit_session_target = any(
                    arguments.get(key)
                    for key in ("event_id", "target_date", "start_time", "source_start_time")
                )
                if target_scope != "active_workout" and explicit_session_target:
                    event_row, event_error = _resolve_schedule_event_row(
                        cursor,
                        actor_row=actor_row,
                        client_row=client_row,
                        action_type="assign_workout",
                        arguments=arguments,
                        page_context=page_context,
                    )
                    if event_error:
                        return {"success": False, "error": event_error}
                    if not event_row:
                        return {"success": False, "error": "Scheduled session not found."}
                    session_payload = app_module._parse_session_payload(event_row.get("session_payload"))
                    if not app_module._session_payload_has_plan(session_payload):
                        return {"success": False, "error": "No workout is assigned to that session yet."}
                    return {
                        "success": True,
                        "kind": "pending_action",
                        "action_type": action_type,
                        "label": f"Organize workout for {_format_person_name(client_row)}",
                        "summary": (
                            f"Organize the assigned workout on "
                            f"{_format_time_range_with_weekday(event_row.get('start_time'), event_row.get('end_time'), page_context)}."
                        ),
                        "arguments": {
                            "event_id": event_row["id"],
                            "client_id": client_row["id"],
                            "target_scope": "session",
                            "timezone": _normalize_text((page_context or {}).get("timezone")) or None,
                        },
                    }

                active_workout = app_module.get_active_workout(client_row["id"])
                if not active_workout or not app_module._session_payload_has_plan(active_workout.get("workout_data") or {}):
                    return {"success": False, "error": f"No active workout is available for {_format_person_name(client_row)} right now."}
                return {
                    "success": True,
                    "kind": "pending_action",
                    "action_type": action_type,
                    "label": f"Organize active workout for {_format_person_name(client_row)}",
                    "summary": (
                        f"Organize {_format_person_name(client_row)}'s current workout."
                    ),
                    "arguments": {
                        "client_id": client_row["id"],
                        "target_scope": "active_workout",
                        "timezone": _normalize_text((page_context or {}).get("timezone")) or None,
                    },
                }

            if action_type in {"book_session", "book_and_assign_workout"}:
                try:
                    start_dt = _parse_agent_datetime(arguments.get("start_time"), page_context, field="start time")
                    end_dt = (
                        _parse_agent_datetime(arguments.get("end_time"), page_context, field="end time")
                        if arguments.get("end_time")
                        else start_dt + timedelta(minutes=int(arguments.get("duration_minutes") or 60))
                    )
                    app_module._validate_time_window(start_dt, end_dt)
                except ValueError as exc:
                    return {"success": False, "error": str(exc)}

                if action_type == "book_and_assign_workout" and not _normalize_text(arguments.get("workout_category")):
                    return {"success": False, "error": "Booking and assigning a workout needs a workout category."}
                if action_type == "book_and_assign_workout":
                    custom_workout_categories = arguments.get("custom_categories") or []
                    workout_category_value = _normalize_text(arguments.get("workout_category"))
                    if workout_category_value in {CUSTOM_WORKOUT_TOKEN, HOME_WORKOUT_TOKEN}:
                        if not custom_workout_categories:
                            return {"success": False, "error": "Which categories would you like in this custom workout?"}
                        if not _coerce_int(arguments.get("duration_minutes")):
                            arguments["duration_minutes"] = DEFAULT_ASSIGNED_WORKOUT_DURATION_MINUTES

                cursor.execute(
                    """
                    SELECT COUNT(*)::int AS completed_count
                      FROM trainer_schedule
                     WHERE trainer_id = %s
                       AND client_id = %s
                       AND status = 'completed'
                    """,
                    (actor_row["id"], client_row["id"]),
                )
                completed_row = cursor.fetchone() or {}

                session_summary = app_module._resolve_client_session_summary(
                    cursor,
                    actor_row["id"],
                    client_row["id"],
                    client_row.get("sessions_booked") or 0,
                    completed_row.get("completed_count") or 0,
                    client_row.get("sessions_remaining"),
                )
                sessions_left = session_summary.get("sessions_left")
                if sessions_left is not None and sessions_left <= 0:
                    return {"success": False, "error": "That client has no sessions remaining."}

                conflict, message = app_module._schedule_conflicts(
                    cursor,
                    actor_row["id"],
                    client_row["id"],
                    start_dt,
                    end_dt,
                )
                if conflict:
                    return {"success": False, "error": message}

                workout_category = _normalize_text(arguments.get("workout_category")) or None
                workout_display_label = _normalize_text(arguments.get("workout_display_label")) or workout_category
                label = f"Schedule {_format_person_name(client_row)}"
                if workout_display_label:
                    label = f"{label} for {workout_display_label}"
                return {
                    "success": True,
                    "kind": "pending_action",
                    "action_type": action_type,
                    "label": label,
                    "summary": (
                        f"Book {_format_person_name(client_row)} on {_format_time_range_with_weekday(start_dt, end_dt, page_context)}."
                        if not workout_display_label
                        else (
                            f"Book {_format_person_name(client_row)} on {_format_time_range_with_weekday(start_dt, end_dt, page_context)} "
                            f"and assign a {workout_display_label} workout."
                        )
                    ),
                    "arguments": {
                        "client_id": client_row["id"],
                        "start_time": start_dt.isoformat(),
                        "end_time": end_dt.isoformat(),
                        "duration_minutes": int((end_dt - start_dt).total_seconds() // 60),
                        "note": _normalize_text(arguments.get("note")) or None,
                        "workout_category": workout_category,
                        "workout_display_label": workout_display_label,
                        "custom_categories": arguments.get("custom_categories") or [],
                    },
                }

            event_row, event_error = _resolve_schedule_event_row(
                cursor,
                actor_row=actor_row,
                client_row=client_row,
                action_type=action_type,
                arguments=arguments,
                page_context=page_context,
            )
            if event_error:
                return {"success": False, "error": event_error}
            if not event_row:
                return {"success": False, "error": "Scheduled session not found."}
            event_id = event_row.get("id")

            if action_type == "swap_sessions":
                swap_event_id = _coerce_int(arguments.get("swap_event_id"))
                if not swap_event_id:
                    return {"success": False, "error": "I need both sessions to swap them."}
                second_client_id = _coerce_int(arguments.get("second_client_id"))
                second_client_name = _normalize_text(arguments.get("second_client_name")) or None
                second_client_row = client_row
                if second_client_id and second_client_id != client_row["id"]:
                    second_client_row, second_client_error = _resolve_client_row(
                        cursor,
                        actor_row,
                        client_id=second_client_id,
                        client_name=second_client_name,
                        page_context=page_context,
                    )
                    if second_client_error:
                        return {"success": False, "error": second_client_error}
                    if not second_client_row:
                        return {"success": False, "error": "I could not resolve the second client for that swap."}
                swap_event_row, swap_event_error = _resolve_schedule_event_row(
                    cursor,
                    actor_row=actor_row,
                    client_row=second_client_row,
                    action_type=action_type,
                    arguments={"event_id": swap_event_id},
                    page_context=page_context,
                )
                if swap_event_error:
                    return {"success": False, "error": swap_event_error}
                if not swap_event_row:
                    return {"success": False, "error": "The second session for that swap was not found."}
                if swap_event_row.get("id") == event_id:
                    return {"success": False, "error": "I need two different sessions to perform a swap."}
                first_status = _normalize_text(event_row.get("status")).lower() or "booked"
                second_status = _normalize_text(swap_event_row.get("status")).lower() or "booked"
                if first_status != "booked" or second_status != "booked":
                    return {"success": False, "error": "Only booked sessions can be swapped."}
                first_start = event_row.get("start_time")
                first_end = event_row.get("end_time")
                second_start = swap_event_row.get("start_time")
                second_end = swap_event_row.get("end_time")
                if not first_start or not first_end or not second_start or not second_end:
                    return {"success": False, "error": "Both sessions need a valid start and end time to swap them."}
                owner_trainer_id = _coerce_int(event_row.get("trainer_id"))
                swap_trainer_id = _coerce_int(swap_event_row.get("trainer_id"))
                if not owner_trainer_id or not swap_trainer_id or owner_trainer_id != swap_trainer_id:
                    return {"success": False, "error": "Both sessions need to belong to the same trainer calendar to swap them."}
                conflict, message = _schedule_conflicts_excluding_ids(
                    cursor,
                    owner_trainer_id,
                    client_row["id"],
                    second_start,
                    second_end,
                    [event_id, swap_event_id],
                )
                if conflict:
                    return {"success": False, "error": message}
                conflict, message = _schedule_conflicts_excluding_ids(
                    cursor,
                    owner_trainer_id,
                    second_client_row["id"],
                    first_start,
                    first_end,
                    [event_id, swap_event_id],
                )
                if conflict:
                    return {"success": False, "error": message}
                return {
                    "success": True,
                    "kind": "pending_action",
                    "action_type": action_type,
                    "label": (
                        f"Swap {_format_person_name(client_row)} with {_format_person_name(second_client_row)}"
                        if second_client_row.get("id") != client_row.get("id")
                        else f"Swap {_format_person_name(client_row)} sessions"
                    ),
                    "summary": _format_swap_summary(
                        client_row,
                        first_start,
                        first_end,
                        second_client_row,
                        second_start,
                        second_end,
                        page_context,
                    ),
                    "arguments": {
                        "event_id": event_id,
                        "swap_event_id": swap_event_id,
                        "client_id": client_row["id"],
                        "second_client_id": second_client_row["id"],
                        "second_client_name": _format_person_name(second_client_row),
                        "timezone": _normalize_text((page_context or {}).get("timezone")) or None,
                    },
                }

            if action_type in {"cancel_session", "complete_session", "set_session_booked", "delete_session"}:
                target_status_map = {
                    "cancel_session": "cancelled",
                    "complete_session": "completed",
                    "set_session_booked": "booked",
                }
                target_status = target_status_map.get(action_type)
                current_status = _normalize_text(event_row.get("status")).lower() or "booked"
                if target_status and current_status == target_status:
                    return {
                        "success": False,
                        "error": f"That session is already marked {target_status}.",
                    }
                label_map = {
                    "cancel_session": f"Cancel session for {_format_person_name(client_row)}",
                    "complete_session": f"Complete session for {_format_person_name(client_row)}",
                    "set_session_booked": f"Mark session booked for {_format_person_name(client_row)}",
                    "delete_session": f"Delete session for {_format_person_name(client_row)}",
                }
                summary_map = {
                    "cancel_session": f"Mark the session as cancelled on {_format_time_range(event_row.get('start_time'), event_row.get('end_time'), page_context)}.",
                    "complete_session": f"Mark the session as completed on {_format_time_range(event_row.get('start_time'), event_row.get('end_time'), page_context)}.",
                    "set_session_booked": f"Mark the session as booked on {_format_time_range(event_row.get('start_time'), event_row.get('end_time'), page_context)}.",
                    "delete_session": f"Delete the session from the calendar on {_format_time_range(event_row.get('start_time'), event_row.get('end_time'), page_context)}.",
                }
                return {
                    "success": True,
                    "kind": "pending_action",
                    "action_type": action_type,
                    "label": label_map[action_type],
                    "summary": summary_map[action_type],
                    "arguments": {
                        "event_id": event_id,
                        "client_id": client_row["id"],
                        "timezone": _normalize_text((page_context or {}).get("timezone")) or None,
                    },
                }

            if action_type == "reschedule_session":
                try:
                    start_dt = _parse_agent_datetime(arguments.get("start_time"), page_context, field="start time")
                    end_dt = (
                        _parse_agent_datetime(arguments.get("end_time"), page_context, field="end time")
                        if arguments.get("end_time")
                        else start_dt + timedelta(minutes=int(arguments.get("duration_minutes") or 60))
                    )
                    app_module._validate_time_window(start_dt, end_dt)
                except ValueError as exc:
                    return {"success": False, "error": str(exc)}
                conflict, message = app_module._schedule_conflicts(
                    cursor,
                    actor_row["id"],
                    client_row["id"],
                    start_dt,
                    end_dt,
                    exclude_id=event_id,
                )
                if conflict:
                    return {"success": False, "error": message}
                return {
                    "success": True,
                    "kind": "pending_action",
                    "action_type": action_type,
                    "label": f"Reschedule {_format_person_name(client_row)}",
                    "summary": _format_reschedule_summary(
                        event_row.get("start_time"),
                        event_row.get("end_time"),
                        start_dt,
                        end_dt,
                        page_context,
                    ),
                    "arguments": {
                        "event_id": event_id,
                        "client_id": client_row["id"],
                        "start_time": start_dt.isoformat(),
                        "end_time": end_dt.isoformat(),
                        "timezone": _normalize_text((page_context or {}).get("timezone")) or None,
                    },
                }

            if action_type == "assign_workout":
                workout_category = _normalize_text(arguments.get("workout_category"))
                if not workout_category:
                    return {"success": False, "error": "Assigning a workout needs a workout category."}
                custom_categories = arguments.get("custom_categories") or []
                if workout_category in {CUSTOM_WORKOUT_TOKEN, HOME_WORKOUT_TOKEN}:
                    if not custom_categories:
                        return {"success": False, "error": "Which categories would you like in this custom workout?"}
                    if not _coerce_int(arguments.get("duration_minutes")):
                        arguments["duration_minutes"] = DEFAULT_ASSIGNED_WORKOUT_DURATION_MINUTES
                client_name = _format_person_name(client_row)
                workout_display_label = _normalize_text(arguments.get("workout_display_label")) or workout_category
                return {
                    "success": True,
                    "kind": "pending_action",
                    "action_type": action_type,
                    "label": f"Assign {workout_display_label} to {client_name}",
                    "summary": (
                        f"Assign {client_name} {_indefinite_article(workout_display_label).lower()} "
                        f"{workout_display_label} workout on "
                        f"{_format_time_range(event_row.get('start_time'), event_row.get('end_time'), page_context)}."
                    ),
                    "arguments": {
                        "event_id": event_id,
                        "client_id": client_row["id"],
                        "workout_category": workout_category,
                        "workout_display_label": workout_display_label,
                        "duration_minutes": _coerce_int(arguments.get("duration_minutes")),
                        "custom_categories": custom_categories,
                    },
                }

    return {"success": False, "error": f"Unsupported action_type: {action_type}"}


def prepare_fitbase_action(arguments: dict[str, Any], actor_row: dict, page_context: dict | None) -> dict[str, Any]:
    return _prepare_schedule_action(arguments, actor_row, page_context)


def _load_roster_clients(actor_row: dict, page_context: dict | None) -> list[dict[str, Any]]:
    role = _normalize_role(actor_row)
    if role not in {"trainer", "admin"}:
        return []
    params: list[Any] = []
    query = [
        """
        SELECT id, name, last_name, username, trainer_id, sessions_remaining, sessions_booked, workout_duration,
               exercise_history, subscription_type, trial_end_date
          FROM users
        """
    ]
    if role == "trainer":
        query.append("WHERE trainer_id = %s")
        params.append(actor_row["id"])
    query.append("ORDER BY name NULLS LAST, last_name NULLS LAST, username")
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute("\n".join(query), params)
            rows = cursor.fetchall() or []
    return rows


def _message_mentions_name(message_text: str, candidate: str | None) -> bool:
    normalized_candidate = _normalize_text(candidate)
    if not normalized_candidate:
        return False
    pattern = r"(?<!\w)" + re.escape(normalized_candidate.lower()).replace(r"\ ", r"\s+") + r"(?:'s|s)?(?!\w)"
    return re.search(pattern, _normalize_text(message_text).lower()) is not None


def _match_client_from_message(actor_row: dict, message_text: str, page_context: dict | None) -> dict[str, Any] | None:
    page_client_id = _coerce_int((page_context or {}).get("selected_client_id"))
    roster = _load_roster_clients(actor_row, page_context)
    ranked_matches: list[tuple[int, int, dict[str, Any]]] = []
    for client in roster:
        scored_candidates: list[tuple[int, str]] = []
        full_name = _format_person_name(client)
        username = _normalize_text(client.get("username"))
        first_name = _normalize_text(client.get("name"))
        last_name = _normalize_text(client.get("last_name"))
        if _message_mentions_name(message_text, full_name):
            scored_candidates.append((400 + len(full_name), full_name))
        if _message_mentions_name(message_text, username):
            scored_candidates.append((350 + len(username), username))
        if _message_mentions_name(message_text, first_name):
            scored_candidates.append((200 + len(first_name), first_name))
        if _message_mentions_name(message_text, last_name):
            scored_candidates.append((150 + len(last_name), last_name))
        if scored_candidates:
            best_score, best_label = max(scored_candidates, key=lambda item: item[0])
            ranked_matches.append((best_score, len(best_label), client))
    if ranked_matches:
        ranked_matches.sort(key=lambda item: (item[0], item[1]), reverse=True)
        top_score = ranked_matches[0][0]
        top_matches = [client for score, _, client in ranked_matches if score == top_score]
        if len(top_matches) == 1:
            return top_matches[0]
    if page_client_id:
        for client in roster:
            if client.get("id") == page_client_id:
                return client
    return None


def resolve_client_from_message(actor_row: dict, message_text: str, page_context: dict | None) -> dict[str, Any] | None:
    return _match_client_from_message(actor_row, message_text, page_context)


def _match_client_from_segment(
    actor_row: dict,
    segment_text: str,
    page_context: dict | None,
    *,
    fallback_client: dict | None = None,
    allow_page_fallback: bool = False,
) -> dict[str, Any] | None:
    segment_text = _normalize_text(segment_text)
    if segment_text:
        matched_client = _match_client_from_message(
            actor_row,
            segment_text,
            page_context if allow_page_fallback else None,
        )
        if matched_client:
            return matched_client
    return fallback_client


def _extract_relative_or_named_date(message_text: str, page_context: dict | None) -> date | None:
    lowered = _normalize_text(message_text).lower()
    tz_info = _tzinfo_from_page(page_context)
    today_local = datetime.now(tz_info).date()
    if "today" in lowered:
        return today_local
    if "tomorrow" in lowered:
        return today_local + timedelta(days=1)
    if "yesterday" in lowered:
        return today_local - timedelta(days=1)

    iso_match = re.search(r"\b(\d{4}-\d{2}-\d{2})\b", lowered)
    if iso_match:
        return _parse_local_date(iso_match.group(1), page_context)

    slash_match = re.search(r"\b(\d{1,2}/\d{1,2}/\d{2,4})\b", message_text)
    if slash_match:
        return _parse_local_date(slash_match.group(1), page_context)

    month_match = re.search(
        r"\b("
        r"(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|"
        r"aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)"
        r"\s+\d{1,2}(?:st|nd|rd|th)?(?:,\s*\d{4})?"
        r")\b",
        message_text,
        flags=re.IGNORECASE,
    )
    if month_match:
        raw_value = month_match.group(1)
        if not re.search(r"\d{4}", raw_value):
            raw_value = f"{raw_value}, {today_local.year}"
        return _parse_local_date(raw_value, page_context)

    weekday_match = re.search(
        r"\b(?:(this|next|last)\s+)?"
        r"(monday|tuesday|wednesday|thursday|friday|saturday|sunday)"
        r"(?:\s+(this|next|last)\s+week)?\b",
        lowered,
        flags=re.IGNORECASE,
    )
    if weekday_match:
        prefix = (weekday_match.group(1) or "").lower()
        weekday_name = (weekday_match.group(2) or "").lower()
        suffix = (weekday_match.group(3) or "").lower()
        direction = suffix or prefix
        weekday_lookup = {
            "monday": 0,
            "tuesday": 1,
            "wednesday": 2,
            "thursday": 3,
            "friday": 4,
            "saturday": 5,
            "sunday": 6,
        }
        target_weekday = weekday_lookup.get(weekday_name)
        if target_weekday is not None:
            start_of_week = today_local - timedelta(days=today_local.weekday())
            week_offset = 0
            if direction == "next":
                week_offset = 1
            elif direction == "last":
                week_offset = -1
            target_week_start = start_of_week + timedelta(weeks=week_offset)
            return target_week_start + timedelta(days=target_weekday)
    return None


def _extract_clock_from_message(message_text: str) -> tuple[int, int] | None:
    time_match = re.search(r"\b(\d{1,2})(?::(\d{2}))?\s*(am|pm)\b", message_text, flags=re.IGNORECASE)
    if not time_match:
        return None
    hour = int(time_match.group(1))
    minute = int(time_match.group(2) or 0)
    meridiem = time_match.group(3).lower()
    if hour == 12:
        hour = 0
    if meridiem == "pm":
        hour += 12
    return hour, minute


def _extract_clock_window_from_message(message_text: str) -> tuple[tuple[int, int], tuple[int, int], int] | None:
    normalized = _normalize_text(message_text)
    range_match = re.search(
        r"\b(?:from\s+)?(\d{1,2})(?::(\d{2}))?\s*(am|pm)?\s*(?:-|to)\s*(\d{1,2})(?::(\d{2}))?\s*(am|pm)?\b",
        normalized,
        flags=re.IGNORECASE,
    )
    if not range_match:
        return None

    start_hour_12 = int(range_match.group(1))
    start_minute = int(range_match.group(2) or 0)
    start_meridiem = (range_match.group(3) or "").lower() or None
    end_hour_12 = int(range_match.group(4))
    end_minute = int(range_match.group(5) or 0)
    end_meridiem = (range_match.group(6) or "").lower() or None

    if not (1 <= start_hour_12 <= 12 and 1 <= end_hour_12 <= 12):
        return None
    if start_minute > 59 or end_minute > 59:
        return None
    if not start_meridiem and not end_meridiem:
        return None

    def _to_24(hour_12: int, minute_value: int, meridiem_value: str) -> tuple[int, int]:
        hour_24 = hour_12 % 12
        if meridiem_value == "pm":
            hour_24 += 12
        return hour_24, minute_value

    start_candidates = [start_meridiem] if start_meridiem else ["am", "pm"]
    end_candidates = [end_meridiem] if end_meridiem else ["am", "pm"]

    best_match: tuple[tuple[int, int], tuple[int, int], int] | None = None
    for start_candidate in start_candidates:
        for end_candidate in end_candidates:
            start_parts = _to_24(start_hour_12, start_minute, start_candidate)
            end_parts = _to_24(end_hour_12, end_minute, end_candidate)
            start_minutes = start_parts[0] * 60 + start_parts[1]
            end_minutes = end_parts[0] * 60 + end_parts[1]
            duration_minutes = end_minutes - start_minutes
            if duration_minutes <= 0 or duration_minutes > 12 * 60:
                continue
            candidate = (start_parts, end_parts, duration_minutes)
            if best_match is None or duration_minutes < best_match[2]:
                best_match = candidate
    return best_match


def _extract_time_mentions(message_text: str) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    pattern = re.compile(
        r"\b(?:(\d{1,2})(?::(\d{2}))\s*(am|pm)?|(\d{1,2})\s*(am|pm))\b",
        flags=re.IGNORECASE,
    )
    for match in pattern.finditer(message_text):
        colon_hour = match.group(1)
        colon_minute = match.group(2)
        colon_meridiem = match.group(3)
        plain_hour = match.group(4)
        plain_meridiem = match.group(5)
        hour = int(colon_hour or plain_hour or 0)
        minute = int(colon_minute or 0)
        meridiem = (colon_meridiem or plain_meridiem or "").lower() or None
        if hour < 1 or hour > 12 or minute < 0 or minute > 59:
            continue
        matches.append(
            {
                "raw": match.group(0),
                "hour": hour,
                "minute": minute,
                "meridiem": meridiem,
                "start": match.start(),
                "end": match.end(),
            }
        )
    return matches


def _find_client_day_sessions(actor_row: dict, client_row: dict, target_day: date, page_context: dict | None) -> list[dict[str, Any]]:
    actor_role = _normalize_role(actor_row)
    start_window, end_window = _day_bounds(target_day, page_context)
    params: list[Any] = [client_row["id"], start_window, end_window]
    trainer_clause = ""
    if actor_role != "admin":
        trainer_clause = " AND trainer_id = %s"
        params.append(actor_row["id"])
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                f"""
                SELECT id,
                       trainer_id,
                       client_id,
                       start_time,
                       end_time,
                       status,
                       note,
                       session_category
                  FROM trainer_schedule
                 WHERE client_id = %s
                   AND start_time >= %s
                   AND start_time < %s
                   {trainer_clause}
                 ORDER BY start_time ASC
                """,
                params,
            )
            return cursor.fetchall() or []


def _match_session_by_time_hint(
    rows: list[dict[str, Any]],
    mention: dict[str, Any] | None,
    page_context: dict | None,
) -> dict[str, Any] | None:
    if not rows:
        return None
    if not mention:
        booked_rows = [row for row in rows if (_normalize_text(row.get("status")) or "booked").lower() == "booked"]
        return booked_rows[0] if len(booked_rows) == 1 else (rows[0] if len(rows) == 1 else None)

    tz_info = _tzinfo_from_page(page_context)
    exact_matches = []
    loose_matches = []
    for row in rows:
        start_dt = row.get("start_time")
        if not start_dt:
            continue
        local_start = start_dt.astimezone(tz_info)
        local_hour12 = ((local_start.hour - 1) % 12) + 1
        local_meridiem = "pm" if local_start.hour >= 12 else "am"
        if local_hour12 == mention["hour"] and local_start.minute == mention["minute"]:
            loose_matches.append(row)
            if not mention.get("meridiem") or mention["meridiem"] == local_meridiem:
                exact_matches.append(row)
    target_rows = exact_matches or loose_matches
    booked_rows = [row for row in target_rows if (_normalize_text(row.get("status")) or "booked").lower() == "booked"]
    if len(booked_rows) == 1:
        return booked_rows[0]
    if len(target_rows) == 1:
        return target_rows[0]
    return None


def _datetime_matches_mention(dt: datetime | None, mention: dict[str, Any] | None, page_context: dict | None) -> bool:
    if not dt or not mention:
        return False
    local_dt = dt.astimezone(_tzinfo_from_page(page_context))
    local_hour12 = ((local_dt.hour - 1) % 12) + 1
    local_meridiem = "pm" if local_dt.hour >= 12 else "am"
    if local_hour12 != int(mention.get("hour") or 0):
        return False
    if local_dt.minute != int(mention.get("minute") or 0):
        return False
    mention_meridiem = mention.get("meridiem")
    return not mention_meridiem or mention_meridiem == local_meridiem


def _match_session_by_window_hint(
    rows: list[dict[str, Any]],
    start_mention: dict[str, Any] | None,
    end_mention: dict[str, Any] | None,
    page_context: dict | None,
) -> dict[str, Any] | None:
    if not rows:
        return None
    target_rows = rows
    if start_mention:
        target_rows = [row for row in target_rows if _datetime_matches_mention(row.get("start_time"), start_mention, page_context)]
    if end_mention:
        matched_end_rows = [row for row in target_rows if _datetime_matches_mention(row.get("end_time"), end_mention, page_context)]
        if matched_end_rows:
            target_rows = matched_end_rows
    booked_rows = [row for row in target_rows if (_normalize_text(row.get("status")) or "booked").lower() == "booked"]
    if len(booked_rows) == 1:
        return booked_rows[0]
    if len(target_rows) == 1:
        return target_rows[0]
    return None


def _build_local_iso_from_mention(
    target_day: date,
    mention: dict[str, Any],
    page_context: dict | None,
    *,
    reference_dt: datetime | None = None,
) -> str | None:
    meridiem = mention.get("meridiem")
    if not meridiem and reference_dt is not None:
        local_reference = reference_dt.astimezone(_tzinfo_from_page(page_context))
        meridiem = "pm" if local_reference.hour >= 12 else "am"
    if not meridiem:
        return None
    hour = int(mention["hour"])
    minute = int(mention["minute"])
    hour %= 12
    if meridiem == "pm":
        hour += 12
    tz_info = _tzinfo_from_page(page_context)
    local_dt = datetime.combine(target_day, time(hour=hour, minute=minute)).replace(tzinfo=tz_info)
    return local_dt.isoformat()


def _extract_reschedule_time_pair(message_text: str) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    mentions = _extract_time_mentions(message_text)
    if not mentions:
        return None, None
    to_match = re.search(r"\bto\b", message_text, flags=re.IGNORECASE)
    if len(mentions) >= 2:
        return mentions[0], mentions[1]
    if to_match and mentions[0]["start"] > to_match.start():
        return None, mentions[0]
    if to_match:
        return mentions[0], None
    return None, mentions[0]


def _strip_time_phrases_for_date_parsing(message_text: str) -> str:
    cleaned = _normalize_text(message_text)
    cleaned = re.sub(
        r"\bfrom\s+\d{1,2}(?::\d{2})?\s*(?:am|pm)?\s*(?:-|to)\s*\d{1,2}(?::\d{2})?\s*(?:am|pm)?\b",
        " ",
        cleaned,
        flags=re.IGNORECASE,
    )
    cleaned = re.sub(
        r"\bat\s+\d{1,2}(?::\d{2})?\s*(?:am|pm)\b",
        " ",
        cleaned,
        flags=re.IGNORECASE,
    )
    cleaned = re.sub(
        r"\b\d{1,2}(?::\d{2})?\s*(?:am|pm)\b",
        " ",
        cleaned,
        flags=re.IGNORECASE,
    )
    return _normalize_text(cleaned)


def _extract_reschedule_date_pair(message_text: str, page_context: dict | None) -> tuple[date | None, date | None]:
    normalized = _normalize_text(message_text)
    to_match = re.search(r"\bto\b", normalized, flags=re.IGNORECASE)
    source_segment = normalized
    destination_segment = ""
    if to_match:
        source_segment = normalized[:to_match.start()]
        destination_segment = normalized[to_match.end():]

    source_day = _extract_relative_or_named_date(_strip_time_phrases_for_date_parsing(source_segment), page_context)
    destination_day = _extract_relative_or_named_date(_strip_time_phrases_for_date_parsing(destination_segment), page_context)

    if source_day and not destination_day:
        date_mentions = _extract_date_mentions_with_spans(normalized, page_context)
        if len(date_mentions) >= 2:
            destination_day = date_mentions[1]["date"]
    if not source_day and not destination_day:
        return None, None
    if not source_day:
        source_day = destination_day
    if not destination_day:
        destination_day = source_day
    return source_day, destination_day


def _build_local_iso_from_parts(target_day: date, clock_parts: tuple[int, int], page_context: dict | None) -> str:
    hour, minute = clock_parts
    tz_info = _tzinfo_from_page(page_context)
    local_dt = datetime.combine(target_day, time(hour=hour, minute=minute)).replace(tzinfo=tz_info)
    return local_dt.isoformat()


def _build_duration_reply_options(
    *,
    action_type: str,
    client_row: dict,
    arguments: dict[str, Any],
    page_context: dict | None,
) -> list[dict[str, Any]]:
    client_name = _format_person_name(client_row)
    workout_display_label = _normalize_text(arguments.get("workout_display_label")) or _normalize_text(arguments.get("workout_category")) or "workout"
    target_date = _normalize_text(arguments.get("target_date"))
    start_time = _normalize_text(arguments.get("start_time"))
    session_phrase = ""
    if target_date and start_time:
        start_dt = _coerce_datetime_value(start_time)
        if start_dt:
            session_phrase = f" on {_format_time_range(start_dt, None, page_context)}"
    elif target_date:
        try:
            target_day = _parse_local_date(target_date, page_context)
            session_phrase = f" on {target_day.strftime('%b %-d, %Y')}"
        except ValueError:
            session_phrase = f" on {target_date}"

    verb = "Assign" if action_type == "assign_workout" else "Book"
    options = []
    for duration in DEFAULT_CUSTOM_DURATION_CHOICES:
        message = f"{verb} {client_name} a {workout_display_label} workout{session_phrase} for {duration} minutes."
        options.append({"label": f"{duration} min", "message": message})
    return options


def _extract_duration_minutes_from_message(message_text: str) -> int | None:
    lowered = _normalize_text(message_text).lower()
    hour_match = re.search(r"\b1\s*(?:hour|hr)\b", lowered)
    if hour_match:
        return 60
    minute_match = re.search(r"\b(20|30|45|60)\s*(?:minute|minutes|min|mins)\b", lowered)
    if minute_match:
        return int(minute_match.group(1))
    hyphenated_match = re.search(r"\b(20|30|45|60)\s*-\s*minute\b", lowered)
    if hyphenated_match:
        return int(hyphenated_match.group(1))
    return None


def _extract_custom_workout_categories(message_text: str) -> list[str]:
    lowered = _normalize_text(message_text).lower()
    matches: list[tuple[int, str]] = []
    seen_tokens: set[str] = set()
    for pattern, token, _pretty in CUSTOM_WORKOUT_COMPONENTS:
        match = re.search(pattern, lowered, flags=re.IGNORECASE)
        if match and token not in seen_tokens:
            seen_tokens.add(token)
            matches.append((match.start(), token))
    matches.sort(key=lambda item: item[0])
    return [token for _idx, token in matches]


def _format_custom_workout_display_label(custom_categories: list[str] | None) -> str | None:
    if not custom_categories:
        return None
    pretty_lookup = {token: pretty for _pattern, token, pretty in CUSTOM_WORKOUT_COMPONENTS}
    labels = [pretty_lookup.get(token, token.title()) for token in custom_categories]
    return ", ".join(labels)


def _extract_workout_request_from_message(message_text: str) -> dict[str, Any] | None:
    lowered = _normalize_text(message_text).lower()
    explicit_home_custom = HOME_WORKOUT_TOKEN.lower() in lowered
    explicit_gym_custom = CUSTOM_WORKOUT_TOKEN.lower() in lowered
    custom_categories = _extract_custom_workout_categories(message_text)
    if explicit_home_custom or explicit_gym_custom or len(custom_categories) > 1:
        workout_category = HOME_WORKOUT_TOKEN if explicit_home_custom else CUSTOM_WORKOUT_TOKEN
        return {
            "workout_category": workout_category,
            "custom_categories": custom_categories,
            "display_label": _format_custom_workout_display_label(custom_categories) or workout_category,
            "is_custom": True,
        }
    for category in sorted(KNOWN_WORKOUT_CATEGORIES, key=len, reverse=True):
        if category.lower() in lowered:
            return {
                "workout_category": category,
                "custom_categories": [],
                "display_label": category,
                "is_custom": category in {CUSTOM_WORKOUT_TOKEN, HOME_WORKOUT_TOKEN},
            }
    for pattern, category in WORKOUT_CATEGORY_ALIASES:
        if re.search(pattern, lowered, flags=re.IGNORECASE):
            return {
                "workout_category": category,
                "custom_categories": [],
                "display_label": category,
                "is_custom": category in {CUSTOM_WORKOUT_TOKEN, HOME_WORKOUT_TOKEN},
            }
    return None


def _extract_swap_segment_details(segment_text: str, page_context: dict | None) -> tuple[date | None, dict[str, Any] | None, dict[str, Any] | None]:
    target_day = _extract_relative_or_named_date(segment_text, page_context)
    mentions = _extract_time_mentions(segment_text)
    start_mention = mentions[0] if mentions else None
    end_mention = mentions[1] if len(mentions) > 1 else None
    return target_day, start_mention, end_mention


def _prepare_swap_sessions_action(message_text: str, actor_row: dict, page_context: dict | None) -> dict[str, Any]:
    segments = re.split(r"\bwith\b", message_text, maxsplit=1, flags=re.IGNORECASE)
    first_client = None
    second_client = None
    first_day = None
    first_start_mention = None
    first_end_mention = None
    second_day = None
    second_start_mention = None
    second_end_mention = None

    if len(segments) == 2:
        first_client = _match_client_from_segment(actor_row, segments[0], page_context, allow_page_fallback=True)
        if not first_client:
            first_client = _match_client_from_message(actor_row, message_text, page_context)
        if not first_client:
            return {"success": False, "error": "Tell me which client's session should move first."}
        second_client = _match_client_from_segment(actor_row, segments[1], page_context, fallback_client=first_client)
        first_day, first_start_mention, first_end_mention = _extract_swap_segment_details(segments[0], page_context)
        second_day, second_start_mention, second_end_mention = _extract_swap_segment_details(segments[1], page_context)
    else:
        first_client = _match_client_from_message(actor_row, message_text, page_context)
        date_mentions = _extract_date_mentions_with_spans(message_text, page_context)
        if first_client and len(date_mentions) >= 2:
            first_day = date_mentions[0]["date"]
            second_day = date_mentions[1]["date"]
            first_segment = message_text[:date_mentions[1]["start"]]
            second_segment = message_text[date_mentions[1]["start"]:]
            first_mentions = _extract_time_mentions(first_segment)
            second_mentions = _extract_time_mentions(second_segment)
            first_start_mention = first_mentions[0] if first_mentions else None
            first_end_mention = first_mentions[1] if len(first_mentions) > 1 else None
            second_start_mention = second_mentions[0] if second_mentions else None
            second_end_mention = second_mentions[1] if len(second_mentions) > 1 else None
            second_client = _match_client_from_segment(actor_row, second_segment, page_context, fallback_client=first_client)
        else:
            return {
                "success": False,
                "error": "Tell me both sessions to swap, like 'swap Client A on March 30 at 5:00 PM with Client B on March 31 at 5:00 PM'.",
            }

    if not first_day or not second_day:
        return {"success": False, "error": "I need both session dates to swap them."}

    first_sessions = _find_client_day_sessions(actor_row, first_client, first_day, page_context)
    second_sessions = _find_client_day_sessions(actor_row, second_client, second_day, page_context)
    first_session = _match_session_by_window_hint(first_sessions, first_start_mention, first_end_mention, page_context)
    if not first_session:
        return {
            "success": False,
            "error": f"I could not match {_format_person_name(first_client)}'s session on {first_day.isoformat()}. Tell me the exact session time shown on the calendar.",
        }
    second_session = _match_session_by_window_hint(second_sessions, second_start_mention, second_end_mention, page_context)
    if not second_session:
        return {
            "success": False,
            "error": f"I could not match {_format_person_name(second_client)}'s session on {second_day.isoformat()}. Tell me the exact session time shown on the calendar.",
        }
    if first_session.get("id") == second_session.get("id"):
        return {"success": False, "error": "I need two different sessions to perform a swap."}

    return prepare_fitbase_action(
        {
            "action_type": "swap_sessions",
            "client_id": first_client["id"],
            "client_name": _format_person_name(first_client),
            "event_id": first_session["id"],
            "second_client_id": second_client["id"],
            "second_client_name": _format_person_name(second_client),
            "swap_event_id": second_session["id"],
            "timezone": _normalize_text((page_context or {}).get("timezone")) or None,
        },
        actor_row,
        page_context,
    )


def _message_uses_session_reference(message_text: str) -> bool:
    lowered = _normalize_text(message_text).lower()
    if not lowered:
        return False
    reference_patterns = (
        r"\bthat session\b",
        r"\bthis session\b",
        r"\bsame session\b",
        r"\bthat workout\b",
        r"\bthis workout\b",
        r"\bthat one\b",
        r"\bit\b",
    )
    return any(re.search(pattern, lowered) for pattern in reference_patterns)


def _extract_date_mentions_with_spans(message_text: str, page_context: dict | None) -> list[dict[str, Any]]:
    mentions: list[dict[str, Any]] = []
    seen_spans: set[tuple[int, int]] = set()

    def add_mention(start: int, end: int, raw_value: str, parsed: date | None) -> None:
        if not parsed or (start, end) in seen_spans:
            return
        seen_spans.add((start, end))
        mentions.append(
            {
                "start": start,
                "end": end,
                "raw": raw_value,
                "date": parsed,
            }
        )

    lowered = _normalize_text(message_text).lower()
    relative_words = {
        "today": 0,
        "tomorrow": 1,
        "yesterday": -1,
    }
    tz_info = _tzinfo_from_page(page_context)
    today_local = datetime.now(tz_info).date()
    for word, offset in relative_words.items():
        for match in re.finditer(rf"\b{word}\b", lowered):
            add_mention(match.start(), match.end(), match.group(0), today_local + timedelta(days=offset))

    for match in re.finditer(r"\b\d{4}-\d{2}-\d{2}\b", message_text):
        add_mention(match.start(), match.end(), match.group(0), _parse_local_date(match.group(0), page_context))

    for match in re.finditer(r"\b\d{1,2}/\d{1,2}/\d{2,4}\b", message_text):
        add_mention(match.start(), match.end(), match.group(0), _parse_local_date(match.group(0), page_context))

    month_pattern = re.compile(
        r"\b(?:(?:mon|monday|tue|tues|tuesday|wed|wednesday|thu|thur|thurs|thursday|fri|friday|sat|saturday|sun|sunday)\s+)?"
        r"((?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|"
        r"aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)"
        r"\s+\d{1,2}(?:st|nd|rd|th)?(?:,\s*\d{4})?)\b",
        flags=re.IGNORECASE,
    )
    for match in month_pattern.finditer(message_text):
        raw_value = match.group(1)
        add_mention(match.start(1), match.end(1), raw_value, _parse_local_date(raw_value, page_context))

    mentions.sort(key=lambda item: item["start"])
    return mentions


def _extract_booking_slots_from_message(message_text: str, page_context: dict | None) -> list[dict[str, Any]]:
    date_mentions = _extract_date_mentions_with_spans(message_text, page_context)
    if not date_mentions:
        return []

    slots: list[dict[str, Any]] = []
    for index, mention in enumerate(date_mentions):
        next_boundary = date_mentions[index + 1]["start"] if index + 1 < len(date_mentions) else len(message_text)
        segment = message_text[mention["start"]:next_boundary]
        clock_window = _extract_clock_window_from_message(segment)
        if clock_window:
            start_parts, end_parts, duration_minutes = clock_window
            slots.append(
                {
                    "target_date": mention["date"].isoformat(),
                    "start_time": _build_local_iso_from_parts(mention["date"], start_parts, page_context),
                    "end_time": _build_local_iso_from_parts(mention["date"], end_parts, page_context),
                    "duration_minutes": duration_minutes,
                }
            )
            continue
        clock_parts = _extract_clock_from_message(segment)
        if not clock_parts:
            continue
        slots.append(
            {
                "target_date": mention["date"].isoformat(),
                "start_time": _build_local_iso_from_parts(mention["date"], clock_parts, page_context),
                "duration_minutes": 60,
            }
        )
    return slots


def _pending_action_start_date(arguments: dict[str, Any], page_context: dict | None) -> date | None:
    start_dt = _coerce_datetime_value(arguments.get("start_time"))
    if not start_dt:
        return None
    return start_dt.astimezone(_tzinfo_from_page(page_context)).date()


def _pending_action_matches_time(
    arguments: dict[str, Any],
    mention: dict[str, Any] | None,
    page_context: dict | None,
) -> bool:
    if not mention:
        return True
    start_dt = _coerce_datetime_value(arguments.get("start_time"))
    return _datetime_matches_mention(start_dt, mention, page_context)


def _prepare_multi_booking_actions(message_text: str, actor_row: dict, page_context: dict | None) -> list[dict[str, Any]] | None:
    lowered = _normalize_text(message_text).lower()
    if not any(keyword in lowered for keyword in ("schedule", "book")):
        return None
    client_row = _match_client_from_message(actor_row, message_text, page_context)
    if not client_row:
        return None
    workout_request = _extract_workout_request_from_message(message_text)
    slots = _extract_booking_slots_from_message(message_text, page_context)
    if len(slots) < 2:
        return None

    prepared: list[dict[str, Any]] = []
    for slot in slots:
        arguments: dict[str, Any] = {
            "action_type": "book_and_assign_workout" if workout_request else "book_session",
            "client_id": client_row["id"],
            "client_name": _format_person_name(client_row),
            "target_date": slot["target_date"],
            "start_time": slot["start_time"],
            "duration_minutes": slot["duration_minutes"],
        }
        if slot.get("end_time"):
            arguments["end_time"] = slot["end_time"]
        if workout_request:
            arguments["workout_category"] = workout_request["workout_category"]
            if workout_request.get("custom_categories"):
                arguments["custom_categories"] = workout_request["custom_categories"]
            if workout_request.get("display_label"):
                arguments["workout_display_label"] = workout_request["display_label"]
        prepared_result = prepare_fitbase_action(arguments, actor_row, page_context)
        if not prepared_result.get("success") or prepared_result.get("kind") != "pending_action":
            return None
        prepared.append(prepared_result)
    return prepared


def _merge_assign_request_into_pending_bookings(
    segment_text: str,
    actor_row: dict,
    page_context: dict | None,
    prepared_items: list[dict[str, Any]],
) -> tuple[bool, str | None]:
    workout_request = _extract_workout_request_from_message(segment_text)
    if not workout_request:
        return False, None

    client_row = _match_client_from_message(actor_row, segment_text, page_context)
    candidate_client_id = client_row.get("id") if client_row else None
    if candidate_client_id is None:
        unique_client_ids = {
            _coerce_int((item.get("arguments") or {}).get("client_id"))
            for item in prepared_items
            if item.get("action_type") in {"book_session", "book_and_assign_workout"}
        }
        unique_client_ids.discard(None)
        if len(unique_client_ids) == 1:
            candidate_client_id = next(iter(unique_client_ids))

    target_day = _extract_relative_or_named_date(segment_text, page_context)
    start_hint = None
    clock_window = _extract_clock_window_from_message(segment_text)
    if clock_window:
        start_parts, _end_parts, _duration_minutes = clock_window
        start_hint = {
            "hour": ((start_parts[0] - 1) % 12) + 1,
            "minute": start_parts[1],
            "meridiem": "pm" if start_parts[0] >= 12 else "am",
        }
    else:
        start_hint = _extract_time_mentions(segment_text)[0] if _extract_time_mentions(segment_text) else None

    matching_indexes: list[int] = []
    for index, item in enumerate(prepared_items):
        if item.get("action_type") not in {"book_session", "book_and_assign_workout"}:
            continue
        arguments = item.get("arguments") or {}
        if candidate_client_id is not None and _coerce_int(arguments.get("client_id")) != candidate_client_id:
            continue
        if target_day and _pending_action_start_date(arguments, page_context) != target_day:
            continue
        if not _pending_action_matches_time(arguments, start_hint, page_context):
            continue
        matching_indexes.append(index)

    if not matching_indexes:
        return False, None
    if len(matching_indexes) > 1:
        return False, "I found more than one matching scheduled request in that message. Add the exact time for the workout assignment."

    selected_index = matching_indexes[0]
    existing_item = prepared_items[selected_index]
    existing_arguments = dict(existing_item.get("arguments") or {})
    merged_arguments = {
        **existing_arguments,
        "action_type": "book_and_assign_workout",
        "workout_category": workout_request["workout_category"],
        "custom_categories": workout_request.get("custom_categories") or [],
        "workout_display_label": workout_request.get("display_label"),
    }
    duration_minutes = _extract_duration_minutes_from_message(segment_text)
    if duration_minutes:
        merged_arguments["duration_minutes"] = duration_minutes
    elif workout_request.get("is_custom"):
        merged_arguments["duration_minutes"] = DEFAULT_ASSIGNED_WORKOUT_DURATION_MINUTES

    merged_result = prepare_fitbase_action(merged_arguments, actor_row, page_context)
    if not merged_result.get("success") or merged_result.get("kind") != "pending_action":
        return False, merged_result.get("error") or "I couldn't attach that workout to the scheduled request."

    prepared_items[selected_index] = merged_result
    return True, None


def _split_batch_schedule_requests(message_text: str) -> list[str]:
    raw_text = str(message_text or "")
    if not _normalize_text(raw_text):
        return []
    segments = [
        _normalize_text(segment.strip(" ,.;"))
        for segment in _BATCH_REQUEST_SPLIT_PATTERN.split(raw_text)
        if _normalize_text(segment.strip(" ,.;"))
    ]
    return segments


def maybe_prepare_batched_schedule_actions(
    message_text: str,
    actor_row: dict,
    page_context: dict | None,
    recent_history: list[dict[str, str]] | None = None,
) -> dict[str, Any] | None:
    segments = _split_batch_schedule_requests(message_text)
    if len(segments) < 2:
        return None
    if len(segments) > BATCH_ACTION_LIMIT:
        return {
            "success": False,
            "kind": "pending_action_batch_limit",
            "error": f"I can handle up to {BATCH_ACTION_LIMIT} requests at a time. Split the rest into another message.",
            "requested_count": len(segments),
        }

    prepared_items: list[dict[str, Any]] = []
    synthetic_history = list(recent_history or [])
    for segment in segments:
        merged_assign, merge_error = _merge_assign_request_into_pending_bookings(
            segment,
            actor_row,
            page_context,
            prepared_items,
        )
        if merged_assign:
            synthetic_history.append({"role": "user", "content": segment})
            continue
        if merge_error:
            return {
                "success": False,
                "kind": "pending_action_batch_parse_error",
                "error": merge_error,
            }

        multi_booking_results = _prepare_multi_booking_actions(segment, actor_row, page_context)
        if multi_booking_results:
            prepared_items.extend(multi_booking_results)
            if len(prepared_items) > BATCH_ACTION_LIMIT:
                return {
                    "success": False,
                    "kind": "pending_action_batch_limit",
                    "error": f"I can handle up to {BATCH_ACTION_LIMIT} requests at a time. Split the rest into another message.",
                    "requested_count": len(prepared_items),
                }
            synthetic_history.append({"role": "user", "content": segment})
            continue

        result = maybe_prepare_direct_schedule_action(
            segment,
            actor_row,
            page_context,
            synthetic_history,
        )
        if not result or not result.get("success") or result.get("kind") != "pending_action":
            return {
                "success": False,
                "kind": "pending_action_batch_parse_error",
                "error": (result or {}).get("error")
                or "I couldn't clearly break that into separate requests. Keep it to up to 3 clear requests in one message.",
            }
        prepared_items.append(result)
        synthetic_history.append({"role": "user", "content": segment})

    return {
        "success": True,
        "kind": "pending_action_batch",
        "count": len(prepared_items),
        "items": prepared_items,
    }


def maybe_prepare_direct_schedule_action(
    message_text: str,
    actor_row: dict,
    page_context: dict | None,
    recent_history: list[dict[str, str]] | None = None,
) -> dict[str, Any] | None:
    role = _normalize_role(actor_row)
    if role not in {"trainer", "admin"}:
        return None

    lowered = _normalize_text(message_text).lower()
    workout_optimization_markers = ("organize", "reorganize", "optimize", "rearrange", "group", "efficient", "efficiency")
    if not any(keyword in lowered for keyword in ("swap", "switch", "cancel", "reschedule", "schedule", "book", "assign", "move", "delete", "remove", "complete", "mark", *workout_optimization_markers)):
        return None
    workout_request = _extract_workout_request_from_message(message_text)
    action_type = None
    if "swap" in lowered or "switch" in lowered:
        action_type = "swap_sessions"
    elif "workout" in lowered and any(marker in lowered for marker in workout_optimization_markers):
        action_type = "optimize_workout_layout"
    elif "delete" in lowered or "remove" in lowered:
        action_type = "delete_session"
    elif "cancel" in lowered:
        action_type = "cancel_session"
    elif "complete" in lowered or re.search(r"\bmark\b.*\bcompleted?\b", lowered):
        action_type = "complete_session"
    elif re.search(r"\b(mark|set|change)\b.*\bbooked\b", lowered):
        action_type = "set_session_booked"
    elif "reschedule" in lowered or "move " in lowered:
        action_type = "reschedule_session"
    elif "assign" in lowered and "workout" in lowered:
        action_type = "assign_workout"
    elif "schedule" in lowered or "book" in lowered:
        action_type = "book_and_assign_workout" if workout_request else "book_session"
    if not action_type:
        return None
    if action_type != "optimize_workout_layout":
        if "session" not in lowered and "sessions" not in lowered and "workout" not in lowered and "calendar" not in lowered:
            return None

    prior_user_message = _latest_prior_user_message(recent_history, message_text)
    parse_message = message_text
    if prior_user_message and _message_uses_session_reference(message_text):
        parse_message = f"{prior_user_message} {message_text}"

    if action_type == "swap_sessions":
        return _prepare_swap_sessions_action(message_text, actor_row, page_context)

    workout_request = _extract_workout_request_from_message(parse_message)

    client_row = _match_client_from_message(actor_row, parse_message, page_context)
    if not client_row:
        return None

    arguments: dict[str, Any] = {
        "action_type": action_type,
        "client_id": client_row["id"],
        "client_name": _format_person_name(client_row),
    }

    source_day = None
    destination_day = None
    if action_type == "reschedule_session":
        source_day, destination_day = _extract_reschedule_date_pair(parse_message, page_context)
        target_day = source_day
    else:
        target_day = _extract_relative_or_named_date(parse_message, page_context)
    clock_window = _extract_clock_window_from_message(parse_message)
    if target_day:
        arguments["target_date"] = target_day.isoformat()
        if action_type == "assign_workout":
            if clock_window:
                start_parts, _end_parts, duration_minutes = clock_window
                arguments["start_time"] = _build_local_iso_from_parts(target_day, start_parts, page_context)
                arguments["duration_minutes"] = duration_minutes
            else:
                clock_parts = _extract_clock_from_message(parse_message)
                if clock_parts:
                    arguments["start_time"] = _build_local_iso_from_parts(target_day, clock_parts, page_context)

    if workout_request:
        arguments["workout_category"] = workout_request["workout_category"]
        if workout_request.get("custom_categories"):
            arguments["custom_categories"] = workout_request["custom_categories"]
        if workout_request.get("display_label"):
            arguments["workout_display_label"] = workout_request["display_label"]
        duration_minutes = _extract_duration_minutes_from_message(parse_message)
        if duration_minutes:
            arguments["duration_minutes"] = duration_minutes
        elif workout_request.get("is_custom"):
            if not workout_request.get("custom_categories"):
                return {
                    "success": False,
                    "error": "Which categories would you like in this custom workout?",
                }
            arguments["duration_minutes"] = DEFAULT_ASSIGNED_WORKOUT_DURATION_MINUTES

    if action_type == "reschedule_session":
        if not source_day:
            return None
        current_time_hint, new_time_hint = _extract_reschedule_time_pair(parse_message)
        client_sessions = _find_client_day_sessions(actor_row, client_row, source_day, page_context)
        target_session = _match_session_by_time_hint(client_sessions, current_time_hint, page_context)
        if not target_session:
            if current_time_hint or new_time_hint:
                time_label = current_time_hint.get("raw") if current_time_hint else "that"
                return {
                    "success": False,
                    "error": f"I could not match {_format_person_name(client_row)}'s {time_label.strip()} session on {source_day.isoformat()}. Tell me the exact current session time or choose it from the calendar.",
                }
            return None
        duration_minutes = max(
            15,
            int(((target_session.get("end_time") - target_session.get("start_time")).total_seconds()) // 60)
            if target_session.get("start_time") and target_session.get("end_time")
            else 60,
        )
        new_start_iso = None
        if new_time_hint:
            new_start_iso = _build_local_iso_from_mention(
                destination_day or source_day,
                new_time_hint,
                page_context,
                reference_dt=target_session.get("start_time"),
            )
        if not new_start_iso:
            clock_parts = _extract_clock_from_message(parse_message)
            if clock_parts and (destination_day or source_day):
                new_start_iso = _build_local_iso_from_parts(destination_day or source_day, clock_parts, page_context)
        if not new_start_iso and (destination_day or source_day) and target_session.get("start_time"):
            reference_dt = target_session.get("start_time").astimezone(_tzinfo_from_page(page_context))
            new_start_iso = _build_local_iso_from_parts(
                destination_day or source_day,
                (reference_dt.hour, reference_dt.minute),
                page_context,
            )
        if not new_start_iso:
            return {
                "success": False,
                "error": f"I found {_format_person_name(client_row)}'s session, but I still need the new time. Tell me the new start time with AM or PM.",
            }
        arguments["event_id"] = target_session["id"]
        arguments["source_start_time"] = target_session.get("start_time").isoformat() if target_session.get("start_time") else None
        if destination_day:
            arguments["target_date"] = destination_day.isoformat()
        arguments["start_time"] = new_start_iso
        arguments["duration_minutes"] = duration_minutes
        result = prepare_fitbase_action(arguments, actor_row, page_context)
        return result if result else None

    if action_type in {"book_session", "book_and_assign_workout", "reschedule_session"}:
        if target_day and clock_window:
            start_parts, end_parts, duration_minutes = clock_window
            arguments["start_time"] = _build_local_iso_from_parts(target_day, start_parts, page_context)
            arguments["end_time"] = _build_local_iso_from_parts(target_day, end_parts, page_context)
            arguments["duration_minutes"] = duration_minutes
        else:
            clock_parts = _extract_clock_from_message(parse_message)
            if target_day and clock_parts:
                arguments["start_time"] = _build_local_iso_from_parts(target_day, clock_parts, page_context)
                arguments["duration_minutes"] = 60
            else:
                return None

    if action_type == "optimize_workout_layout":
        if target_day:
            arguments["target_date"] = target_day.isoformat()
            if clock_window:
                start_parts, _end_parts, _duration_minutes = clock_window
                arguments["start_time"] = _build_local_iso_from_parts(target_day, start_parts, page_context)
            else:
                clock_parts = _extract_clock_from_message(parse_message)
                if clock_parts:
                    arguments["start_time"] = _build_local_iso_from_parts(target_day, clock_parts, page_context)
        if "active workout" in lowered or "current workout" in lowered or "workout builder" in lowered or "builder" in lowered:
            arguments["target_scope"] = "active_workout"

    if action_type == "assign_workout" and "target_date" not in arguments and "start_time" not in arguments:
        return None

    if action_type in {"cancel_session", "complete_session", "set_session_booked", "delete_session"} and "target_date" not in arguments and "start_time" not in arguments:
        return None

    result = prepare_fitbase_action(arguments, actor_row, page_context)
    return result if result else None


def _generate_workout_payload_for_client(
    trainer_row: dict,
    client_row: dict,
    workout_category: str,
    *,
    duration_minutes: int | None = None,
    custom_categories: list[str] | None = None,
) -> tuple[dict | None, str | None, dict[str, Any] | None]:
    app_module = _load_app_module()
    selected_category = workout_category
    trainer_can_generate_premium = app_module.trainer_has_premium_generation_access(trainer_row)
    subscription_type = client_row.get("subscription_type")
    trial_end_date = client_row.get("trial_end_date")
    today = datetime.today().date()
    if not trainer_can_generate_premium:
        if subscription_type == "free" or (
            subscription_type == "premium" and trial_end_date and today > trial_end_date
        ):
            if selected_category != app_module.FREE_SUBSCRIPTION_CATEGORY:
                return None, "This client needs Premium access to use that workout category.", None

    duration_minutes = int(duration_minutes or client_row.get("workout_duration") or 60)
    user_level = get_user_level(client_row.get("exercise_history"))
    trainer_catalog_mode, trainer_catalog_gym_id = app_module._catalog_scope_from_user_row(trainer_row)
    try:
        workout_plan, skipped_meta = generate_workout(
            selected_category,
            user_level,
            client_row["id"],
            duration_minutes,
            custom_categories=custom_categories,
            catalog_mode=trainer_catalog_mode,
            catalog_gym_id=trainer_catalog_gym_id,
        )
    except ValueError as exc:
        return None, str(exc), None
    workout_payload = {
        "plan": workout_plan,
        "duration_minutes": duration_minutes,
        "skipped": skipped_meta,
        "catalog_mode": trainer_catalog_mode,
        "catalog_gym_id": trainer_catalog_gym_id,
        "media_owner_user_id": client_row.get("trainer_id") or trainer_row["id"],
        "category": selected_category,
    }
    if custom_categories:
        workout_payload["custom_categories"] = custom_categories
    workout_payload, optimization_meta = app_module._optimize_workout_payload_layout(
        workout_payload,
        preserve_block_order=True,
    )
    return workout_payload, None, optimization_meta


def _schedule_conflicts_excluding_ids(
    cursor,
    trainer_id: int,
    client_id: int,
    start_dt: datetime,
    end_dt: datetime,
    exclude_ids: list[int] | None = None,
) -> tuple[bool, str | None]:
    app_module = _load_app_module()
    exclude_ids = [int(value) for value in (exclude_ids or []) if value]
    params = [trainer_id, start_dt, end_dt]
    exclude_clause = ""
    if exclude_ids:
        exclude_clause = " AND NOT (id = ANY(%s))"
        params.append(exclude_ids)

    cursor.execute(
        f"""
        SELECT 1
          FROM trainer_schedule
         WHERE trainer_id = %s
           AND end_time > %s
           AND start_time < %s
           AND is_self_booked = FALSE
           {exclude_clause}
         LIMIT 1
        """,
        params,
    )
    if cursor.fetchone():
        return True, "Trainer already has a booking in that window."

    if app_module._trainer_time_off_conflict(cursor, trainer_id, start_dt, end_dt):
        return True, "Trainer has personal time blocked during that window."

    params = [client_id, start_dt, end_dt]
    if exclude_ids:
        params.append(exclude_ids)
    cursor.execute(
        f"""
        SELECT 1
          FROM trainer_schedule
         WHERE client_id = %s
           AND end_time > %s
           AND start_time < %s
           {exclude_clause}
         LIMIT 1
        """,
        params,
    )
    if cursor.fetchone():
        return True, "Client is already booked for that time."
    return False, None


def _resolve_owner_trainer_id(actor_row: dict, client_row: dict) -> int:
    if _normalize_role(actor_row) == "trainer":
        return actor_row["id"]
    return _coerce_int(client_row.get("trainer_id")) or actor_row["id"]


def _build_client_counts_response(cursor, trainer_id: int, client_id: int) -> dict[str, Any]:
    app_module = _load_app_module()
    cursor.execute(
        "SELECT sessions_remaining, sessions_booked, workouts_completed FROM users WHERE id = %s",
        (client_id,),
    )
    counts_row = cursor.fetchone() or {}
    cursor.execute(
        """
        SELECT COUNT(*)::int AS completed_count
          FROM trainer_schedule
         WHERE trainer_id = %s
           AND client_id = %s
           AND status = 'completed'
        """,
        (trainer_id, client_id),
    )
    completed_row = cursor.fetchone() or {}
    sessions_booked = int(counts_row.get("sessions_booked") or 0)
    sessions_completed = int(completed_row.get("completed_count") or 0)
    summary = app_module._resolve_client_session_summary(
        cursor,
        trainer_id,
        client_id,
        sessions_booked,
        sessions_completed,
        counts_row.get("sessions_remaining"),
    )
    return {
        "sessions_booked": sessions_booked,
        "sessions_remaining": summary.get("sessions_total"),
        "sessions_completed": sessions_completed,
        "workouts_completed": counts_row.get("workouts_completed"),
        "sessions_left": summary.get("sessions_left"),
    }


def _load_action_event_row(cursor, event_id: int, actor_row: dict) -> tuple[dict | None, str | None]:
    actor_role = _normalize_role(actor_row)
    params: list[Any] = [event_id]
    trainer_clause = ""
    if actor_role != "admin":
        trainer_clause = " AND ts.trainer_id = %s"
        params.append(actor_row["id"])
    cursor.execute(
        f"""
        SELECT ts.id,
               ts.trainer_id,
               ts.client_id,
               ts.start_time,
               ts.end_time,
               ts.status,
               ts.note,
               ts.session_id,
               ts.session_category,
               ts.session_completed_at,
               ts.session_payload,
               CASE WHEN ts.session_payload IS NULL THEN FALSE ELSE TRUE END AS has_session_workout,
               c.name AS client_name,
               c.last_name AS client_last_name,
               c.username AS client_username
          FROM trainer_schedule ts
          JOIN users c ON c.id = ts.client_id
         WHERE ts.id = %s
           {trainer_clause}
        """,
        params,
    )
    row = cursor.fetchone()
    if not row:
        return None, "Scheduled session not found."
    return row, None


def _apply_schedule_status_update(action_row: dict, actor_row: dict, client_row: dict, target_status: str) -> dict[str, Any]:
    payload = action_row.get("arguments") or {}
    if isinstance(payload, str):
        payload = json.loads(payload)
    event_id = _coerce_int(payload.get("event_id"))
    if not event_id:
        return {"success": False, "error": "Scheduled session not found."}

    app_module = _load_app_module()
    owner_trainer_id = _resolve_owner_trainer_id(actor_row, client_row)
    session_logged = False
    session_meta_payload = None
    session_log_error = None
    logged_workout_label = None
    client_counts: dict[str, Any] | None = None
    trainer_completed_delta = 0

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            row, row_error = _load_action_event_row(cursor, event_id, actor_row)
            if row_error:
                return {"success": False, "error": row_error}
            if row.get("client_id") != client_row.get("id"):
                return {"success": False, "error": "That scheduled session belongs to a different client."}

            current_status = (_normalize_text(row.get("status")) or "booked").lower()
            if current_status == target_status:
                return {"success": False, "error": f"That session is already marked {target_status}."}

            if target_status == "booked":
                cursor.execute(
                    "SELECT sessions_remaining, sessions_booked FROM users WHERE id = %s",
                    (client_row["id"],),
                )
                counts_snapshot = cursor.fetchone() or {}
                remaining = counts_snapshot.get("sessions_remaining")
                booked_now = int(counts_snapshot.get("sessions_booked") or 0)
                cursor.execute(
                    """
                    SELECT COUNT(*)::int AS completed_count
                      FROM trainer_schedule
                     WHERE trainer_id = %s
                       AND client_id = %s
                       AND status = 'completed'
                    """,
                    (owner_trainer_id, client_row["id"]),
                )
                completed_row = cursor.fetchone() or {}
                summary_snapshot = app_module._resolve_client_session_summary(
                    cursor,
                    owner_trainer_id,
                    client_row["id"],
                    booked_now,
                    int(completed_row.get("completed_count") or 0),
                    remaining,
                )
                remaining_quota = summary_snapshot.get("sessions_left")
                if remaining_quota is not None and remaining_quota <= 0:
                    return {"success": False, "error": "Client has no sessions remaining to mark as booked."}

            if current_status != "completed" and target_status == "completed":
                base_category = None
                assigned_payload = app_module._parse_session_payload(row.get("session_payload"))
                if assigned_payload and app_module._session_payload_has_plan(assigned_payload):
                    base_category = (
                        assigned_payload.get("category")
                        if isinstance(assigned_payload, dict)
                        else None
                    ) or row.get("session_category")
                    comp_success, comp_error, comp_meta = app_module._complete_workout_from_payload(
                        client_row["id"],
                        base_category,
                        assigned_payload,
                        session_id_override=row.get("session_id"),
                    )
                else:
                    comp_success, comp_error, comp_meta = app_module._complete_workout_for_user(client_row["id"])
                if comp_success:
                    session_logged = True
                    session_meta_payload = comp_meta
                    logged_workout_label = _normalize_text((comp_meta or {}).get("display_category")) or _normalize_text(base_category) or _normalize_text(row.get("session_category")) or None
                else:
                    session_log_error = comp_error or "No workout was logged for this session."

            cursor.execute(
                """
                UPDATE trainer_schedule
                   SET status = %s
                 WHERE id = %s
                """,
                (target_status, event_id),
            )
            if cursor.rowcount == 0:
                return {"success": False, "error": "Scheduled session not found."}

            status_delta = 0
            workout_delta = 0
            if current_status == "booked" and target_status != "booked":
                status_delta = -1
            elif current_status != "booked" and target_status == "booked":
                status_delta = 1
            if status_delta:
                app_module._adjust_sessions_booked(cursor, client_row["id"], status_delta)

            if current_status != "completed" and target_status == "completed":
                workout_delta = 0 if session_logged else 1
                trainer_completed_delta = 1
            elif current_status == "completed" and target_status != "completed":
                workout_delta = -1
                trainer_completed_delta = -1
            if workout_delta:
                app_module._adjust_workouts_completed(cursor, client_row["id"], workout_delta)

            client_counts = _build_client_counts_response(cursor, owner_trainer_id, client_row["id"])

            conn.commit()

        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            refreshed, refresh_error = _load_action_event_row(cursor, event_id, actor_row)
            if refresh_error:
                return {"success": False, "error": refresh_error}

    if session_logged and session_meta_payload:
        app_module._attach_session_to_schedule(
            client_row["id"],
            session_meta_payload,
            trainer_id=owner_trainer_id,
            schedule_event_id=event_id,
        )

    return {
        "success": True,
        "client_id": client_row["id"],
        "client_counts": client_counts,
        "trainer_completed_delta": trainer_completed_delta,
        "session_logged": session_logged,
        "session_log_error": session_log_error,
        "logged_workout_label": logged_workout_label,
        "result": app_module._serialize_schedule_row(refreshed),
    }


def execute_pending_action(action_row: dict, actor_row: dict) -> dict[str, Any]:
    action_type = _normalize_text(action_row.get("action_type")).lower()
    payload = action_row.get("arguments") or {}
    if isinstance(payload, str):
        payload = json.loads(payload)

    app_module = _load_app_module()
    actor_role = _normalize_role(actor_row)
    if actor_role not in {"trainer", "admin"}:
        return {"success": False, "error": "Confirming that action requires trainer or admin access."}

    if action_type == "block_time_off":
        start_dt = _parse_agent_datetime(payload.get("start_time"), None, field="start time")
        end_dt = _parse_agent_datetime(payload.get("end_time"), None, field="end time")
        with get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                conflict, message = app_module._time_off_conflicts(cursor, actor_row["id"], start_dt, end_dt)
                if conflict:
                    return {"success": False, "error": message}
                cursor.execute(
                    """
                    INSERT INTO trainer_time_off (trainer_id, start_time, end_time, title, note)
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING id, trainer_id, start_time, end_time, title, note
                    """,
                    (
                        actor_row["id"],
                        start_dt,
                        end_dt,
                        _normalize_text(payload.get("title")) or "Personal Time",
                        _normalize_text(payload.get("note")) or None,
                    ),
                )
                row = cursor.fetchone()
                conn.commit()
        return {
            "success": True,
            "action_type": action_type,
            "message": f"Blocked {_normalize_text(payload.get('title')) or 'Personal Time'}.",
            "result": app_module._serialize_time_off_row(row),
        }

    client_id = _coerce_int(payload.get("client_id"))
    client_row = _load_user_row(client_id) if client_id else None
    if not client_row:
        return {"success": False, "error": "Client not found anymore."}
    if actor_role == "trainer" and client_row.get("trainer_id") != actor_row["id"]:
        return {"success": False, "error": "That client is not linked to your roster."}

    if action_type == "optimize_workout_layout":
        page_context = {"timezone": _normalize_text(payload.get("timezone")) or None}
        target_scope = _normalize_text(payload.get("target_scope")).lower() or "active_workout"
        if target_scope == "session":
            event_id = _coerce_int(payload.get("event_id"))
            row, workout_payload, error_response = app_module._load_trainer_session_payload_for_edit(actor_row, event_id)
            if error_response:
                payload_data, status_code = error_response
                return {"success": False, "error": (payload_data or {}).get("error") or f"Unable to organize that workout ({status_code})."}
            optimized_payload, optimization_meta = app_module._optimize_workout_payload_layout(
                workout_payload,
                preserve_block_order=True,
            )
            if optimization_meta.get("changed"):
                with get_connection() as conn:
                    with conn.cursor() as cursor:
                        cursor.execute(
                            """
                            UPDATE trainer_schedule
                               SET session_payload = %s
                             WHERE id = %s
                            """,
                            (psycopg2.extras.Json(optimized_payload), event_id),
                        )
                        conn.commit()
            return {
                "success": True,
                "action_type": action_type,
                "message": _format_workout_optimization_message(
                    client_row,
                    target_scope="session",
                    page_context=page_context,
                    start_dt=row.get("start_time"),
                    end_dt=row.get("end_time"),
                    changed=bool(optimization_meta.get("changed")),
                ),
                "client_id": client_id,
                "trainer_completed_delta": 0,
                "result": {
                    "action_type": action_type,
                    "event_id": event_id,
                    "client_id": client_id,
                    "target_scope": "session",
                    "optimization": optimization_meta,
                },
            }

        active = app_module.get_active_workout(client_id)
        workout_payload = (active or {}).get("workout_data") or {}
        if not active or not app_module._session_payload_has_plan(workout_payload):
            return {"success": False, "error": f"No active workout is available for {_format_person_name(client_row)} right now."}
        optimized_payload, optimization_meta = app_module._optimize_workout_payload_layout(
            workout_payload,
            preserve_block_order=True,
        )
        if optimization_meta.get("changed"):
            with get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        """
                        UPDATE active_workouts
                           SET workout_data = %s
                         WHERE user_id = %s
                        """,
                        (psycopg2.extras.Json(optimized_payload), client_id),
                    )
                    conn.commit()
        return {
            "success": True,
            "action_type": action_type,
            "message": _format_workout_optimization_message(
                client_row,
                target_scope="active_workout",
                page_context=page_context,
                changed=bool(optimization_meta.get("changed")),
            ),
            "client_id": client_id,
            "trainer_completed_delta": 0,
            "result": {
                "action_type": action_type,
                "client_id": client_id,
                "target_scope": "active_workout",
                "optimization": optimization_meta,
            },
        }

    if action_type in {"book_session", "book_and_assign_workout"}:
        start_dt = _parse_agent_datetime(payload.get("start_time"), None, field="start time")
        end_dt = _parse_agent_datetime(payload.get("end_time"), None, field="end time")
        owner_trainer_id = _resolve_owner_trainer_id(actor_row, client_row)
        client_counts = None
        with get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute(
                    """
                    SELECT COUNT(*)::int AS completed_count
                      FROM trainer_schedule
                     WHERE trainer_id = %s
                       AND client_id = %s
                       AND status = 'completed'
                    """,
                    (owner_trainer_id, client_id),
                )
                completed_row = cursor.fetchone() or {}
                session_summary = app_module._resolve_client_session_summary(
                    cursor,
                    owner_trainer_id,
                    client_id,
                    client_row.get("sessions_booked") or 0,
                    completed_row.get("completed_count") or 0,
                    client_row.get("sessions_remaining"),
                )
                sessions_left = session_summary.get("sessions_left")
                if sessions_left is not None and sessions_left <= 0:
                    return {"success": False, "error": "That client has no sessions remaining."}
                conflict, message = app_module._schedule_conflicts(cursor, owner_trainer_id, client_id, start_dt, end_dt)
                if conflict:
                    return {"success": False, "error": message}
                cursor.execute(
                    """
                    INSERT INTO trainer_schedule (trainer_id, client_id, start_time, end_time, note)
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        owner_trainer_id,
                        client_id,
                        start_dt,
                        end_dt,
                        _normalize_text(payload.get("note")) or None,
                    ),
                )
                event_id = (cursor.fetchone() or {}).get("id")
                app_module._adjust_sessions_booked(cursor, client_id, 1)
                client_counts = _build_client_counts_response(cursor, owner_trainer_id, client_id)
                conn.commit()

        workout_message = None
        if action_type == "book_and_assign_workout" and payload.get("workout_category"):
            workout_payload, error, optimization_meta = _generate_workout_payload_for_client(
                actor_row,
                client_row,
                payload["workout_category"],
                duration_minutes=_coerce_int(payload.get("duration_minutes")),
                custom_categories=payload.get("custom_categories") or [],
            )
            if error:
                with get_connection() as cleanup_conn:
                    with cleanup_conn.cursor() as cleanup_cursor:
                        cleanup_cursor.execute(
                            "DELETE FROM trainer_schedule WHERE id = %s AND trainer_id = %s",
                            (event_id, owner_trainer_id),
                        )
                        app_module._adjust_sessions_booked(cleanup_cursor, client_id, -1)
                        cleanup_conn.commit()
                return {"success": False, "error": error}
            display_category, _ = app_module._resolve_workout_display_metadata(workout_payload, payload["workout_category"])
            assigned, assign_error, meta = app_module._assign_workout_to_schedule(
                actor_row,
                owner_trainer_id,
                client_id,
                event_id,
                workout_payload,
                display_category,
                payload["workout_category"],
            )
            if not assigned:
                with get_connection() as cleanup_conn:
                    with cleanup_conn.cursor() as cleanup_cursor:
                        cleanup_cursor.execute(
                            "DELETE FROM trainer_schedule WHERE id = %s AND trainer_id = %s",
                            (event_id, owner_trainer_id),
                        )
                        app_module._adjust_sessions_booked(cleanup_cursor, client_id, -1)
                        cleanup_conn.commit()
                return {"success": False, "error": assign_error or "Unable to assign the workout to that session."}
            workout_message = f" Assigned a {display_category} workout."
            if optimization_meta and optimization_meta.get("changed"):
                workout_message += " Organized the workout."
        with get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute(
                    """
                    SELECT ts.id, ts.trainer_id, ts.client_id, ts.start_time, ts.end_time, ts.status, ts.note,
                           ts.session_id, ts.session_category, ts.session_completed_at, ts.is_self_booked,
                           c.name AS client_name, c.last_name AS client_last_name, c.username AS client_username
                      FROM trainer_schedule ts
                      JOIN users c ON c.id = ts.client_id
                     WHERE ts.id = %s
                    """,
                    (event_id,),
                )
                row = cursor.fetchone()
        return {
            "success": True,
            "action_type": action_type,
            "message": _format_booking_result_message(
                client_row,
                row,
                {"timezone": _normalize_text(payload.get("timezone")) or None},
                workout_message=workout_message,
            ),
            "client_id": client_id,
            "client_counts": client_counts,
            "trainer_completed_delta": 0,
            "result": app_module._serialize_schedule_row(row),
        }

    if action_type == "reschedule_session":
        event_id = _coerce_int(payload.get("event_id"))
        start_dt = _parse_agent_datetime(payload.get("start_time"), None, field="start time")
        end_dt = _parse_agent_datetime(payload.get("end_time"), None, field="end time")
        owner_trainer_id = _resolve_owner_trainer_id(actor_row, client_row)
        client_counts = None
        original_row = None
        page_context = {"timezone": _normalize_text(payload.get("timezone")) or None}
        with get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute(
                    """
                    SELECT id, start_time, end_time
                      FROM trainer_schedule
                     WHERE id = %s
                       AND trainer_id = %s
                    """,
                    (event_id, actor_row["id"]),
                )
                original_row = cursor.fetchone()
                if not original_row:
                    return {"success": False, "error": "Scheduled session not found."}
                conflict, message = app_module._schedule_conflicts(
                    cursor,
                    actor_row["id"],
                    client_id,
                    start_dt,
                    end_dt,
                    exclude_id=event_id,
                )
                if conflict:
                    return {"success": False, "error": message}
                cursor.execute(
                    """
                    UPDATE trainer_schedule
                       SET start_time = %s,
                           end_time = %s
                     WHERE id = %s
                       AND trainer_id = %s
                    RETURNING id, trainer_id, client_id, start_time, end_time, status, note,
                              session_id, session_category, session_completed_at, is_self_booked
                    """,
                    (start_dt, end_dt, event_id, actor_row["id"]),
                )
                row = cursor.fetchone()
                if not row:
                    return {"success": False, "error": "Scheduled session not found."}
                client_counts = _build_client_counts_response(cursor, owner_trainer_id, client_id)
                conn.commit()
        return {
            "success": True,
            "action_type": action_type,
            "message": _format_reschedule_result_message(
                client_row,
                (original_row or {}).get("start_time"),
                (original_row or {}).get("end_time"),
                row.get("start_time"),
                row.get("end_time"),
                page_context,
            ),
            "client_id": client_id,
            "client_counts": client_counts,
            "trainer_completed_delta": 0,
            "result": app_module._serialize_schedule_row(row),
        }

    if action_type == "swap_sessions":
        event_id = _coerce_int(payload.get("event_id"))
        swap_event_id = _coerce_int(payload.get("swap_event_id"))
        second_client_id = _coerce_int(payload.get("second_client_id"))
        if not event_id or not swap_event_id:
            return {"success": False, "error": "Both sessions are required for a swap."}
        if event_id == swap_event_id:
            return {"success": False, "error": "I need two different sessions to perform a swap."}
        page_context = {"timezone": _normalize_text(payload.get("timezone")) or None}
        with get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                first_row, first_error = _load_action_event_row(cursor, event_id, actor_row)
                if first_error:
                    return {"success": False, "error": first_error}
                second_row, second_error = _load_action_event_row(cursor, swap_event_id, actor_row)
                if second_error:
                    return {"success": False, "error": second_error}
                first_client_id = _coerce_int(first_row.get("client_id"))
                swap_client_id = _coerce_int(second_row.get("client_id"))
                if first_client_id != client_id:
                    return {"success": False, "error": "That swap request belongs to a different client."}
                if second_client_id and swap_client_id != second_client_id:
                    return {"success": False, "error": "The second session belongs to a different client."}
                first_status = (_normalize_text(first_row.get("status")) or "booked").lower()
                second_status = (_normalize_text(second_row.get("status")) or "booked").lower()
                if first_status != "booked" or second_status != "booked":
                    return {"success": False, "error": "Only booked sessions can be swapped."}
                first_start = first_row.get("start_time")
                first_end = first_row.get("end_time")
                second_start = second_row.get("start_time")
                second_end = second_row.get("end_time")
                if not first_start or not first_end or not second_start or not second_end:
                    return {"success": False, "error": "Both sessions need valid start and end times to swap them."}
                owner_trainer_id = _coerce_int(first_row.get("trainer_id"))
                swap_trainer_id = _coerce_int(second_row.get("trainer_id"))
                if not owner_trainer_id or not swap_trainer_id or owner_trainer_id != swap_trainer_id:
                    return {"success": False, "error": "Both sessions need to belong to the same trainer calendar to swap them."}
                conflict, message = _schedule_conflicts_excluding_ids(
                    cursor,
                    owner_trainer_id,
                    first_client_id,
                    second_start,
                    second_end,
                    [event_id, swap_event_id],
                )
                if conflict:
                    return {"success": False, "error": message}
                conflict, message = _schedule_conflicts_excluding_ids(
                    cursor,
                    owner_trainer_id,
                    swap_client_id,
                    first_start,
                    first_end,
                    [event_id, swap_event_id],
                )
                if conflict:
                    return {"success": False, "error": message}
                cursor.execute(
                    """
                    UPDATE trainer_schedule
                       SET start_time = %s,
                           end_time = %s
                     WHERE id = %s
                       AND trainer_id = %s
                    """,
                    (second_start, second_end, event_id, owner_trainer_id),
                )
                if cursor.rowcount == 0:
                    return {"success": False, "error": "Scheduled session not found."}
                cursor.execute(
                    """
                    UPDATE trainer_schedule
                       SET start_time = %s,
                           end_time = %s
                     WHERE id = %s
                       AND trainer_id = %s
                    """,
                    (first_start, first_end, swap_event_id, owner_trainer_id),
                )
                if cursor.rowcount == 0:
                    return {"success": False, "error": "Scheduled session not found."}
                cursor.execute(
                    """
                    SELECT ts.id, ts.trainer_id, ts.client_id, ts.start_time, ts.end_time, ts.status, ts.note,
                           ts.session_id, ts.session_category, ts.session_completed_at, ts.is_self_booked,
                           c.name AS client_name, c.last_name AS client_last_name, c.username AS client_username
                      FROM trainer_schedule ts
                      JOIN users c ON c.id = ts.client_id
                     WHERE ts.id IN (%s, %s)
                     ORDER BY ts.start_time ASC
                    """,
                    (event_id, swap_event_id),
                )
                swapped_rows = cursor.fetchall() or []
                conn.commit()
        return {
            "success": True,
            "action_type": action_type,
            "message": _format_swap_result_message(
                first_row,
                first_start,
                first_end,
                second_row,
                second_start,
                second_end,
                page_context,
            ),
            "client_id": client_id,
            "second_client_id": swap_client_id,
            "trainer_completed_delta": 0,
            "result": {
                "client_id": client_id,
                "second_client_id": swap_client_id,
                "events": [app_module._serialize_schedule_row(row) for row in swapped_rows],
            },
        }

    if action_type == "cancel_session":
        status_result = _apply_schedule_status_update(action_row, actor_row, client_row, "cancelled")
        if not status_result.get("success"):
            return status_result
        page_context = {"timezone": _normalize_text(payload.get("timezone")) or None}
        return {
            "success": True,
            "action_type": action_type,
            "message": _format_status_result_message(client_row, status_result.get("result"), page_context, "cancelled"),
            "client_id": client_id,
            "client_counts": status_result.get("client_counts"),
            "trainer_completed_delta": status_result.get("trainer_completed_delta", 0),
            "result": status_result.get("result"),
        }

    if action_type == "complete_session":
        status_result = _apply_schedule_status_update(action_row, actor_row, client_row, "completed")
        if not status_result.get("success"):
            return status_result
        page_context = {"timezone": _normalize_text(payload.get("timezone")) or None}
        return {
            "success": True,
            "action_type": action_type,
            "message": _format_status_result_message(
                client_row,
                status_result.get("result"),
                page_context,
                "completed",
                logged_workout_label=status_result.get("logged_workout_label"),
                session_log_error=status_result.get("session_log_error"),
            ),
            "client_id": client_id,
            "client_counts": status_result.get("client_counts"),
            "trainer_completed_delta": status_result.get("trainer_completed_delta", 0),
            "session_logged": status_result.get("session_logged"),
            "session_log_error": status_result.get("session_log_error"),
            "logged_workout_label": status_result.get("logged_workout_label"),
            "result": status_result.get("result"),
        }

    if action_type == "set_session_booked":
        status_result = _apply_schedule_status_update(action_row, actor_row, client_row, "booked")
        if not status_result.get("success"):
            return status_result
        page_context = {"timezone": _normalize_text(payload.get("timezone")) or None}
        return {
            "success": True,
            "action_type": action_type,
            "message": _format_status_result_message(client_row, status_result.get("result"), page_context, "booked"),
            "client_id": client_id,
            "client_counts": status_result.get("client_counts"),
            "trainer_completed_delta": status_result.get("trainer_completed_delta", 0),
            "result": status_result.get("result"),
        }

    if action_type == "delete_session":
        event_id = _coerce_int(payload.get("event_id"))
        owner_trainer_id = _resolve_owner_trainer_id(actor_row, client_row)
        client_counts = None
        trainer_completed_delta = 0
        page_context = {"timezone": _normalize_text(payload.get("timezone")) or None}
        with get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                row, row_error = _load_action_event_row(cursor, event_id, actor_row)
                if row_error:
                    return {"success": False, "error": row_error}
                if row.get("client_id") != client_row.get("id"):
                    return {"success": False, "error": "That scheduled session belongs to a different client."}
                cursor.execute(
                    "DELETE FROM trainer_schedule WHERE id = %s RETURNING client_id, status",
                    (event_id,),
                )
                deleted_row = cursor.fetchone()
                if not deleted_row:
                    return {"success": False, "error": "Scheduled session not found."}
                prior_status = (deleted_row.get("status") or "booked").lower()
                if prior_status == "booked":
                    app_module._adjust_sessions_booked(cursor, client_id, -1)
                if prior_status == "completed":
                    app_module._adjust_workouts_completed(cursor, client_id, -1)
                    trainer_completed_delta = -1
                client_counts = _build_client_counts_response(cursor, owner_trainer_id, client_id)
                conn.commit()
        return {
            "success": True,
            "action_type": action_type,
            "message": _format_status_result_message(client_row, row, page_context, "deleted"),
            "client_id": client_id,
            "client_counts": client_counts,
            "trainer_completed_delta": trainer_completed_delta,
            "result": {"event_id": event_id},
        }

    if action_type == "assign_workout":
        event_id = _coerce_int(payload.get("event_id"))
        workout_category = _normalize_text(payload.get("workout_category"))
        if not workout_category:
            return {"success": False, "error": "Assigning a workout needs a workout category."}
        workout_payload, error, optimization_meta = _generate_workout_payload_for_client(
            actor_row,
            client_row,
            workout_category,
            duration_minutes=_coerce_int(payload.get("duration_minutes")),
            custom_categories=payload.get("custom_categories") or [],
        )
        if error:
            return {"success": False, "error": error}
        display_category, _ = app_module._resolve_workout_display_metadata(workout_payload, workout_category)
        assigned, assign_error, meta = app_module._assign_workout_to_schedule(
            actor_row,
            actor_row["id"],
            client_id,
            event_id,
            workout_payload,
            display_category,
            workout_category,
        )
        if not assigned:
            return {"success": False, "error": assign_error or "Unable to assign the workout to that session."}
        return {
            "success": True,
            "action_type": action_type,
            "message": (
                f"Assigned {_format_person_name(client_row)} a {display_category} workout."
                + (" Organized the workout." if optimization_meta and optimization_meta.get("changed") else "")
            ),
            "client_id": client_id,
            "trainer_completed_delta": 0,
            "result": {"event_id": event_id, **(meta or {})},
        }

    return {"success": False, "error": f"Unsupported action_type: {action_type}"}


AGENT_TOOL_SPECS = [
    {
        "type": "function",
        "function": {
            "name": LOOKUP_TOOL_NAME,
            "description": "Fetch exact FitBaseAI app, training, roster, schedule, or business data from deterministic sources. Use this for metrics, history, schedule questions, and admin counts.",
            "parameters": {
                "type": "object",
                "properties": {
                    "metric_key": {
                        "type": "string",
                        "enum": [
                            "estimated_one_rep_max",
                            "most_tracked_workout",
                            "today_schedule",
                            "schedule_window_summary",
                            "next_session",
                            "trainer_top_sessions_this_month",
                            "new_users_this_month",
                            "client_performance_summary",
                            "current_user_summary",
                            "trainer_roster_summary",
                            "platform_summary",
                            "risk_flags_summary",
                            "trial_status",
                        ],
                    },
                    "client_id": {"type": ["integer", "null"]},
                    "client_name": {"type": ["string", "null"]},
                    "exercise_query": {"type": ["string", "null"]},
                    "target_date": {
                        "type": ["string", "null"],
                        "description": "ISO calendar date like 2026-03-31 in the current user's local timezone.",
                    },
                    "window_key": {
                        "type": ["string", "null"],
                        "enum": [
                            "today",
                            "yesterday",
                            "tomorrow",
                            "this_week",
                            "last_week",
                            "next_week",
                            "this_month",
                            "last_month",
                            "next_month",
                            "this_year",
                            "last_year",
                            "next_year",
                        ],
                        "description": "Relative schedule window for exact count questions.",
                    },
                    "window_start": {
                        "type": ["string", "null"],
                        "description": "Exact range start as an ISO 8601 datetime in the user's timezone when a custom range is needed.",
                    },
                    "window_end": {
                        "type": ["string", "null"],
                        "description": "Exact range end as an ISO 8601 datetime in the user's timezone when a custom range is needed.",
                    },
                    "window_label": {
                        "type": ["string", "null"],
                        "description": "Human-readable label for the custom schedule range, like last 3 months or from Mar 1, 2026 to Mar 31, 2026.",
                    },
                },
                "required": ["metric_key"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": ACTION_TOOL_NAME,
            "description": "Prepare a guarded FitBaseAI trainer or admin action. Use ISO 8601 datetimes with timezone offsets when possible. These actions must be confirmed before they execute.",
            "parameters": {
                "type": "object",
                "properties": {
                    "action_type": {
                        "type": "string",
                        "enum": [
                            "book_session",
                            "book_and_assign_workout",
                            "swap_sessions",
                            "reschedule_session",
                            "cancel_session",
                            "complete_session",
                            "set_session_booked",
                            "delete_session",
                            "assign_workout",
                            "optimize_workout_layout",
                            "block_time_off",
                        ],
                    },
                    "client_id": {"type": ["integer", "null"]},
                    "client_name": {"type": ["string", "null"]},
                    "second_client_id": {"type": ["integer", "null"]},
                    "second_client_name": {"type": ["string", "null"]},
                    "event_id": {"type": ["integer", "null"]},
                    "swap_event_id": {"type": ["integer", "null"]},
                    "target_date": {
                        "type": ["string", "null"],
                        "description": "Calendar date like 2026-03-31. Use this when the user refers to today, tomorrow, or a named date for an existing session.",
                    },
                    "source_start_time": {
                        "type": ["string", "null"],
                        "description": "For reschedule requests phrased like 'from 5:30 PM to 4:30 PM', this is the CURRENT session start time being moved.",
                    },
                    "start_time": {
                        "type": ["string", "null"],
                        "description": "ISO 8601 datetime like 2026-03-31T10:00:00-05:00. For reschedule_session, this must be the NEW desired start time, not the old one.",
                    },
                    "end_time": {
                        "type": ["string", "null"],
                        "description": "ISO 8601 datetime like 2026-03-31T11:00:00-05:00.",
                    },
                    "duration_minutes": {"type": ["integer", "null"]},
                    "note": {"type": ["string", "null"]},
                    "title": {"type": ["string", "null"]},
                    "workout_category": {"type": ["string", "null"]},
                    "workout_display_label": {"type": ["string", "null"]},
                    "custom_categories": {
                        "type": ["array", "null"],
                        "items": {"type": "string"},
                    },
                    "target_scope": {
                        "type": ["string", "null"],
                        "enum": ["session", "active_workout"],
                    },
                },
                "required": ["action_type"],
                "additionalProperties": False,
            },
        },
    },
]


def execute_tool_call(tool_name: str, arguments: dict[str, Any], actor_row: dict, page_context: dict | None) -> dict[str, Any]:
    if tool_name == LOOKUP_TOOL_NAME:
        return lookup_fitbase_data(arguments, actor_row, page_context)
    if tool_name == ACTION_TOOL_NAME:
        return prepare_fitbase_action(arguments, actor_row, page_context)
    return {"success": False, "error": f"Unknown tool: {tool_name}"}
