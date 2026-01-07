import os, re, logging, json, math, uuid, psycopg2, psycopg2.extras, psycopg2.errors, stripe, requests
from flask import Flask, flash, redirect, render_template, request, session, jsonify, url_for, current_app, abort, send_from_directory
from markupsafe import Markup
from werkzeug.security import generate_password_hash, check_password_hash
from helpers import (
    login_required,
    calculate_target_heart_rate,
    generate_workout,
    get_guidelines,
    get_connection,
    is_admin,
    normalize_email,
    upsert_invited_user,
    issue_single_use_token,
    validate_token,
    mark_token_used,
    username_available,
    fmt_utc,
    int_or_none,
    inches_0_11_or_none,
    float_or_none,
    hash_token,
    get_category_groups,
    get_user_level,
    LEVEL_MAP,
    check_and_downgrade_trial,
    check_subscription_expiry,
    get_active_workout,
    set_active_workout,
    clear_active_workout,
    parse_injury_payload,
    compute_injury_exclusions,
    CUSTOM_WORKOUT_TOKEN,
    HOME_WORKOUT_TOKEN,
    CUSTOM_WORKOUT_CATEGORIES,
    CUSTOM_WORKOUT_SELECTION_LIMITS,
    HOME_EQUIPMENT_OPTIONS,
    build_home_equipment_clause,
    CARDIO_BODYWEIGHT_WORKOUTS,
    normalize_custom_workout_categories,
    normalize_home_equipment_selection,
    custom_selection_bounds,
)
from collections import OrderedDict
from dotenv import load_dotenv
from datetime import datetime, date, timedelta, timezone, time, tzinfo
from zoneinfo import ZoneInfo
from mail import (
    send_email,
    send_password_reset_email,
    send_invite_email,
    send_verification_email,
    send_trainer_link_email,
    send_trainer_link_connected_email,
)
from urllib.parse import urlencode, urlparse 
from decimal import Decimal, InvalidOperation
from dns import resolver as dns_resolver, exception as dns_exception

# Set up basic logging configuration
logging.basicConfig(level=logging.INFO)

load_dotenv()

app = Flask(__name__)

secret = os.getenv("SECRET_KEY")
if not secret:
    raise RuntimeError("SECRET_KEY is not set!")
app.secret_key = secret

# Stripe
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
premium_price_id = os.getenv("STRIPE_PREMIUM_PRICE_ID")
pro_price_id = os.getenv("STRIPE_PRO_PRICE_ID")
stripe_portal_configuration_id = os.getenv("STRIPE_PORTAL_CONFIGURATION_ID")
PLAN_PRICE_LOOKUP = {
    "premium": premium_price_id,
    "pro": pro_price_id,
}
PRICE_PLAN_LOOKUP = {
    price_id: plan
    for plan, price_id in PLAN_PRICE_LOOKUP.items()
    if price_id
}
ENV = os.getenv("FLASK_ENV", "development")
if ENV == "production":
    webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET_LIVE")
else:
    webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET_TEST")

ALLOWED_ROLES = {"user", "trainer", "admin"}
ALLOWED_SUBS  = {"free", "premium", "pro"}
INVITE_TTL_HOURS = 48
VERIFY_TTL_HOURS = 48
RESEND_COOLDOWN_SECONDS = 60  
VERIFY_PURPOSE = "verify_email"
RESET_TTL_HOURS = 2

TURNSTILE_SITE_KEY = os.getenv("TURNSTILE_SITE_KEY")
TURNSTILE_SECRET_KEY = os.getenv("TURNSTILE_SECRET_KEY")
TURNSTILE_ENABLED = bool(TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY)
SESSION_VERSION_CHECK_INTERVAL_SECONDS = int(os.getenv("SESSION_VERSION_CHECK_INTERVAL_SECONDS", "0"))

REGISTRATION_RATE_LIMIT_WINDOW = timedelta(hours=int(os.getenv("REGISTRATION_RATE_LIMIT_WINDOW_HOURS", "1")))
REGISTRATION_RATE_LIMIT_PER_EMAIL = int(os.getenv("REGISTRATION_RATE_LIMIT_PER_EMAIL", "3"))
REGISTRATION_RATE_LIMIT_PER_IP = int(os.getenv("REGISTRATION_RATE_LIMIT_PER_IP", "20"))

DISPOSABLE_EMAIL_DOMAINS = {
    "mailinator.com",
    "tempmail.com",
    "guerrillamail.com",
    "10minutemail.com",
    "yopmail.com",
    "discard.email",
    "fakeinbox.com",
    "sharklasers.com",
    "trashmail.com",
    "getnada.com",
}

TRAINER_NOTE_MAX_LENGTH = 1000
TRAINER_PROFILE_TEXT_LIMIT = 1000
ONE_REP_MAX_COEFFICIENT = 0.0333
HISTORY_WINDOW_LIMITS = {
    '90d': 150,
    '1y': 240,
    'all': 400,
}
HISTORY_WINDOW_DELTAS = {
    '90d': timedelta(days=90),
    '1y': timedelta(days=365),
    'all': None,
}
DEFAULT_HISTORY_WINDOW = '90d'
WORKOUT_NOTES_PLACEHOLDER = "No notes yet."
FREE_SUBSCRIPTION_CATEGORY = "Shoulders and Abs"

TRAINER_CLIENT_COUNT_BUCKETS = [
    {'code': 1, 'label': '0-5 active clients', 'min': 0, 'max': 5},
    {'code': 2, 'label': '6-15 active clients', 'min': 6, 'max': 15},
    {'code': 3, 'label': '16-30 active clients', 'min': 16, 'max': 30},
    {'code': 4, 'label': '31+ active clients', 'min': 31, 'max': None},
]

TRAINER_SESSION_BUCKETS = [
    {'code': 1, 'label': '0-15 sessions/week', 'min': 0, 'max': 15},
    {'code': 2, 'label': '16-30 sessions/week', 'min': 16, 'max': 30},
    {'code': 3, 'label': '31-40 sessions/week', 'min': 31, 'max': 40},
    {'code': 4, 'label': '41+ sessions/week', 'min': 41, 'max': None},
]

TRAINER_CLIENT_BUCKET_CODES = {entry['code'] for entry in TRAINER_CLIENT_COUNT_BUCKETS}
TRAINER_SESSION_BUCKET_CODES = {entry['code'] for entry in TRAINER_SESSION_BUCKETS}
SCHEDULE_ACCESS_REQUIRED_MESSAGE = "Schedule access requires an active training plan."
DEFAULT_CALENDAR_WINDOW = (5, 21)
MIN_CALENDAR_WINDOW_HOURS = 5


def _normalize_role_value(role_value, *, default=None):
    """Convert stored role strings to a supported canonical value."""
    if isinstance(role_value, str):
        normalized = role_value.strip().lower()
        if normalized == 'client':
            normalized = 'user'
        if normalized in ALLOWED_ROLES:
            return normalized
    return default


def _resolve_user_role(*, user_id=None, conn=None, default='user'):
    """Ensure session holds a canonical role value, reloading from DB if needed."""
    current_role = session.get('role')
    normalized = _normalize_role_value(current_role, default=None)
    if normalized:
        if current_role != normalized:
            session['role'] = normalized
        if session.get('is_admin') != (normalized == 'admin'):
            session['is_admin'] = (normalized == 'admin')
        return normalized

    if user_id is None:
        user_id = session.get('user_id')
    if not user_id:
        normalized = _normalize_role_value(None, default=default)
        if session.get('role') != normalized:
            session['role'] = normalized
        if session.get('is_admin') != (normalized == 'admin'):
            session['is_admin'] = (normalized == 'admin')
        return normalized

    def _fetch_role(active_conn):
        with active_conn.cursor() as cursor:
            cursor.execute("SELECT role FROM users WHERE id = %s", (user_id,))
            row = cursor.fetchone()
            return row[0] if row else None

    if conn is not None:
        db_role = _fetch_role(conn)
    else:
        with get_connection() as temp_conn:
            db_role = _fetch_role(temp_conn)

    normalized = _normalize_role_value(db_role, default=default)
    if session.get('role') != normalized:
        session['role'] = normalized
    if session.get('is_admin') != (normalized == 'admin'):
        session['is_admin'] = (normalized == 'admin')
    return normalized


def _normalize_calendar_window(start_value, end_value, *, default_start=DEFAULT_CALENDAR_WINDOW[0], default_end=DEFAULT_CALENDAR_WINDOW[1]):
    """Clamp calendar availability windows and enforce the minimum duration."""
    try:
        normalized_start = max(0, min(23, int(start_value)))
        normalized_end = max(1, min(24, int(end_value)))
    except (TypeError, ValueError):
        return default_start, default_end
    if normalized_end - normalized_start < MIN_CALENDAR_WINDOW_HOURS:
        normalized_start = max(0, min(normalized_start, 24 - MIN_CALENDAR_WINDOW_HOURS))
        normalized_end = normalized_start + MIN_CALENDAR_WINDOW_HOURS
    return normalized_start, normalized_end


def _enforce_session_version(user_id: int):
    """Ensure current session matches the user's latest session_version."""
    stored_version = session.get('session_version')
    if stored_version is None:
        return None

    now = datetime.now(timezone.utc)
    if SESSION_VERSION_CHECK_INTERVAL_SECONDS > 0:
        last_checked_iso = session.get('session_version_checked_at')
        if last_checked_iso:
            try:
                last_checked = datetime.fromisoformat(last_checked_iso)
            except ValueError:
                last_checked = None
            if last_checked:
                delta = (now - last_checked).total_seconds()
                if delta < SESSION_VERSION_CHECK_INTERVAL_SECONDS:
                    return None

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT session_version FROM users WHERE id = %s", (user_id,))
            row = cur.fetchone()
    session['session_version_checked_at'] = now.isoformat()
    db_version = (row[0] if row else None) or 1

    if db_version == stored_version:
        return None

    session.clear()
    flash("Please log in again to refresh your account changes.", "info")
    return redirect(url_for('login'))


def _user_has_schedule_access(user_row):
    """Client schedule is available only when linked to a trainer and on a paid tier."""
    if not user_row:
        return False
    subscription_type = (user_row.get('subscription_type') or '').strip().lower()
    if subscription_type == 'free':
        return False
    return bool(user_row.get('trainer_id'))


def _normalize_trainer_bucket(value, buckets):
    if value is None:
        return None
    try:
        numeric_value = int(value)
    except (TypeError, ValueError):
        return None
    bucket_codes = {entry['code'] for entry in buckets}
    if numeric_value in bucket_codes:
        return numeric_value
    for entry in buckets:
        min_val = entry.get('min')
        max_val = entry.get('max')
        if min_val is not None and numeric_value < min_val:
            continue
        if max_val is None or numeric_value <= max_val:
            return entry['code']
    return None


def _sanitize_trainer_note_input(value):
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if len(text) > TRAINER_NOTE_MAX_LENGTH:
        text = text[:TRAINER_NOTE_MAX_LENGTH]
    return text


def _coerce_float(value):
    if value is None:
        return None
    if isinstance(value, (float, int)):
        return float(value)
    if isinstance(value, Decimal):
        return float(value)
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return None


def _is_plank_exercise(name):
    if not name:
        return False
    try:
        normalized = str(name).strip().lower()
    except Exception:
        return False
    return 'plank' in normalized


def _is_bodyweight_exercise(name):
    if not name:
        return False
    try:
        normalized = str(name).strip().lower()
    except Exception:
        return False
    return 'bodyweight' in normalized


def _estimate_one_rep_max(weight, reps):
    weight_val = _coerce_float(weight)
    reps_val = _coerce_float(reps)
    if weight_val is None or reps_val is None:
        return None
    if weight_val <= 0 or reps_val <= 0:
        return None
    return round(weight_val * (1 + ONE_REP_MAX_COEFFICIENT * reps_val), 1)


def _record_exercise_history(user_id, workout_id, max_weight, max_reps):
    if max_weight is None and max_reps is None:
        return
    try:
        with get_connection() as history_conn:
            with history_conn.cursor() as history_cursor:
                history_cursor.execute(
                    """
                    INSERT INTO user_exercise_history (user_id, workout_id, weight, reps, source)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (user_id, workout_id, max_weight, max_reps, 'pr_update'),
                )
    except psycopg2.errors.UndefinedTable:
        logging.warning("user_exercise_history table missing; skipping history insert for workout_id=%s", workout_id)
    except Exception:
        logging.exception("Failed to record exercise history for workout_id=%s", workout_id)


def _log_workout_session_history(user_id: int, category_label: str, session_entries: list[dict]) -> tuple[str | None, datetime | None]:
    """
    Persist a snapshot of each exercise in a completed workout into user_exercise_history.
    Returns (session_id, completed_at) when successful.
    """
    if not session_entries:
        return None, None

    session_uuid = uuid.uuid4()
    completed_at = datetime.now(timezone.utc)

    try:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                insert_sql = """
                    INSERT INTO user_exercise_history
                        (user_id, workout_id, weight, reps, recorded_at, session_id, category, subcategory, notes, source)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
                for entry in session_entries:
                    workout_id = entry.get('workout_id')
                    if not workout_id:
                        continue
                    weight = entry.get('weight')
                    reps = entry.get('reps')
                    subcategory = entry.get('subcategory')
                    notes = entry.get('notes')
                    cursor.execute(
                        insert_sql,
                        (
                            user_id,
                            workout_id,
                            weight,
                            reps,
                            completed_at,
                            str(session_uuid),
                            category_label,
                            subcategory,
                            notes,
                            'session_complete',
                        ),
                    )
            conn.commit()
    except Exception:
        logging.exception("Failed to record workout session snapshot for user_id=%s", user_id)
        return None, completed_at

    return str(session_uuid), completed_at


def _downsample_history(points: list[dict], max_points: int) -> list[dict]:
    if not isinstance(points, list) or max_points is None or max_points <= 0:
        return points
    length = len(points)
    if length <= max_points:
        return points
    step = math.ceil(length / max_points)
    sampled = points[::step]
    if sampled[-1] is not points[-1]:
        sampled.append(points[-1])
    return sampled


def _normalize_plan_for_iteration(plan):
    if isinstance(plan, list):
        normalized = []
        for entry in plan:
            if isinstance(entry, dict) and 'subcategory' in entry:
                normalized.append((entry.get('subcategory'), entry.get('exercises') or []))
            elif isinstance(entry, (list, tuple)) and len(entry) >= 2:
                normalized.append((entry[0], entry[1]))
        return normalized
    if isinstance(plan, dict):
        return list(plan.items())
    return []


def _format_exercise(selected_category, exercise):
    if isinstance(exercise, dict):
        workout_id = exercise.get('workout_id')
        name = exercise.get('name')
        description = exercise.get('description')
        youtube_id = exercise.get('youtube_id')
        image_start = exercise.get('image_exercise_start')
        image_end = exercise.get('image_exercise_end')
        max_weight = exercise.get('max_weight')
        max_reps = exercise.get('max_reps')
        notes = exercise.get('notes')
    else:
        workout_id = exercise[0]
        name = exercise[1]
        description = exercise[2]
        youtube_id = exercise[3]
        image_start = exercise[4]
        image_end = exercise[5]
        max_weight = exercise[6] if len(exercise) > 6 else None
        max_reps = exercise[7] if len(exercise) > 7 else None
        notes = exercise[8] if len(exercise) > 8 else None

    if max_weight is not None and not isinstance(max_weight, (int, float)):
        try:
            max_weight = float(max_weight)
        except (TypeError, ValueError):
            max_weight = None

    if max_reps is not None and not isinstance(max_reps, (int, float)):
        try:
            max_reps = int(max_reps)
        except (TypeError, ValueError):
            max_reps = None

    return {
        'workout_id': workout_id,
        'name': name,
        'description': description,
        'youtube_id': youtube_id,
        'image_exercise_start': image_start,
        'image_exercise_end': image_end,
        'max_weight': max_weight,
        'max_reps': max_reps,
        'category': selected_category,
        'notes': notes,
    }


def format_workout_for_response(selected_category, workout_plan):
    formatted = []
    for subcategory, exercises in _normalize_plan_for_iteration(workout_plan):
        items = [_format_exercise(selected_category, ex) for ex in (exercises or [])]
        formatted.append({'subcategory': subcategory, 'exercises': items})
    return formatted

@app.route('/')
def home():
    """Public landing page or the logged-in dashboard."""
    if 'user_id' not in session:
        return render_template('landing.html')

    # Get the user ID from the session
    user_id = session['user_id']
    check_and_downgrade_trial(user_id)
    check_subscription_expiry(user_id)
    now_utc = datetime.now(timezone.utc)
    _, workout_details_timezone, workout_details_tz_offset = _resolve_request_timezone('workout_session')

    def _format_person(first_name, last_name, username):
        parts = [part for part in (first_name, last_name) if part]
        if parts:
            return " ".join(parts)
        return username

    def _format_time_label(dt: datetime) -> str:
        return dt.strftime("%I:%M %p").lstrip('0')

    def _describe_session(row: dict, counterpart_label: str) -> dict | None:
        if not row:
            return None
        start_dt = row.get('start_time')
        end_dt = row.get('end_time')
        if not start_dt or not end_dt:
            return None
        start_local = start_dt.astimezone()
        end_local = end_dt.astimezone()
        date_short = f"{start_local.strftime('%a')}, {start_local.strftime('%b')} {start_local.day}"
        date_full = f"{start_local.strftime('%A')}, {start_local.strftime('%b')} {start_local.day}"
        if start_local.date() == end_local.date():
            time_label = f"{_format_time_label(start_local)} – {_format_time_label(end_local)}"
        else:
            time_label = (
                f"{_format_time_label(start_local)} – "
                f"{end_local.strftime('%a')} {_format_time_label(end_local)}"
            )
        timezone_label = start_local.tzname() or "local time"
        if counterpart_label == 'Trainer':
            counterpart_name = _format_person(
                row.get('trainer_name'),
                row.get('trainer_last_name'),
                row.get('trainer_username'),
            )
        else:
            counterpart_name = _format_person(
                row.get('client_name'),
                row.get('client_last_name'),
                row.get('client_username'),
            )
        return {
            'id': row.get('id'),
            'date_label': date_short,
            'full_date_label': date_full,
            'time_label': time_label,
            'timezone_label': timezone_label,
            'counterpart_name': counterpart_name,
            'counterpart_role': counterpart_label,
            'status': (row.get('status') or 'booked').capitalize(),
            'start_iso': start_dt.isoformat(),
            'end_iso': end_dt.isoformat(),
        }

    client_next_session = None
    trainer_next_session = None
    injury_status = None
    injury_free_days = None
    form_completed_flag = False

    # Connect to the database to fetch the username
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute("""
                SELECT name,
                       fitness_goals,
                       workouts_completed,
                       last_workout_completed,
                       form_completed,
                       role,
                       trainer_id,
                       injury,
                       injury_details,
                       cardio_restriction,
                       injury_free_since
                  FROM users
                 WHERE id = %s
            """, (user_id,))
            user = cursor.fetchone()

            # Ensure the user exists
            if user is None:
                flash("User not found.", "danger")
                return redirect('/logout')

            form_completed_flag = bool(user.get('form_completed'))
            injury_payload = parse_injury_payload(user.get('injury'))
            cardio_flag = bool(user.get('cardio_restriction')) or injury_payload['cardio']
            injury_details_text = (user.get('injury_details') or '').strip()
            if form_completed_flag:
                has_active_injury = bool(injury_payload['regions'] or cardio_flag or injury_details_text)
                injury_status = 'Yes' if has_active_injury else 'No'
                if not has_active_injury:
                    streak_start = user.get('injury_free_since')
                    if isinstance(streak_start, date):
                        delta_days = (date.today() - streak_start).days
                        if delta_days < 0:
                            delta_days = 0
                        injury_free_days = delta_days + 1
                    else:
                        injury_free_days = 0
                else:
                    injury_free_days = 0

            role = user.get('role')
            trainer_id = user.get('trainer_id')

            if role == 'user' and trainer_id:
                cursor.execute(
                    """
                    SELECT ts.id,
                           ts.start_time,
                           ts.end_time,
                           ts.status,
                           t.name AS trainer_name,
                           t.last_name AS trainer_last_name,
                           t.username AS trainer_username
                      FROM trainer_schedule ts
                      JOIN users t
                        ON t.id = ts.trainer_id
                     WHERE ts.client_id = %s
                       AND ts.status = 'booked'
                       AND ts.end_time >= %s
                     ORDER BY ts.start_time ASC
                     LIMIT 1
                    """,
                    (user_id, now_utc),
                )
                row = cursor.fetchone()
                if row:
                    client_next_session = _describe_session(row, 'Trainer')

            if role in {'trainer', 'admin'}:
                cursor.execute(
                    """
                    SELECT ts.id,
                           ts.start_time,
                           ts.end_time,
                           ts.status,
                           c.name AS client_name,
                           c.last_name AS client_last_name,
                           c.username AS client_username
                      FROM trainer_schedule ts
                      JOIN users c
                        ON c.id = ts.client_id
                     WHERE ts.trainer_id = %s
                       AND ts.status = 'booked'
                       AND ts.end_time >= %s
                     ORDER BY ts.start_time ASC
                     LIMIT 1
                    """,
                    (user_id, now_utc),
                )
                row = cursor.fetchone()
                if row:
                    trainer_next_session = _describe_session(row, 'Client')
        
    # Extract the name from the result
    name = user.get('name')
    fitness_goals = user.get('fitness_goals') if user.get('fitness_goals') else "Not set yet" 
    workouts_completed = user.get('workouts_completed') if user.get('workouts_completed') is not None else 0  
    last_workout_completed = user.get('last_workout_completed') if user.get('last_workout_completed') else "No workouts completed yet"
    form_completed = form_completed_flag

    return render_template(
        'index.html', 
        name=name if form_completed else None, 
        fitness_goals=fitness_goals, 
        workouts_completed=workouts_completed,
        last_workout_completed=last_workout_completed,
        form_completed=form_completed,
        user_role=role,
        client_next_session=client_next_session,
        trainer_next_session=trainer_next_session,
        injury_status=injury_status,
        injury_free_days=injury_free_days,
        workout_details_timezone=workout_details_timezone,
        workout_details_tz_offset=workout_details_tz_offset,
    )


def _get_request_ip():
    header_keys = [
        "CF-Connecting-IP",
        "X-Forwarded-For",
        "X-Real-IP",
    ]
    for key in header_keys:
        value = request.headers.get(key)
        if value:
            return value.split(",")[0].strip()
    return request.remote_addr


def _verify_turnstile_token(token: str, remote_ip: str | None) -> bool:
    if not TURNSTILE_ENABLED:
        return True
    if not token:
        return False
    payload = {
        "secret": TURNSTILE_SECRET_KEY,
        "response": token,
    }
    if remote_ip:
        payload["remoteip"] = remote_ip
    try:
        resp = requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=payload,
            timeout=5,
        )
        resp.raise_for_status()
        result = resp.json()
    except requests.RequestException:
        current_app.logger.exception("Turnstile verification request failed")
        return False
    except ValueError:
        current_app.logger.warning("Unexpected Turnstile response payload")
        return False

    success = bool(result.get("success"))
    if not success:
        current_app.logger.warning("Turnstile rejected registration: %s", result.get("error-codes"))
    return success


def _domain_is_disposable(domain: str) -> bool:
    return domain.lower() in DISPOSABLE_EMAIL_DOMAINS


def _domain_has_mx_record(domain: str) -> bool:
    try:
        answers = dns_resolver.resolve(domain, "MX", lifetime=3.0)
        return bool(answers)
    except dns_exception.DNSException:
        current_app.logger.warning("Unable to verify MX for domain=%s", domain)
        return False


def _check_registration_rate_limit(email: str | None, ip: str | None):
    if REGISTRATION_RATE_LIMIT_WINDOW <= timedelta(0):
        return True, None
    cutoff = datetime.now(timezone.utc) - REGISTRATION_RATE_LIMIT_WINDOW
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                if REGISTRATION_RATE_LIMIT_PER_EMAIL > 0 and email:
                    cur.execute(
                        """
                        SELECT COUNT(1)
                          FROM registration_attempts
                         WHERE lower(email) = lower(%s)
                           AND created_at >= %s
                        """,
                        (email, cutoff),
                    )
                    if cur.fetchone()[0] >= REGISTRATION_RATE_LIMIT_PER_EMAIL:
                        return False, "Too many attempts for that email. Please try again later."

                if REGISTRATION_RATE_LIMIT_PER_IP > 0 and ip:
                    cur.execute(
                        """
                        SELECT COUNT(1)
                          FROM registration_attempts
                         WHERE ip = %s
                           AND created_at >= %s
                        """,
                        (ip, cutoff),
                    )
                    if cur.fetchone()[0] >= REGISTRATION_RATE_LIMIT_PER_IP:
                        return False, "Too many registrations from this network. Please wait and try again."
    except psycopg2.errors.UndefinedTable:
        current_app.logger.warning("registration_attempts table missing; skipping rate limit enforcement")
        return True, None
    except psycopg2.Error:
        current_app.logger.exception("Unable to check registration rate limit")
        return True, None

    return True, None


def _record_registration_attempt(email: str | None, ip: str | None):
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO registration_attempts (email, ip)
                    VALUES (%s, %s)
                    """,
                    (email, ip),
                )
            conn.commit()
    except psycopg2.errors.UndefinedTable:
        current_app.logger.warning("registration_attempts table missing; skipping attempt logging")
    except psycopg2.Error:
        current_app.logger.exception("Failed to record registration attempt")


def _render_register_template(trainer_mode: bool):
    endpoint = 'trainer_register' if trainer_mode else 'register'
    return render_template(
        'register.html',
        trainer_mode=trainer_mode,
        form_action=url_for(endpoint),
        turnstile_enabled=TURNSTILE_ENABLED,
        turnstile_site_key=TURNSTILE_SITE_KEY,
    )


def _handle_registration(trainer_mode: bool):
    if 'user_id' in session:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        raw_email = (request.form.get('email') or '').strip()
        email = raw_email.lower() or None
        password = request.form.get('password') or ''
        confirmation = request.form.get('confirmation') or ''

        if not username:
            flash("Username is required", "danger"); return _render_register_template(trainer_mode)
        if not raw_email:
            flash("Email is required", "danger"); return _render_register_template(trainer_mode)
        if not re.match(r"^[^@]+@[^@]+\.[^@]+$", raw_email):
            flash("Please enter a valid email address.", "danger"); return _render_register_template(trainer_mode)
        if not password or not confirmation:
            flash("Password and confirmation are required", "danger"); return _render_register_template(trainer_mode)
        if len(username) > 50 or len(username) < 3:
            flash("Username must be 3–50 characters", "danger"); return _render_register_template(trainer_mode)
        if len(password) < 8:
            flash("Password must be at least 8 characters", "danger"); return _render_register_template(trainer_mode)
        if not any(c.isupper() for c in password):
            flash("Password must include at least one uppercase letter", "danger"); return _render_register_template(trainer_mode)
        if not any(c in "!@#$%^&*()-_+=<>?/{}~" for c in password):
            flash("Password must include at least one special character", "danger"); return _render_register_template(trainer_mode)
        if password != confirmation:
            flash("Passwords do not match", "danger"); return _render_register_template(trainer_mode)

        client_ip = _get_request_ip()
        turnstile_token = (request.form.get('cf-turnstile-response') or '').strip()

        if TURNSTILE_ENABLED:
            if not turnstile_token:
                flash("Please complete the verification challenge.", "danger"); return _render_register_template(trainer_mode)
            if not _verify_turnstile_token(turnstile_token, client_ip):
                flash("We couldn't verify that you're human. Please try again.", "danger"); return _render_register_template(trainer_mode)

        if email:
            domain = email.rsplit('@', 1)[1]
            if _domain_is_disposable(domain):
                flash("Please use a permanent email address.", "danger"); return _render_register_template(trainer_mode)
            if not _domain_has_mx_record(domain):
                flash("We couldn't confirm that email provider receives messages. Try another email.", "danger"); return _render_register_template(trainer_mode)

        allowed, rate_limit_message = _check_registration_rate_limit(email, client_ip)
        if not allowed:
            flash(rate_limit_message or "Too many registration attempts. Please try again later.", "danger"); return _render_register_template(trainer_mode)

        _record_registration_attempt(email, client_ip)

        subscription_type = 'pro' if trainer_mode else 'free'
        role = 'trainer' if trainer_mode else 'user'

        with get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT 1 FROM users WHERE lower(username)=lower(%s) LIMIT 1", (username,))
                if cur.fetchone():
                    flash("Username already exists", "danger")
                    return _render_register_template(trainer_mode)

                if email:
                    cur.execute("SELECT 1 FROM users WHERE lower(email)=lower(%s) LIMIT 1", (email,))
                    if cur.fetchone():
                        flash("An account with that email already exists", "danger")
                        return _render_register_template(trainer_mode)

                hashed_password = generate_password_hash(password)

                try:
                    cur.execute("""
                        INSERT INTO users (username, hash, email, email_verified, subscription_type, role)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        RETURNING id
                    """, (username, hashed_password, email, False, subscription_type, role))
                    user_row = cur.fetchone()
                    user_id = user_row['id']

                    raw_token, expires_at, _token_id = issue_single_use_token(conn, user_id, "verify_email", VERIFY_TTL_HOURS)  
                    verify_url = url_for("verify_email", token=raw_token, _external=True)
                    resend_url  = url_for("resend_verify_confirm", _external=True)

                    conn.commit()

                except psycopg2.Error as e:
                    if isinstance(e, psycopg2.errors.UniqueViolation):
                        flash("That username or email is already in use", "danger")
                    else:
                        flash("Error creating account", "danger")
                    conn.rollback()
                    return _render_register_template(trainer_mode)

        try:
            send_verification_email(
                to_email=email,
                verify_url=verify_url,
                first_name=username,
                ttl_hours=VERIFY_TTL_HOURS,
                current_year=date.today().year,
                resend_url=resend_url
            )
        except Exception:
            current_app.logger.exception("Failed sending welcome/verification email")

        flash("Registration successful! Please check your email to verify your account.", "success")
        return redirect('/login')

    return _render_register_template(trainer_mode)


@app.route('/register', methods=['GET', 'POST'])
def register():
    return _handle_registration(trainer_mode=False)


@app.route('/trainer/register', methods=['GET', 'POST'])
def trainer_register():
    return _handle_registration(trainer_mode=True)


@app.route('/verify_email')
def verify_email():
    token = request.args.get('token', '').strip()
    if not token:
        flash("Invalid verification link.", "danger")
        return redirect(url_for('login'))

    try:
        with get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                token_row = validate_token(conn, token, "verify_email")  
                if not token_row:
                    digest = hash_token(token)

                    cur.execute("""
                        SELECT u.email_verified
                          FROM user_tokens ut
                          JOIN users u ON u.id = ut.user_id
                         WHERE ut.purpose = %s
                           AND ut.token_digest = %s
                         LIMIT 1
                    """, ("verify_email", digest))
                    row = cur.fetchone()

                    if row and bool(row['email_verified']):
                        flash("Your email is verified. Please log in.", "success")
                        return redirect(url_for('login'))
                
                    flash("That verification link is invalid or expired. Please try again.", "danger")
                    return redirect(url_for('login'))

                user_id = token_row['user_id']
                mark_token_used(conn, token_row["token_id"])
                cur.execute("UPDATE users SET email_verified = TRUE WHERE id = %s", (user_id,))
                conn.commit()

        flash("Your email has been verified. You can now log in.", "success")
        return redirect(url_for('login'))

    except Exception:
        current_app.logger.exception("Email verification error")
        flash("Something went wrong verifying your email. Please try again.", "danger")
        return redirect(url_for('login'))


@app.get("/verify/resend")
def resend_verify_confirm():
    prefill_email = ""
    if 'user_id' in session:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT email FROM users WHERE id = %s", (session['user_id'],))
                row = cur.fetchone()
                if row and row[0]:
                    prefill_email = row[0]
    return render_template("resend_verify_confirm.html", prefill_email=prefill_email)



@app.post("/verify/resend")
def resend_verify_do():
    """POST: actually issue a new token and email using an email address."""
    generic_msg = "If an account exists and isn’t verified, we’ve sent a new verification link."
    raw_email = (request.form.get("email") or "").strip()

    if not raw_email:
        flash("Please enter the email address associated with your account.", "danger")
        return redirect(url_for("resend_verify_confirm"))
    if not re.match(r"^[^@]+@[^@]+\.[^@]+$", raw_email):
        flash("Please enter a valid email address.", "danger")
        return redirect(url_for("resend_verify_confirm"))

    normalized_email = normalize_email(raw_email)

    try:
        with get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT id AS user_id, email, username, email_verified
                      FROM users
                     WHERE lower(email) = lower(%s)
                     LIMIT 1
                """, (normalized_email,))
                row = cur.fetchone()

                if not row:
                    flash(generic_msg, "info")
                    return redirect(url_for("login"))

                if row["email_verified"]:
                    flash("Your email is already verified. Please log in.", "success")
                    return redirect(url_for("login"))

                cur.execute("""
                    SELECT created_at
                      FROM user_tokens
                     WHERE user_id = %s AND purpose = %s
                     ORDER BY created_at DESC
                     LIMIT 1
                """, (row["user_id"], VERIFY_PURPOSE))

                last = cur.fetchone()
                now = datetime.now(timezone.utc)

                if last:
                    last_ts = last["created_at"]
                    if last_ts.tzinfo is None:
                        last_ts = last_ts.replace(tzinfo=timezone.utc)

                    delta = now - last_ts
                    if delta < timedelta(seconds=RESEND_COOLDOWN_SECONDS):
                        remaining = max(1, RESEND_COOLDOWN_SECONDS - int(delta.total_seconds()))
                        flash(f"A verification email was just sent. Please verify or try again in ~{remaining}s.", "warning")
                        return redirect(url_for("login"))

                cur.execute("""
                    UPDATE user_tokens
                       SET used_at = %s
                     WHERE user_id = %s
                       AND purpose = %s
                       AND used_at IS NULL
                """, (now, row["user_id"], VERIFY_PURPOSE))

                new_raw, _expires_at, _token_id = issue_single_use_token(conn, row["user_id"], VERIFY_PURPOSE, VERIFY_TTL_HOURS)
                new_verify_url = url_for("verify_email", token=new_raw, _external=True)
                conn.commit()

        send_verification_email(
            to_email=row["email"],
            first_name=row["username"],
            verify_url=new_verify_url,
            ttl_hours=VERIFY_TTL_HOURS,
            resend_url=url_for("resend_verify_confirm", _external=True)
        )
        flash("We've sent you a new verification link.", "success")
        return redirect(url_for("login"))

    except Exception:
        current_app.logger.exception("Resend via email failed")
        flash(generic_msg, "info")
        return redirect(url_for("login"))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('home'))  

    if request.method == 'POST':
        session.clear()

        identifier = (request.form.get('username') or '').strip()  
        password = request.form.get('password') or ''

        if not identifier or not password:
            flash("Must provide username/email and password", "danger")
            return render_template('login.html')

        with get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                if '@' in identifier:
                    cur.execute("""
                        SELECT id, username, email, hash, status, email_verified, role, session_version
                        FROM users
                        WHERE lower(email) = lower(%s)
                        LIMIT 1
                    """, (identifier,))
                else:
                    cur.execute("""
                        SELECT id, username, email, hash, status, email_verified, role, session_version
                        FROM users
                        WHERE lower(username) = lower(%s)
                        LIMIT 1
                    """, (identifier,))
                user = cur.fetchone()

        # Basic auth check
        if not user or not user['hash'] or not check_password_hash(user['hash'], password):
            flash("Invalid username and/or password", "danger")
            return render_template('login.html')

        # Account state gates
        if user['status'] == 'disabled':
            flash("Your account is disabled. Please contact support.", "danger")
            return render_template('login.html')

        if user['status'] in ('invited', 'pending'):
            flash("Please finish account setup using your invite/verification link.", "warning")
            return render_template('login.html')

        # Enforce email verification to login
        if user['email'] and not user['email_verified']:
            flash("Please verify your email before logging in.", "warning")
            return render_template('login.html')

        # Success → remember session
        session['user_id'] = user['id']
        session['session_version'] = user.get('session_version', 1)
        session['session_version_checked_at'] = datetime.now(timezone.utc).isoformat()
        normalized_role = _normalize_role_value(user.get('role'), default='user')
        session['role'] = normalized_role
        session['is_admin'] = (normalized_role == 'admin')

        # Stamp last login
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE users SET last_login_at = now() WHERE id = %s", (user['id'],))
                conn.commit()

        flash("Login successful!", "success")
        return redirect(url_for('home'))  

    return render_template('login.html')


@app.before_request
def check_trial_status_and_subscription():
    print("Before request endpoint:", request.endpoint)
    if 'user_id' not in session:
        return

    # Skip checks for static files and public routes
    if request.endpoint in ['static', 'login', 'register', 'logout', None]:
        return

    enforcement_response = _enforce_session_version(session['user_id'])
    if enforcement_response:
        return enforcement_response

    _resolve_user_role(user_id=session['user_id'])

    # Run the checks once per day per user session
    today = datetime.now(timezone.utc).date().isoformat()
    if session.get('trial_checked_on') != today:
        check_and_downgrade_trial(session['user_id'])
        check_subscription_expiry(session['user_id'])
        session['trial_checked_on'] = today


@app.route('/logout')
def logout():
    """Log user out"""
    session.clear()
    flash("You have been logged out.", "success")
    return redirect('/login')


@app.route('/favicon.ico')
def favicon():
    """Serve the favicon from the static directory."""
    return send_from_directory(
        os.path.join(app.root_path, 'static'),
        'favicon.png',
        mimetype='image/png',
    )


@app.route('/training', methods=['GET', 'POST'])
@login_required
def training():
    """Handle personal training form and display workout options."""
    user_id = session['user_id']
    # Always enforce downgrade check before premium content
    check_and_downgrade_trial(user_id)
    check_subscription_expiry(user_id)
    form_completed = False  # Default flag to determine what to show
    injury_regions_prefill = []
    cardio_restriction_prefill = False
    injury_details_prefill = ''
    injury_status_prefill = 'No'
    user_role = 'user'
    workout_duration = None
    fitness_goals = None
    trainer_client_count_prefill = None
    trainer_sessions_per_week_prefill = None
    trainer_focus_areas_prefill = ''
    trainer_platform_goals_prefill = ''

    try:
        # Check if the form has already been completed
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT form_completed, exercise_history, fitness_goals, workout_duration,
                           injury, injury_details, cardio_restriction, role,
                           trainer_client_count, trainer_sessions_per_week,
                           trainer_focus_areas, trainer_platform_goals
                      FROM users
                     WHERE id = %s
                    """,
                    (user_id,)
                )
                result = cursor.fetchone()
                form_completed = bool(result[0])
                exercise_history = result[1]
                fitness_goals = result[2]
                workout_duration = result[3]
                injury_profile = parse_injury_payload(result[4])
                injury_regions_prefill = injury_profile['regions']
                cardio_restriction_prefill = bool(result[6]) or injury_profile['cardio']
                injury_details_prefill = result[5]
                user_role = result[7] or 'user'
                trainer_client_count_prefill = _normalize_trainer_bucket(result[8], TRAINER_CLIENT_COUNT_BUCKETS)
                trainer_sessions_per_week_prefill = _normalize_trainer_bucket(result[9], TRAINER_SESSION_BUCKETS)
                trainer_focus_areas_prefill = result[10] or ''
                trainer_platform_goals_prefill = result[11] or ''
                injury_status_prefill = 'Yes' if (injury_regions_prefill or cardio_restriction_prefill or (injury_details_prefill or '').strip()) else 'No'
    except Exception as e:
        flash(f"An error occurred: {e}", "danger")
        return render_template(
            'training.html',
            user=None,
            form_completed=False,
            workouts=[],
            grouped_workouts={},
            target_heart_rate_zone=None,
            guidelines={},
            fitness_goals=None,
            workout_duration=None,
            current_date=date.today(),
            injury_regions=injury_regions_prefill,
            injury_details=injury_details_prefill,
            injury_status=injury_status_prefill,
            cardio_restriction=cardio_restriction_prefill,
            injury_excluded_categories=[],
            injury_skipped_subcategories=[],
            custom_workout_categories=CUSTOM_WORKOUT_CATEGORIES,
            custom_workout_limits=CUSTOM_WORKOUT_SELECTION_LIMITS,
            custom_workout_token=CUSTOM_WORKOUT_TOKEN,
            home_workout_token=HOME_WORKOUT_TOKEN,
            home_equipment_options=HOME_EQUIPMENT_OPTIONS,
            user_role=user_role,
            trainer_client_count_prefill=trainer_client_count_prefill,
            trainer_sessions_per_week_prefill=trainer_sessions_per_week_prefill,
            trainer_focus_areas_prefill=trainer_focus_areas_prefill,
            trainer_platform_goals_prefill=trainer_platform_goals_prefill,
            trainer_client_count_options=TRAINER_CLIENT_COUNT_BUCKETS,
            trainer_sessions_per_week_options=TRAINER_SESSION_BUCKETS,
        )

    # If the user submits the form and it hasn't been completed yet
    if request.method == 'POST' and not form_completed:
        # Get form data
        name = request.form.get('name')
        last_name = request.form.get('last_name')
        age = int_or_none(request.form.get('age'))
        weight = float_or_none(request.form.get('weight'))
        height_feet = int_or_none(request.form.get('height_feet'))
        height_inches = inches_0_11_or_none(request.form.get('height_inches'))
        gender = request.form.get('gender')
        exercise_history = request.form.get('exercise_history')
        fitness_goals = request.form.getlist('fitness_goals')  # List of selected goals
        injury_status = request.form.get('injury_status') or 'No'
        injury_payload_raw = request.form.get('injury') or '[]'
        injury_details = request.form.get('injury_details')
        cardio_restriction_input = (request.form.get('cardio_restriction') == 'yes')
        injury_payload_form = parse_injury_payload(injury_payload_raw)
        injury_regions_selected = injury_payload_form['regions']
        cardio_restriction_value = cardio_restriction_input or injury_payload_form['cardio']
        workout_duration_raw = request.form.get('workout_duration')
        commitment = request.form.get('commitment')
        additional_notes = request.form.get('additional_notes')
        waiver = request.form.get('waiver')
        trainer_client_count = None
        trainer_sessions_per_week = None
        trainer_focus_areas = None
        trainer_platform_goals = None
        is_trainer = (user_role == 'trainer')

        if is_trainer:
            trainer_client_count = int_or_none(request.form.get('trainer_client_count'))
            trainer_sessions_per_week = int_or_none(request.form.get('trainer_sessions_per_week'))
            trainer_focus_areas = (request.form.get('trainer_focus_areas') or '').strip()
            trainer_platform_goals = (request.form.get('trainer_platform_goals') or '').strip()


        # Combine fitness goals into a single string
        fitness_goals_str = ", ".join(fitness_goals)

        # Validate required fields
        errors = {}

        # Name
        if not (name or "").strip():
            errors['name'] = "First name is required."
        if not (last_name or "").strip():
            errors['last_name'] = "Last name is required."

        # Numbers
        if age is None or age < 0:
            errors['age'] = "Enter your age as a whole number (0 or more)."
        if weight is None or weight < 0 or weight > 999.9:
            errors['weight'] = "Enter a weight between 0 and 999.9."
        if height_feet is None or height_feet < 0:
            errors['height_feet'] = "Feet must be a whole number (0 or more)."
        if height_inches is None:
            errors['height_inches'] = "Inches must be a whole number from 0 to 11."

        # Radios/selects
        if gender not in ("Male", "Female"):
            errors['gender'] = "Please select your gender."
        if not exercise_history:
            errors['exercise_history'] = "Please select your exercise history."
        if not commitment:
            errors['commitment'] = "Please select your weekly commitment."

        injury_status_normalized = injury_status.strip().title()
        if injury_status_normalized not in ("Yes", "No"):
            errors['injury_status'] = "Please let us know if you currently have injuries or restrictions."

        # Checkboxes (1–2 goals)
        if len(fitness_goals) < 1 or len(fitness_goals) > 2:
            errors['fitness_goals'] = "Please select 1–2 fitness goals."

        # Injury requirements (only if 'Yes')
        if injury_status_normalized == "Yes":
            if not injury_regions_selected and not cardio_restriction_value:
                errors['injury'] = "Please choose at least one area FitBaseAI should skip."
            if not (injury_details or "").strip():
                errors['injury_details'] = "Please share a few details about the injury or restriction."

        allowed_durations = {"20", "30", "45", "60"}
        if workout_duration_raw not in allowed_durations:
            errors['workout_duration'] = "Please select a valid workout duration."
            
        if not waiver:
            errors["waiver"] = "You must agree to the Terms of Service and Liability Waiver."

        if is_trainer:
            if trainer_client_count is None or trainer_client_count not in TRAINER_CLIENT_BUCKET_CODES:
                errors['trainer_client_count'] = "Select the range that best matches your client load."
            if trainer_sessions_per_week is None or trainer_sessions_per_week not in TRAINER_SESSION_BUCKET_CODES:
                errors['trainer_sessions_per_week'] = "Select the range that best matches your weekly cadence."
            if not trainer_focus_areas:
                errors['trainer_focus_areas'] = "Tell us about the clients you specialize in coaching."
            elif len(trainer_focus_areas) > TRAINER_PROFILE_TEXT_LIMIT:
                trainer_focus_areas = trainer_focus_areas[:TRAINER_PROFILE_TEXT_LIMIT]
            if not trainer_platform_goals:
                errors['trainer_platform_goals'] = "Share how you'll use FitBaseAI with your clients."
            elif len(trainer_platform_goals) > TRAINER_PROFILE_TEXT_LIMIT:
                trainer_platform_goals = trainer_platform_goals[:TRAINER_PROFILE_TEXT_LIMIT]

        if errors:
            flash("Please fix the highlighted fields.", "danger")
            # Re-render with what the user typed + which fields failed
            return render_template(
                'training.html',
                form_completed=False,
                form_data=request.form,
                errors=errors,
                injury_regions=injury_regions_selected,
                injury_details=injury_details or '',
                injury_status=injury_status_normalized,
                cardio_restriction=cardio_restriction_value,
                injury_excluded_categories=compute_injury_exclusions(injury_regions_selected, cardio_restriction_value),
                injury_skipped_subcategories=[],
                custom_workout_categories=CUSTOM_WORKOUT_CATEGORIES,
                custom_workout_limits=CUSTOM_WORKOUT_SELECTION_LIMITS,
                custom_workout_token=CUSTOM_WORKOUT_TOKEN,
                home_workout_token=HOME_WORKOUT_TOKEN,
                home_equipment_options=HOME_EQUIPMENT_OPTIONS,
                user_role=user_role,
                trainer_client_count_prefill=trainer_client_count_prefill,
                trainer_sessions_per_week_prefill=trainer_sessions_per_week_prefill,
                trainer_focus_areas_prefill=trainer_focus_areas_prefill,
                trainer_platform_goals_prefill=trainer_platform_goals_prefill,
                trainer_client_count_options=TRAINER_CLIENT_COUNT_BUCKETS,
                trainer_sessions_per_week_options=TRAINER_SESSION_BUCKETS,
            ), 400
        
        workout_duration = int(workout_duration_raw)
        injury_json = json.dumps(injury_regions_selected)
        is_injury_free = (injury_status_normalized == "No")
        trainer_client_count_value = trainer_client_count if is_trainer else None
        trainer_sessions_per_week_value = trainer_sessions_per_week if is_trainer else None
        trainer_focus_areas_value = trainer_focus_areas if is_trainer else None
        trainer_platform_goals_value = trainer_platform_goals if is_trainer else None

        # Connect to the database and update user information
        try:
            with get_connection() as conn:
                with conn.cursor() as cursor:
                    trial_end_date = datetime.today().date() + timedelta(days=14)
                    cursor.execute("""
                        UPDATE users
                        SET 
                            age = %s, weight = %s, height_feet = %s, height_inches = %s, 
                            gender = %s, exercise_history = %s, fitness_goals = %s, 
                            injury = %s, injury_details = %s, cardio_restriction = %s,
                            commitment = %s, additional_notes = %s, 
                            trainer_client_count = %s, trainer_sessions_per_week = %s,
                            trainer_focus_areas = %s, trainer_platform_goals = %s,
                            name = %s, last_name = %s, form_completed = TRUE, workout_duration = %s,
                            injury_free_since = CASE WHEN %s THEN COALESCE(injury_free_since, CURRENT_DATE) ELSE NULL END,
                            subscription_type = CASE 
                                WHEN role = 'trainer' THEN 'pro'
                                ELSE 'premium'
                            END,
                            trial_end_date = %s
                        WHERE id = %s
                    """, (
                        age, weight, height_feet, height_inches, gender, 
                        exercise_history, fitness_goals_str, injury_json, injury_details,
                        cardio_restriction_value,
                        commitment, additional_notes,
                        trainer_client_count_value, trainer_sessions_per_week_value,
                        trainer_focus_areas_value, trainer_platform_goals_value,
                        name, last_name, workout_duration, 
                        is_injury_free, trial_end_date, user_id
                    ))
                    conn.commit()

                    plan_label = "Pro" if user_role == 'trainer' else "Premium"
                    flash(f"✅ Your 14-day free {plan_label} trial has started! You now have full access to the personalized workout generator and tracking.", "success")

            form_completed = True  # Mark the form as completed
            injury_regions_prefill = injury_regions_selected
            cardio_restriction_prefill = cardio_restriction_value
            injury_details_prefill = injury_details
            injury_status_prefill = 'Yes' if (injury_regions_selected or cardio_restriction_value or (injury_details or '').strip()) else 'No'
            trainer_client_count_prefill = trainer_client_count_value
            trainer_sessions_per_week_prefill = trainer_sessions_per_week_value
            trainer_focus_areas_prefill = trainer_focus_areas_value or ''
            trainer_platform_goals_prefill = trainer_platform_goals_value or ''
            flash("Your information has been successfully updated!", "success")
        except Exception as e:
            flash(f"An error occurred: {e}", "danger")
            return render_template(
                'training.html',
                user=None,
                form_completed=False,
                form_data=request.form,
                workouts=[],
                grouped_workouts={},
                target_heart_rate_zone=None,
                guidelines={},
                fitness_goals=fitness_goals_str,
                workout_duration=None,
                current_date=date.today(),
                injury_regions=injury_regions_selected,
                injury_details=injury_details or '',
                injury_status=injury_status_normalized,
                cardio_restriction=cardio_restriction_value,
                injury_excluded_categories=[],
                injury_skipped_subcategories=[],
                errors=None,
                custom_workout_categories=CUSTOM_WORKOUT_CATEGORIES,
                custom_workout_limits=CUSTOM_WORKOUT_SELECTION_LIMITS,
                custom_workout_token=CUSTOM_WORKOUT_TOKEN,
                home_workout_token=HOME_WORKOUT_TOKEN,
                home_equipment_options=HOME_EQUIPMENT_OPTIONS,
                user_role=user_role,
                trainer_client_count_prefill=trainer_client_count_value,
                trainer_sessions_per_week_prefill=trainer_sessions_per_week_value,
                trainer_focus_areas_prefill=trainer_focus_areas_value or '',
                trainer_platform_goals_prefill=trainer_platform_goals_value or '',
                trainer_client_count_options=TRAINER_CLIENT_COUNT_BUCKETS,
                trainer_sessions_per_week_options=TRAINER_SESSION_BUCKETS,
            )

    categories = get_category_groups()
    grouped_workouts = {}
    workouts = []
    target_heart_rate_zone = None
    guidelines = {}

    # Single connection block for fetching grouped workouts and user data
    with get_connection() as conn:
        with conn.cursor() as cursor:
            try:
                # Fetch grouped workouts
                for category, group in categories.items():
                    placeholders = ",".join(["%s"] * len(group))
                    query = f"""
                        SELECT name, description
                          FROM workouts
                         WHERE category IN ({placeholders})
                         ORDER BY CASE movement_type
                                      WHEN 'compound' THEN 1
                                      WHEN 'accessory' THEN 2
                                      ELSE 3
                                  END,
                                  name
                    """
                    cursor.execute(query, group)
                    grouped_workouts[category] = cursor.fetchall()

                # Fetch the user's exercise history and age
                cursor.execute(
                    """
                    SELECT exercise_history, age, fitness_goals, injury, cardio_restriction
                      FROM users
                     WHERE id = %s
                    """,
                    (user_id,)
                )
                user_data = cursor.fetchone()

                if user_data:
                    exercise_history = user_data[0]
                    age = int(user_data[1]) if user_data[1] else None
                    fitness_goals = user_data[2] if user_data[2] else "Not set yet"
                    injury_for_filter = parse_injury_payload(user_data[3])
                    cardio_flag_for_filter = bool(user_data[4]) or injury_for_filter['cardio']
                    injury_regions_prefill = injury_regions_prefill or injury_for_filter['regions']
                    cardio_restriction_prefill = cardio_restriction_prefill or cardio_flag_for_filter
                    injury_status_prefill = 'Yes' if (injury_regions_prefill or cardio_restriction_prefill or (injury_details_prefill or '').strip()) else 'No'
                    injury_excluded_categories = compute_injury_exclusions(injury_for_filter['regions'], cardio_flag_for_filter)
                    skipped_subcategories = set()

                    user_level = get_user_level(exercise_history)

                    # Calculate target heart rate zone
                    if age:
                        target_heart_rate_zone = calculate_target_heart_rate(age)

                    # Fetch workouts matching the user's level
                    cursor.execute(
                        """
                        SELECT name, description, category, subcategory
                          FROM workouts
                         WHERE level <= %s
                         ORDER BY CASE movement_type
                                      WHEN 'compound' THEN 1
                                      WHEN 'accessory' THEN 2
                                      ELSE 3
                                  END,
                                  name
                        """,
                        (user_level,)
                    )
                    all_workouts = cursor.fetchall()
                    filtered_workouts = []
                    for workout_row in all_workouts:
                        category_name = (workout_row[2] or '').upper()
                        subcategory_name = (workout_row[3] or '').upper()
                        if category_name in injury_excluded_categories or subcategory_name in injury_excluded_categories:
                            if subcategory_name:
                                skipped_subcategories.add(subcategory_name)
                            elif category_name:
                                skipped_subcategories.add(category_name)
                            continue
                        filtered_workouts.append(workout_row[:2])
                    workouts = filtered_workouts

                    # Fetch guidelines based on user's level and fitness goals
                    if exercise_history and fitness_goals:
                        guidelines = get_guidelines(exercise_history, fitness_goals)

                else:
                    flash("User information not found. Please update your profile.", "warning")

            except Exception as e:
                flash(f"An error occurred: {e}", "danger")

    injury_excluded_categories = compute_injury_exclusions(injury_regions_prefill, cardio_restriction_prefill)
    skipped_subcategories = locals().get('skipped_subcategories', set())

    # Fetch full user row (including subscription_type, trial_end_date, etc.)
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            user = cursor.fetchone()

    personal_workout_customization_enabled = _user_can_customize_personal_workout(user)
    personal_workout_reorder_url = (
        url_for('personal_reorder_workout_exercises') if personal_workout_customization_enabled else ''
    )
    personal_exercise_refresh_template = (
        url_for('personal_refresh_workout_exercise', workout_id=0) if personal_workout_customization_enabled else ''
    )
    personal_exercise_alternates_template = (
        url_for('personal_list_workout_alternatives', workout_id=0) if personal_workout_customization_enabled else ''
    )

    return render_template(
        'training.html', 
        user=user,
        form_completed=form_completed, 
        workouts=workouts, 
        target_heart_rate_zone=target_heart_rate_zone, 
        grouped_workouts=grouped_workouts, 
        guidelines=guidelines,
        fitness_goals=fitness_goals, 
        workout_duration=workout_duration,
        current_date=date.today(),
        injury_regions=injury_regions_prefill,
        injury_details=injury_details_prefill,
        injury_status=injury_status_prefill,
        cardio_restriction=cardio_restriction_prefill,
        injury_excluded_categories=sorted(injury_excluded_categories),
        injury_skipped_subcategories=sorted({sub for sub in skipped_subcategories if sub}),
        custom_workout_categories=CUSTOM_WORKOUT_CATEGORIES,
        custom_workout_limits=CUSTOM_WORKOUT_SELECTION_LIMITS,
        custom_workout_token=CUSTOM_WORKOUT_TOKEN,
        home_workout_token=HOME_WORKOUT_TOKEN,
        home_equipment_options=HOME_EQUIPMENT_OPTIONS,
        user_role=user_role,
        trainer_client_count_prefill=trainer_client_count_prefill,
        trainer_sessions_per_week_prefill=trainer_sessions_per_week_prefill,
        trainer_focus_areas_prefill=trainer_focus_areas_prefill,
        trainer_platform_goals_prefill=trainer_platform_goals_prefill,
        trainer_client_count_options=TRAINER_CLIENT_COUNT_BUCKETS,
        trainer_sessions_per_week_options=TRAINER_SESSION_BUCKETS,
        personal_workout_customization_enabled=personal_workout_customization_enabled,
        personal_workout_reorder_url=personal_workout_reorder_url,
        personal_exercise_refresh_template=personal_exercise_refresh_template,
        personal_exercise_alternates_template=personal_exercise_alternates_template,
        notes_placeholder=WORKOUT_NOTES_PLACEHOLDER,
    )


@app.route('/trainer_dashboard')
@login_required
def trainer_dashboard():
    """Render trainer dashboard with stats and assigned clients."""
    user_id = session['user_id']
    # Downgrade immediately if the trial/subscription has lapsed
    check_and_downgrade_trial(user_id)
    check_subscription_expiry(user_id)
    trainer = _require_trainer(user_id)
    if not trainer:
        flash("Trainer access requires an active plan.", "danger")
        return redirect(url_for('home'))
    if trainer.get('role') == 'trainer' and not trainer.get('form_completed'):
        flash("Complete your fitness questionnaire to unlock the trainer dashboard.", "warning")
        return redirect(url_for('training'))

    search_term = (request.args.get('search') or '').strip()
    total_clients = 0

    sessions_completed_all_time = 0
    package_map: dict[int, list[dict]] = {}
    package_usage_counts: dict[int, dict[str, int]] = {}
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                "SELECT COUNT(*) AS total_count FROM users WHERE trainer_id = %s",
                (user_id,),
            )
            total_clients = (cursor.fetchone() or {}).get('total_count') or 0

            base_query = [
                """
                SELECT u.id, u.username, u.name, u.last_name, u.email, u.fitness_goals,
                       u.workouts_completed, u.last_workout_completed,
                       u.sessions_remaining,
                       COALESCE(u.sessions_booked, 0) AS sessions_booked,
                       t.name AS trainer_name, t.last_name AS trainer_last_name,
                       t.username AS trainer_username
                  FROM users u
             LEFT JOIN users t
                    ON u.trainer_id = t.id
                 WHERE u.trainer_id = %s
                """
            ]
            params = [user_id]

            if search_term:
                like = f"%{search_term}%"
                base_query.append(
                    """
                    AND (
                        u.username ILIKE %s OR
                        u.name ILIKE %s OR
                        u.last_name ILIKE %s OR
                        u.email ILIKE %s OR
                        (COALESCE(u.name, '') || ' ' || COALESCE(u.last_name, '')) ILIKE %s
                    )
                    """
                )
                params.extend([like, like, like, like, like])

            base_query.append("ORDER BY u.name NULLS LAST, u.last_name NULLS LAST, u.username")
            cursor.execute("\n".join(base_query), params)
            clients = cursor.fetchall() or []

        if clients:
            client_ids_for_packages = [client['id'] for client in clients]
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute(
                    """
                    SELECT id,
                           client_id,
                           trainer_id,
                           label,
                           sessions_purchased,
                           price_paid,
                           currency,
                           note,
                           purchased_at
                      FROM client_session_packages
                     WHERE trainer_id = %s
                       AND client_id = ANY(%s)
                     ORDER BY purchased_at ASC, id ASC
                    """,
                    (user_id, client_ids_for_packages),
                )
                for row in cursor.fetchall() or []:
                    package_map.setdefault(row['client_id'], []).append(row)
            if package_map:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                    package_usage_counts = _fetch_package_usage_counts(
                        cursor,
                        user_id,
                        list(package_map.keys()),
                    )
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT COUNT(*)
                  FROM trainer_schedule
                 WHERE trainer_id = %s
                   AND status = 'completed'
                """,
                (user_id,),
            )
            sessions_completed_all_time = cursor.fetchone()[0] or 0

    client_ids = [client['id'] for client in clients]
    booked_counts, completed_counts = _compute_client_schedule_counts(user_id, client_ids, sync_booked=True)

    total_sessions_completed = 0
    for client in clients:
        booked_sessions = booked_counts.get(client['id'], 0)
        client['sessions_booked'] = booked_sessions
        completed_sessions = completed_counts.get(client['id'], 0)
        client['sessions_completed_count'] = completed_sessions
        total_sessions_completed += completed_sessions
        packages = package_map.get(client['id']) or []
        if packages:
            usage_counts = package_usage_counts.get(client['id']) or {}
            package_booked = usage_counts.get('booked', booked_sessions)
            package_completed = usage_counts.get('completed', completed_sessions)
            summary = _compute_session_package_summary(
                packages,
                int(package_booked or 0),
                int(package_completed or 0),
            )
            client['sessions_total'] = summary['sessions_total']
            client['sessions_left'] = summary['sessions_left']
            client['using_session_packages'] = True
        else:
            total_sessions = client.get('sessions_remaining')
            client['sessions_total'] = total_sessions
            if total_sessions is None:
                client['sessions_left'] = None
            else:
                used = min(total_sessions, booked_sessions + completed_sessions)
                client['sessions_left'] = max(total_sessions - used, 0)

    trainer_stats = {
        'total_clients': total_clients,
        'sessions_completed': total_sessions_completed,
        'sessions_completed_all_time': sessions_completed_all_time,
    }

    trainer_info = {
        'name': trainer.get('name'),
        'last_name': trainer.get('last_name'),
        'username': trainer.get('username'),
        'role': trainer.get('role'),
    }

    schedule_prefs = {'view_start': DEFAULT_CALENDAR_WINDOW[0], 'view_end': DEFAULT_CALENDAR_WINDOW[1]}
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                "SELECT view_start, view_end FROM trainer_schedule_preferences WHERE trainer_id = %s",
                (user_id,),
            )
            row = cursor.fetchone()
            if row:
                start_hour, end_hour = _normalize_calendar_window(
                    row.get('view_start'),
                    row.get('view_end'),
                )
                schedule_prefs = {'view_start': start_hour, 'view_end': end_hour}

    return render_template(
        'trainer_dashboard.html',
        trainer_stats=trainer_stats,
        clients=clients,
        trainer=trainer_info,
        schedule_prefs=schedule_prefs,
        search_term=search_term,
    )


def _require_trainer(user_id: int) -> dict | None:
    """Fetch trainer (or admin) info ensuring appropriate role."""
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT id, role, name, last_name, username, email, subscription_type, workouts_completed, form_completed
                  FROM users
                 WHERE id = %s
                """,
                (user_id,),
            )
            trainer = cursor.fetchone()
    if not trainer or trainer.get('role') not in {'trainer', 'admin'}:
        return None
    return trainer


def _user_can_customize_personal_workout(user_row: dict | None) -> bool:
    """Return True when a user can reorder or refresh their personal workouts."""
    if not user_row:
        return False
    role = (user_row.get('role') or '').lower()
    subscription = (user_row.get('subscription_type') or '').lower()
    if role not in {'trainer', 'admin'}:
        return False
    return subscription == 'pro'


def _get_trainer_link_invite(conn, token_id: int) -> dict | None:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
        cursor.execute(
            """
            SELECT tli.id,
                   tli.token_id,
                   tli.trainer_id,
                   tli.client_id,
                   tli.sessions_remaining,
                   tli.accepted_at,
                   t.name AS trainer_name,
                   t.last_name AS trainer_last_name,
                   t.username AS trainer_username,
                   t.email AS trainer_email,
                   c.email AS client_email,
                   c.name AS client_name,
                   c.last_name AS client_last_name,
                   c.username AS client_username
              FROM trainer_link_invites tli
              JOIN users t
                ON tli.trainer_id = t.id
              JOIN users c
                ON tli.client_id = c.id
             WHERE tli.token_id = %s
            """,
            (token_id,)
        )
        return cursor.fetchone()


def _format_display_name(person: dict, fallback: str) -> str:
    parts = [part for part in (person.get('name'), person.get('last_name')) if part]
    if parts:
        return " ".join(parts)
    username = person.get('username')
    if username:
        return username
    return fallback


def _trainer_display_name(trainer: dict) -> str:
    return _format_display_name(trainer, 'your trainer')


def _client_display_name(client: dict) -> str:
    return _format_display_name(client, 'your client')


def _format_sessions_note(sessions_remaining: int | None) -> str | None:
    if sessions_remaining is None:
        return None
    sessions_label = f"{sessions_remaining} session{'s' if sessions_remaining != 1 else ''}"
    return f"They noted you purchased {sessions_label}."


def _build_trainer_invite_note(trainer: dict, sessions_remaining: int | None) -> str:
    trainer_name = _trainer_display_name(trainer)
    base = f"{trainer_name} invited you to train with them on FitBaseAI."
    sessions_note = _format_sessions_note(sessions_remaining)
    if sessions_note:
        base += f" {sessions_note}"
    return base


def trainer_has_premium_generation_access(trainer: dict | None) -> bool:
    """Return True when a trainer/admin can always create premium workouts for clients."""
    if not trainer:
        return False
    role = (trainer.get('role') or '').lower()
    if role == 'admin':
        return True
    if role == 'trainer':
        return (trainer.get('subscription_type') or '').lower() == 'pro'
    return False


@app.route('/client_profile/<int:client_id>')
@login_required
def client_profile(client_id):
    trainer_id = session['user_id']
    trainer = _require_trainer(trainer_id)
    if not trainer:
        flash("Trainer access required.", "danger")
        return redirect(url_for('home'))

    exercise_search_term = (request.args.get('exercise_q') or '').strip()
    exercise_search_results = []

    sessions_completed_count = 0
    session_packages: list[dict] = []
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT id, trainer_id, username, name, last_name, email,
                       fitness_goals, workouts_completed, last_workout_completed,
                       exercise_history, workout_duration, subscription_type, trial_end_date,
                       sessions_remaining, sessions_booked, commitment, additional_notes,
                       injury, injury_details, cardio_restriction
                  FROM users
                 WHERE id = %s
                """,
                (client_id,),
            )
            client = cursor.fetchone()

            if not client:
                flash("Client not found.", "danger")
                return redirect(url_for('trainer_dashboard'))

            if client.get('trainer_id') != trainer_id and trainer.get('role') != 'admin':
                flash("You do not have access to that client.", "danger")
                return redirect(url_for('trainer_dashboard'))

            cursor.execute(
                "SELECT category, workout_data, created_at FROM active_workouts WHERE user_id = %s",
                (client_id,),
            )
            active = cursor.fetchone()

            package_trainer_id = trainer_id
            if trainer.get('role') == 'admin' and client.get('trainer_id'):
                package_trainer_id = client['trainer_id']
            cursor.execute(
                """
                SELECT id,
                       client_id,
                       trainer_id,
                       label,
                       sessions_purchased,
                       price_paid,
                       currency,
                       note,
                       purchased_at
                  FROM client_session_packages
                 WHERE client_id = %s
                   AND trainer_id = %s
                 ORDER BY purchased_at ASC, id ASC
                """,
                (client_id, package_trainer_id),
            )
            session_packages = cursor.fetchall() or []

            if exercise_search_term:
                cursor.execute(
                    """
                    SELECT w.id AS workout_id,
                           w.name,
                           w.description,
                           w.category,
                           w.youtube_id,
                           uep.max_weight,
                           uep.max_reps,
                           uep.notes
                      FROM workouts w
                 LEFT JOIN user_exercise_progress uep
                        ON uep.workout_id = w.id
                       AND uep.user_id = %s
                     WHERE w.name ILIKE %s
                     ORDER BY CASE w.movement_type
                                  WHEN 'compound' THEN 1
                                  WHEN 'accessory' THEN 2
                                  ELSE 3
                              END,
                              w.name
                     LIMIT 25
                    """,
                    (client_id, f"%{exercise_search_term}%"),
                )
                exercise_search_results = cursor.fetchall() or []
    booked_counts, completed_counts = _compute_client_schedule_counts(trainer_id, [client_id], sync_booked=True)
    client['sessions_booked'] = booked_counts.get(client_id, client.get('sessions_booked') or 0)
    sessions_completed_count = completed_counts.get(client_id, sessions_completed_count)

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            session_summary = _resolve_client_session_summary(
                cursor,
                trainer_id,
                client_id,
                client['sessions_booked'],
                sessions_completed_count,
                client.get('sessions_remaining'),
                packages=session_packages,
            )
    session_packages = session_summary.get('packages', session_packages) if session_summary else session_packages
    injury_payload = parse_injury_payload(client.get('injury') if client else None)
    cardio_restriction_flag = bool(client.get('cardio_restriction') if client else False) or injury_payload['cardio']
    injury_regions = injury_payload['regions']
    injury_details = (client.get('injury_details') or '').strip() if client else ''
    injury_status = 'Yes' if (injury_regions or cardio_restriction_flag or injury_details) else 'No'
    injury_excluded_categories = compute_injury_exclusions(injury_regions, cardio_restriction_flag)

    subscription_type = client.get('subscription_type') if client else None
    trial_end_date = client.get('trial_end_date') if client else None
    today = datetime.today().date()
    client_has_premium_access = not (
        subscription_type == 'free'
        or (subscription_type == 'premium' and trial_end_date and today > trial_end_date)
    )
    trainer_can_generate_premium = trainer_has_premium_generation_access(trainer)
    premium_generation_allowed = client_has_premium_access or trainer_can_generate_premium

    active_workout = None
    active_skipped = {}
    if active:
        workout_payload = active.get('workout_data') or {}
        plan = workout_payload.get('plan') if isinstance(workout_payload, dict) else None
        formatted_plan = None
        if plan:
            formatted_plan = format_workout_for_response(active['category'], plan)
        if isinstance(workout_payload, dict):
            skipped_payload = workout_payload.get('skipped')
            if isinstance(skipped_payload, dict):
                active_skipped = skipped_payload

        created_at = active.get('created_at')
        if created_at:
            try:
                created_display = fmt_utc(created_at)
            except Exception:
                created_display = created_at.strftime("%Y-%m-%d %H:%M") if hasattr(created_at, 'strftime') else str(created_at)
        else:
            created_display = None

        active_workout = {
            'category': active.get('category'),
            'duration_minutes': workout_payload.get('duration_minutes') if isinstance(workout_payload, dict) else None,
            'created_at': created_display,
            'plan': formatted_plan,
            'skipped': active_skipped,
            'custom_categories': workout_payload.get('custom_categories') if isinstance(workout_payload, dict) else [],
            'home_equipment': workout_payload.get('home_equipment') if isinstance(workout_payload, dict) else [],
        }

    category_options = list(get_category_groups().keys())
    if CUSTOM_WORKOUT_TOKEN not in category_options:
        category_options.append(CUSTOM_WORKOUT_TOKEN)
    if HOME_WORKOUT_TOKEN not in category_options:
        category_options.append(HOME_WORKOUT_TOKEN)
    active_skip_categories = sorted(set(active_skipped.get('categories') or []))
    active_skip_subcategories = sorted(set(active_skipped.get('subcategories') or []))
    banner_categories = sorted(set(injury_excluded_categories) | set(active_skip_categories))
    banner_subcategories = sorted(set(active_skip_subcategories))
    banner_cardio = cardio_restriction_flag or bool(active_skipped.get('cardio_restriction'))
    injury_region_labels = [region.replace('_', ' ').title() for region in injury_regions]
    skip_token_set = set(banner_categories) | set(banner_subcategories)
    if banner_cardio:
        skip_token_set.add('CARDIO')
    injury_skip_tokens_display = sorted(token.replace('_', ' ').title() for token in skip_token_set)
    injury_regions_json = json.dumps(injury_regions)

    return render_template(
        'client_profile.html',
        trainer=trainer,
        client=client,
        active_workout=active_workout,
        exercise_search_term=exercise_search_term,
        exercise_search_results=exercise_search_results,
        category_options=category_options,
        injury_status=injury_status,
        injury_regions=injury_regions,
        injury_region_labels=injury_region_labels,
        injury_details=injury_details,
        cardio_restriction=cardio_restriction_flag,
        injury_excluded_categories=banner_categories,
        injury_skipped_subcategories=banner_subcategories,
        injury_skip_tokens=injury_skip_tokens_display,
        injury_regions_json=injury_regions_json,
        custom_workout_categories=CUSTOM_WORKOUT_CATEGORIES,
        custom_workout_limits=CUSTOM_WORKOUT_SELECTION_LIMITS,
        custom_workout_token=CUSTOM_WORKOUT_TOKEN,
        home_workout_token=HOME_WORKOUT_TOKEN,
        home_equipment_options=HOME_EQUIPMENT_OPTIONS,
        client_has_premium_access=client_has_premium_access,
        premium_generation_allowed=premium_generation_allowed,
        sessions_booked=client.get('sessions_booked') if client else 0,
        sessions_completed=sessions_completed_count,
        session_summary=session_summary,
        session_packages=session_summary.get('packages', []) if session_summary else [],
        NOTES_PLACEHOLDER=WORKOUT_NOTES_PLACEHOLDER,
    )


def _parse_iso_datetime(value: str, field: str) -> datetime:
    if not value:
        raise ValueError(f"Missing {field}.")
    try:
        cleaned = value.replace('Z', '+00:00')
        parsed = datetime.fromisoformat(cleaned)
    except ValueError as exc:
        raise ValueError(f"Invalid {field}.") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    else:
        parsed = parsed.astimezone(timezone.utc)
    rounded = parsed.replace(second=0, microsecond=0)
    if rounded.minute % 15 != 0:
        raise ValueError("Times must align to 15-minute increments.")
    return rounded


def _validate_time_window(start_dt: datetime, end_dt: datetime) -> None:
    if end_dt <= start_dt:
        raise ValueError("End time must be after start time.")
    duration = end_dt - start_dt
    minutes = int(duration.total_seconds() // 60)
    if minutes % 15 != 0:
        raise ValueError("Duration must be a multiple of 15 minutes.")


def _ensure_aware_datetime(dt: datetime | None) -> datetime | None:
    """Ensure a datetime value carries timezone info."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _timezone_from_payload(payload: dict | None) -> tzinfo:
    """Resolve a timezone from a request payload or fall back to UTC."""
    if not isinstance(payload, dict):
        payload = {}
    tz_name_raw = payload.get('timezone')
    tz_offset_raw = payload.get('timezone_offset_minutes')
    tz_info = None
    if isinstance(tz_name_raw, str):
        tz_name = tz_name_raw.strip()
        if tz_name:
            try:
                tz_info = ZoneInfo(tz_name)
            except Exception:
                tz_info = None
    if tz_info is None and tz_offset_raw not in (None, ''):
        try:
            offset_minutes = int(tz_offset_raw)
            tz_info = timezone(timedelta(minutes=-offset_minutes))
        except Exception:
            tz_info = None
    if tz_info is None:
        tz_info = timezone.utc
    return tz_info


def _format_local_time_label(dt: datetime | None) -> str | None:
    if not dt:
        return None
    label = dt.strftime("%I:%M %p")
    return label.lstrip('0')


def _format_local_time_range(start_dt: datetime | None, end_dt: datetime | None) -> tuple[str | None, str | None, str | None]:
    start_label = _format_local_time_label(start_dt)
    end_label = _format_local_time_label(end_dt)
    if start_label and end_label:
        return start_label, end_label, f"{start_label} – {end_label}"
    if start_label:
        return start_label, None, start_label
    if end_label:
        return None, end_label, end_label
    return None, None, None


def _resolve_local_zone(candidate_tz=None):
    """
    Try to resolve a timezone with DST rules. Prefer:
    1) A supplied zoneinfo key (e.g., America/New_York).
    2) TZ environment variable.
    3) The system local timezone (even if it has no key).
    4) Fall back to the candidate (e.g., UTC) or UTC.
    """
    # If the candidate is a ZoneInfo with a key, keep it.
    if candidate_tz and getattr(candidate_tz, 'key', None):
        return candidate_tz

    # If the candidate is a fixed-offset UTC, we still want a local zone if available.
    tz_env = os.environ.get("TZ")
    if tz_env:
        try:
            return ZoneInfo(tz_env)
        except Exception:
            pass

    system_tz = datetime.now().astimezone().tzinfo
    if system_tz:
        if getattr(system_tz, 'key', None):
            return system_tz
        # Even if there's no key, most system tzinfo objects know DST rules.
        return system_tz

    return candidate_tz or timezone.utc


def _resolve_request_timezone(session_prefix: str) -> tuple[tzinfo, str | None, int | None]:
    """
    Resolve a timezone for agenda-style views using request parameters or prior session hints.
    Returns (tzinfo, timezone_name, offset_minutes_js_style).
    """
    tz_name_key = f'{session_prefix}_timezone'
    tz_offset_key = f'{session_prefix}_tz_offset'

    tz_param = (request.args.get('timezone') or '').strip()
    tz_info = None
    timezone_name = None
    if tz_param:
        try:
            tz_info = ZoneInfo(tz_param)
            timezone_name = tz_param
        except Exception:
            tz_info = None

    if tz_info is not None:
        session[tz_name_key] = timezone_name
    else:
        stored_name = session.get(tz_name_key)
        if stored_name:
            try:
                tz_info = ZoneInfo(stored_name)
                timezone_name = stored_name
            except Exception:
                session.pop(tz_name_key, None)

    tz_offset_minutes = None
    tz_offset_param = request.args.get('tz_offset')
    if tz_offset_param not in (None, ''):
        try:
            tz_offset_minutes = int(tz_offset_param)
            session[tz_offset_key] = tz_offset_minutes
        except (TypeError, ValueError):
            tz_offset_minutes = None
    else:
        stored_offset = session.get(tz_offset_key)
        if isinstance(stored_offset, int):
            tz_offset_minutes = stored_offset

    if tz_info is None and tz_offset_minutes is not None:
        try:
            tz_info = timezone(timedelta(minutes=-tz_offset_minutes))
        except Exception:
            tz_info = None

    if tz_info is None:
        tz_info = datetime.now().astimezone().tzinfo or timezone.utc

    if timezone_name is None:
        timezone_name = getattr(tz_info, 'key', None)

    if tz_offset_minutes is None:
        now_in_zone = datetime.now(timezone.utc).astimezone(tz_info)
        offset_td = now_in_zone.utcoffset()
        if offset_td is not None:
            tz_offset_minutes = int(-offset_td.total_seconds() // 60)

    return tz_info, timezone_name, tz_offset_minutes


def _shift_weekly_preserving_local(
    start_dt: datetime,
    end_dt: datetime,
    week_offset: int,
    tz_hint=None,
) -> tuple[datetime, datetime]:
    """
    Roll a start/end window forward by N weeks while keeping the same local wall time.
    This avoids DST jumps that occur when adding timedeltas in UTC.
    """
    def _ensure_aware(dt: datetime) -> datetime:
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt

    start_dt = _ensure_aware(start_dt)
    end_dt = _ensure_aware(end_dt)

    tz_to_use = _resolve_local_zone(tz_hint or start_dt.tzinfo)

    start_local = start_dt.astimezone(tz_to_use)
    end_local = end_dt.astimezone(tz_to_use)

    target_start_date = start_local.date() + timedelta(weeks=week_offset)
    target_end_date = end_local.date() + timedelta(weeks=week_offset)

    start_clock = time(
        start_local.hour,
        start_local.minute,
        start_local.second,
        start_local.microsecond,
        tzinfo=tz_to_use,
    )
    end_clock = time(
        end_local.hour,
        end_local.minute,
        end_local.second,
        end_local.microsecond,
        tzinfo=tz_to_use,
    )

    shifted_start_local = datetime.combine(target_start_date, start_clock)
    shifted_end_local = datetime.combine(target_end_date, end_clock)

    return shifted_start_local.astimezone(timezone.utc), shifted_end_local.astimezone(timezone.utc)


def _ensure_trainer_client_link(cursor, trainer_id: int, client_id: int, trainer_role: str):
    cursor.execute(
        "SELECT trainer_id, sessions_remaining, sessions_booked FROM users WHERE id = %s",
        (client_id,),
    )
    row = cursor.fetchone()
    if not row:
        return None
    if isinstance(row, dict):
        linked_trainer = row.get('trainer_id')
    else:
        linked_trainer = row[0]
    if linked_trainer == trainer_id or trainer_role == 'admin':
        return row
    return None


def _resolve_back_link(default_url: str) -> str:
    """Return a safe back URL that stays within this application."""
    candidate = request.args.get('back') or request.args.get('return_to') or request.referrer
    if not candidate:
        return default_url
    try:
        parsed = urlparse(candidate)
    except ValueError:
        return default_url
    host_netloc = urlparse(request.host_url).netloc
    if parsed.netloc and parsed.netloc != host_netloc:
        return default_url
    path = parsed.path or ''
    if not path:
        return default_url
    back_url = path
    if parsed.query:
        back_url = f"{back_url}?{parsed.query}"
    if parsed.fragment:
        back_url = f"{back_url}#{parsed.fragment}"
    return back_url


def _trainer_time_off_conflict(cursor, trainer_id: int, start_dt: datetime, end_dt: datetime, exclude_id: int | None = None) -> bool:
    params = [trainer_id, start_dt, end_dt]
    exclude_clause = ""
    if exclude_id is not None:
        exclude_clause = " AND id <> %s"
        params.append(exclude_id)
    cursor.execute(
        f"""
        SELECT 1
          FROM trainer_time_off
         WHERE trainer_id = %s
           AND end_time > %s
           AND start_time < %s
           {exclude_clause}
         LIMIT 1
        """,
        params,
    )
    return cursor.fetchone() is not None


def _schedule_conflicts(cursor, trainer_id: int, client_id: int, start_dt: datetime, end_dt: datetime, exclude_id: int | None = None) -> tuple[bool, str | None]:
    params = [trainer_id, start_dt, end_dt]
    exclude_clause = ""
    if exclude_id is not None:
        exclude_clause = " AND id <> %s"
        params.append(exclude_id)

    cursor.execute(
        f"""
        SELECT 1 FROM trainer_schedule
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
        return True, 'Trainer already has a booking in that window.'

    if _trainer_time_off_conflict(cursor, trainer_id, start_dt, end_dt):
        return True, 'Trainer has personal time blocked during that window.'

    params = [client_id, start_dt, end_dt]
    if exclude_id is not None:
        params.append(exclude_id)

    cursor.execute(
        f"""
        SELECT 1 FROM trainer_schedule
         WHERE client_id = %s
           AND end_time > %s
           AND start_time < %s
           {exclude_clause}
         LIMIT 1
        """,
        params,
    )
    if cursor.fetchone():
        return True, 'Client is already booked for that time.'
    return False, None


def _time_off_conflicts(cursor, trainer_id: int, start_dt: datetime, end_dt: datetime, exclude_id: int | None = None) -> tuple[bool, str | None]:
    if _trainer_time_off_conflict(cursor, trainer_id, start_dt, end_dt, exclude_id=exclude_id):
        return True, 'This personal time block overlaps an existing one.'
    cursor.execute(
        """
        SELECT 1
          FROM trainer_schedule
         WHERE trainer_id = %s
           AND end_time > %s
           AND start_time < %s
           AND is_self_booked = FALSE
        LIMIT 1
        """,
        (trainer_id, start_dt, end_dt),
    )
    if cursor.fetchone():
        return True, 'A client session is already booked during that time.'
    return False, None


def _adjust_sessions_booked(cursor, client_id: int, delta: int) -> None:
    if not delta:
        return
    cursor.execute(
        """
        UPDATE users
           SET sessions_booked = CASE
                 WHEN %s >= 0 THEN COALESCE(sessions_booked, 0) + %s
                 ELSE GREATEST(COALESCE(sessions_booked, 0) + %s, 0)
             END
         WHERE id = %s
        """,
        (delta, delta, delta, client_id),
    )

def _adjust_workouts_completed(cursor, client_id: int, delta: int) -> None:
    if not delta:
        return
    cursor.execute(
        """
        UPDATE users
           SET workouts_completed = CASE
                 WHEN %s >= 0 THEN COALESCE(workouts_completed, 0) + %s
                 ELSE GREATEST(COALESCE(workouts_completed, 0) + %s, 0)
             END
         WHERE id = %s
        """,
        (delta, delta, delta, client_id),
    )


def _fetch_session_packages_by_client(cursor, trainer_id: int, client_ids: list[int]) -> dict[int, list[dict]]:
    """Return a mapping of client_id -> ordered session packages for that trainer."""
    package_map: dict[int, list[dict]] = {}
    if not client_ids:
        return package_map
    cursor.execute(
        """
        SELECT id,
               client_id,
               trainer_id,
               label,
               sessions_purchased,
               price_paid,
               currency,
               note,
               purchased_at
          FROM client_session_packages
         WHERE trainer_id = %s
           AND client_id = ANY(%s)
         ORDER BY purchased_at ASC, id ASC
        """,
        (trainer_id, client_ids),
    )
    for row in cursor.fetchall() or []:
        cid = row['client_id']
        package_map.setdefault(cid, []).append(row)
    return package_map


def _fetch_package_usage_counts(cursor, trainer_id: int, client_ids: list[int]) -> dict[int, dict[str, int]]:
    """Return counts of booked/completed sessions since each client's first package."""
    usage_map: dict[int, dict[str, int]] = {}
    if not client_ids:
        return usage_map
    cursor.execute(
        """
        WITH package_bounds AS (
            SELECT client_id, MIN(purchased_at) AS earliest_purchase
              FROM client_session_packages
             WHERE trainer_id = %s
               AND client_id = ANY(%s)
             GROUP BY client_id
        )
        SELECT pb.client_id,
               COALESCE(SUM(CASE WHEN ts.status = 'booked' THEN 1 ELSE 0 END), 0)::int AS booked_count,
               COALESCE(SUM(CASE WHEN ts.status = 'completed' THEN 1 ELSE 0 END), 0)::int AS completed_count
          FROM package_bounds pb
     LEFT JOIN trainer_schedule ts
            ON ts.client_id = pb.client_id
           AND ts.trainer_id = %s
           AND (
                ts.start_time >= pb.earliest_purchase
                OR ts.created_at >= pb.earliest_purchase
            )
      GROUP BY pb.client_id
        """,
        (trainer_id, client_ids, trainer_id),
    )
    rows = cursor.fetchall() or []
    for row in rows:
        if isinstance(row, dict):
            cid = row.get('client_id')
            booked = row.get('booked_count') or 0
            completed = row.get('completed_count') or 0
        else:
            cid = row[0] if len(row) > 0 else None
            booked = row[1] if len(row) > 1 else 0
            completed = row[2] if len(row) > 2 else 0
        if cid is None:
            continue
        usage_map[int(cid)] = {
            'booked': int(booked or 0),
            'completed': int(completed or 0),
        }
    return usage_map


def _compute_session_package_summary(
    packages: list[dict],
    sessions_booked: int,
    sessions_completed: int,
) -> dict:
    """Given a package list and usage counts, derive totals/remaining sessions."""
    usage_remaining = max(int(sessions_booked or 0) + int(sessions_completed or 0), 0)
    annotated_packages: list[dict] = []
    total_capacity = 0
    sessions_left = 0

    for package in packages:
        purchased_raw = package.get('sessions_purchased')
        try:
            purchased = max(int(purchased_raw or 0), 0)
        except (TypeError, ValueError):
            purchased = 0
        if purchased <= 0:
            annotated = dict(package)
            annotated.update({
                'sessions_used': 0,
                'sessions_left': 0,
                'is_consumed': True,
            })
            annotated_packages.append(annotated)
            continue

        consumed = min(purchased, usage_remaining)
        usage_remaining = max(usage_remaining - purchased, 0)
        remaining = max(purchased - consumed, 0)

        annotated = dict(package)
        annotated['sessions_used'] = consumed
        annotated['sessions_left'] = remaining
        annotated['is_consumed'] = remaining <= 0
        annotated_packages.append(annotated)

        if remaining > 0:
            total_capacity += purchased
            sessions_left += remaining

    return {
        'packages': annotated_packages,
        'sessions_total': total_capacity,
        'sessions_left': sessions_left,
        'using_packages': bool(annotated_packages),
    }


def _resolve_client_session_summary(
    cursor,
    trainer_id: int,
    client_id: int,
    sessions_booked: int | None,
    sessions_completed: int | None,
    fallback_total: int | None,
    *,
    packages: list[dict] | None = None,
) -> dict:
    """Return a normalized session summary for a single client."""
    booked_val = sessions_booked
    completed_val = sessions_completed
    total_val = fallback_total

    if booked_val is None or total_val is None:
        cursor.execute(
            "SELECT sessions_booked, sessions_remaining FROM users WHERE id = %s",
            (client_id,),
        )
        row = cursor.fetchone() or {}
        if booked_val is None:
            booked_val = row.get('sessions_booked') or 0
        if total_val is None:
            total_val = row.get('sessions_remaining')

    if completed_val is None:
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
        row = cursor.fetchone()
        if isinstance(row, dict):
            completed_val = int(row.get('completed_count') or 0)
        else:
            completed_val = int(row[0] if row else 0)

    package_list = packages
    if package_list is None:
        package_map = _fetch_session_packages_by_client(cursor, trainer_id, [client_id])
        package_list = package_map.get(client_id, [])
    if package_list:
        package_trainer_id = trainer_id
        for pkg in package_list:
            pkg_trainer = pkg.get('trainer_id')
            if pkg_trainer:
                package_trainer_id = int(pkg_trainer)
                break
        usage_map = _fetch_package_usage_counts(cursor, package_trainer_id, [client_id])
        usage_counts = usage_map.get(client_id)
        package_booked = int(usage_counts.get('booked', 0)) if usage_counts else int(booked_val or 0)
        package_completed = int(usage_counts.get('completed', 0)) if usage_counts else int(completed_val or 0)
        summary = _compute_session_package_summary(package_list, package_booked, package_completed)
        return summary

    total_sessions = total_val if total_val is None else int(total_val)
    if total_sessions is None:
        sessions_left = None
    else:
        consumed = min(total_sessions, max(int(booked_val or 0) + int(completed_val or 0), 0))
        sessions_left = max(total_sessions - consumed, 0)
    return {
        'sessions_total': total_sessions,
        'sessions_left': sessions_left,
        'using_packages': False,
        'packages': [],
    }
def _compute_client_schedule_counts(trainer_id: int, client_ids: list[int], sync_booked: bool = False) -> tuple[dict[int, int], dict[int, int]]:
    booked_counts: dict[int, int] = {}
    completed_counts: dict[int, int] = {}
    if not client_ids:
        return booked_counts, completed_counts
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT client_id,
                       SUM(CASE WHEN status = 'booked' THEN 1 ELSE 0 END)::int AS booked_count,
                       SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END)::int AS completed_count
                  FROM trainer_schedule
                 WHERE trainer_id = %s
                   AND client_id = ANY(%s)
                 GROUP BY client_id
                """,
                (trainer_id, client_ids),
            )
            for row in cursor.fetchall() or []:
                client_id = row['client_id']
                booked_counts[client_id] = row.get('booked_count') or 0
                completed_counts[client_id] = row.get('completed_count') or 0
        if sync_booked:
            payload = [(booked_counts.get(cid, 0), cid) for cid in client_ids]
            with conn.cursor() as cursor:
                psycopg2.extras.execute_batch(
                    cursor,
                    "UPDATE users SET sessions_booked = %s WHERE id = %s",
                    payload,
                )
            conn.commit()
    return booked_counts, completed_counts


def _serialize_schedule_row(row):
    return {
        'id': row['id'],
        'trainer_id': row['trainer_id'],
        'client_id': row['client_id'],
        'client_name': row.get('client_name'),
        'client_last_name': row.get('client_last_name'),
        'client_username': row.get('client_username'),
        'start_time': row['start_time'].isoformat() if row.get('start_time') else None,
        'end_time': row['end_time'].isoformat() if row.get('end_time') else None,
        'status': row.get('status') or 'booked',
        'type': 'session',
        'note': row.get('note'),
        'session_id': str(row.get('session_id')) if row.get('session_id') else None,
        'session_category': row.get('session_category'),
        'session_completed_at': row['session_completed_at'].isoformat() if row.get('session_completed_at') else None,
        'is_self_booked': bool(row.get('is_self_booked')),
    }


def _serialize_time_off_row(row):
    return {
        'id': row['id'],
        'trainer_id': row['trainer_id'],
        'client_id': None,
        'client_name': None,
        'client_last_name': None,
        'client_username': None,
        'start_time': row['start_time'].isoformat() if row.get('start_time') else None,
        'end_time': row['end_time'].isoformat() if row.get('end_time') else None,
        'status': 'time_off',
        'title': row.get('title') or 'Personal Time',
        'type': 'time_off',
        'note': row.get('note'),
    }


@app.route('/trainer/schedule/data')
@login_required
def trainer_schedule_data():
    trainer_id = session['user_id']
    trainer = _require_trainer(trainer_id)
    if not trainer:
        return jsonify({'success': False, 'error': 'Trainer access required'}), 403

    start_raw = request.args.get('start')
    end_raw = request.args.get('end')
    now_utc = datetime.now(timezone.utc)
    try:
        start_dt = _parse_iso_datetime(start_raw, 'start') if start_raw else (now_utc - timedelta(days=now_utc.weekday()))
        end_dt = _parse_iso_datetime(end_raw, 'end') if end_raw else start_dt + timedelta(days=7)
    except ValueError as exc:
        return jsonify({'success': False, 'error': str(exc)}), 400

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT ts.id, ts.trainer_id, ts.client_id, ts.start_time, ts.end_time, ts.status, ts.note,
                       ts.session_id, ts.session_category, ts.session_completed_at, ts.is_self_booked,
                       c.name AS client_name, c.last_name AS client_last_name, c.username AS client_username
                  FROM trainer_schedule ts
                  JOIN users c ON c.id = ts.client_id
                 WHERE ts.trainer_id = %s
                   AND ts.is_self_booked = FALSE
                   AND ts.start_time < %s
                   AND ts.end_time > %s
                 ORDER BY ts.start_time ASC
                """,
                (trainer_id, end_dt, start_dt),
            )
            session_rows = cursor.fetchall() or []
            cursor.execute(
                """
                SELECT id, trainer_id, start_time, end_time, title, note
                  FROM trainer_time_off
                 WHERE trainer_id = %s
                   AND start_time < %s
                   AND end_time > %s
                 ORDER BY start_time ASC
                """,
                (trainer_id, end_dt, start_dt),
            )
            time_off_rows = cursor.fetchall() or []

    session_events = []
    for row in session_rows:
        serialized = _serialize_schedule_row(row)
        if serialized.get('session_id'):
            serialized['session_url'] = url_for('workout_session_view', session_id=serialized['session_id'])
        session_events.append(serialized)
    time_off_events = [_serialize_time_off_row(row) for row in time_off_rows]
    combined = sorted(session_events + time_off_events, key=lambda ev: ev['start_time'] or '')

    return jsonify({
        'success': True,
        'events': combined,
        'sessions': session_events,
        'time_off': time_off_events,
    })


@app.route('/trainer/schedule/preferences', methods=['GET', 'POST'])
@login_required
def trainer_schedule_preferences():
    trainer_id = session['user_id']
    trainer = _require_trainer(trainer_id)
    if not trainer:
        return jsonify({'success': False, 'error': 'Trainer access required'}), 403

    if request.method == 'GET':
        with get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute(
                    "SELECT view_start, view_end FROM trainer_schedule_preferences WHERE trainer_id = %s",
                    (trainer_id,),
                )
                row = cursor.fetchone()
        if row:
            view_start, view_end = _normalize_calendar_window(
                row.get('view_start'),
                row.get('view_end'),
            )
        else:
            view_start, view_end = DEFAULT_CALENDAR_WINDOW
        return jsonify({'success': True, 'view_start': view_start, 'view_end': view_end})

    data = request.get_json(silent=True) or {}
    try:
        view_start = int(data.get('view_start'))
        view_end = int(data.get('view_end'))
    except (TypeError, ValueError):
        return jsonify({'success': False, 'error': 'Invalid hours provided.'}), 400

    if not (0 <= view_start <= 23 and 1 <= view_end <= 24):
        return jsonify({'success': False, 'error': 'Hours must be between 0 and 24.'}), 400
    if view_end - view_start < MIN_CALENDAR_WINDOW_HOURS:
        return jsonify({'success': False, 'error': f'Viewing window must span at least {MIN_CALENDAR_WINDOW_HOURS} hours.'}), 400

    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO trainer_schedule_preferences (trainer_id, view_start, view_end)
                VALUES (%s, %s, %s)
                ON CONFLICT (trainer_id)
                DO UPDATE SET view_start = EXCLUDED.view_start,
                              view_end = EXCLUDED.view_end,
                              updated_at = CURRENT_TIMESTAMP
                """,
                (trainer_id, view_start, view_end),
            )
            conn.commit()

    return jsonify({'success': True, 'view_start': view_start, 'view_end': view_end})


@app.route('/trainer/schedule/book', methods=['POST'])
@login_required
def trainer_schedule_book():
    trainer_id = session['user_id']
    trainer = _require_trainer(trainer_id)
    if not trainer:
        return jsonify({'success': False, 'error': 'Trainer access required'}), 403

    payload = request.get_json(silent=True) or {}
    client_id = payload.get('client_id')
    duration_minutes = payload.get('duration_minutes') or 60
    note_value = _sanitize_trainer_note_input(payload.get('note'))

    try:
        client_id = int(client_id)
        duration_minutes = int(duration_minutes)
    except (TypeError, ValueError):
        return jsonify({'success': False, 'error': 'Invalid client or duration.'}), 400

    if duration_minutes <= 0:
        return jsonify({'success': False, 'error': 'Duration must be positive.'}), 400

    try:
        start_dt = _parse_iso_datetime(payload.get('start_time'), 'start time')
        end_dt = start_dt + timedelta(minutes=duration_minutes)
        end_raw_override = payload.get('end_time')
        if end_raw_override:
            end_dt = _parse_iso_datetime(end_raw_override, 'end time')
        _validate_time_window(start_dt, end_dt)
    except ValueError as exc:
        return jsonify({'success': False, 'error': str(exc)}), 400

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            link_row = _ensure_trainer_client_link(cursor, trainer_id, client_id, trainer.get('role'))
            if not link_row:
                return jsonify({'success': False, 'error': 'You are not linked with that client.'}), 403

            if isinstance(link_row, dict):
                sessions_remaining = link_row.get('sessions_remaining')
                sessions_booked = link_row.get('sessions_booked') or 0
            else:
                sessions_remaining = link_row[1]
                sessions_booked = link_row[2] or 0

            sessions_booked = int(sessions_booked or 0)
            sessions_remaining_val = None if sessions_remaining is None else int(sessions_remaining)

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
            sessions_completed = int(completed_row.get('completed_count') or 0)

            session_summary = _resolve_client_session_summary(
                cursor,
                trainer_id,
                client_id,
                sessions_booked,
                sessions_completed,
                sessions_remaining_val,
            )
            remaining_quota = session_summary.get('sessions_left')
            if remaining_quota is not None and remaining_quota <= 0:
                flash('That client has no sessions remaining.', 'danger')
                return jsonify({'success': False, 'error': 'Client has no sessions remaining.', 'flash': True}), 400

            conflict, message = _schedule_conflicts(cursor, trainer_id, client_id, start_dt, end_dt)
            if conflict:
                return jsonify({'success': False, 'error': message}), 409

            cursor.execute(
                """
                INSERT INTO trainer_schedule (trainer_id, client_id, start_time, end_time, note)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id
                """,
                (trainer_id, client_id, start_dt, end_dt, note_value),
            )
            new_id_row = cursor.fetchone()
            new_id = new_id_row['id'] if isinstance(new_id_row, dict) else new_id_row[0]

            _adjust_sessions_booked(cursor, client_id, 1)
            conn.commit()

        event_row = None
        counts_row: dict[str, int | None] = {}
        sessions_completed_count = 0
        with get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute(
                    """
                    SELECT ts.id, ts.trainer_id, ts.client_id, ts.start_time, ts.end_time, ts.status, ts.note,
                           c.name AS client_name, c.last_name AS client_last_name, c.username AS client_username
                      FROM trainer_schedule ts
                      JOIN users c ON c.id = ts.client_id
                     WHERE ts.id = %s
                    """,
                    (new_id,),
                )
                event_row = cursor.fetchone()
                cursor.execute(
                    "SELECT sessions_remaining, sessions_booked, workouts_completed FROM users WHERE id = %s",
                    (client_id,),
                )
                counts_row = cursor.fetchone() or {}
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT COUNT(*) FROM trainer_schedule
                     WHERE trainer_id = %s
                       AND client_id = %s
                       AND status = 'completed'
                    """,
                    (trainer_id, client_id),
                )
                result = cursor.fetchone()
                if result:
                    sessions_completed_count = int(result[0] or 0)

        session_summary_after = {}
        with get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                session_summary_after = _resolve_client_session_summary(
                    cursor,
                    trainer_id,
                    client_id,
                    counts_row.get('sessions_booked') or 0,
                    sessions_completed_count,
                    counts_row.get('sessions_remaining'),
                )

    payload = {
        'success': True,
        'event': _serialize_schedule_row(event_row) if event_row else None,
        'sessions_remaining': session_summary_after.get('sessions_total') if session_summary_after else counts_row.get('sessions_remaining'),
        'sessions_left': session_summary_after.get('sessions_left') if session_summary_after else None,
        'sessions_booked': counts_row.get('sessions_booked') if counts_row else None,
        'sessions_completed': sessions_completed_count,
        'workouts_completed': counts_row.get('workouts_completed') if counts_row else None,
    }
    return jsonify(payload)


@app.route('/trainer/schedule/conflicts', methods=['POST'])
@login_required
def trainer_schedule_conflict_check():
    trainer_id = session['user_id']
    trainer = _require_trainer(trainer_id)
    if not trainer:
        return jsonify({'success': False, 'error': 'Trainer access required'}), 403

    data = request.get_json(silent=True) or {}
    start_raw = data.get('start_time')
    end_raw = data.get('end_time')
    exclude_id = data.get('exclude_id')
    client_id = data.get('client_id')

    if not start_raw or not end_raw:
        return jsonify({'success': False, 'error': 'Start and end times are required.'}), 400

    try:
        start_dt = _parse_iso_datetime(start_raw, 'start time')
        end_dt = _parse_iso_datetime(end_raw, 'end time')
        _validate_time_window(start_dt, end_dt)
    except ValueError as exc:
        return jsonify({'success': False, 'error': str(exc)}), 400

    resolved_client_id = None
    if client_id is not None:
        try:
            resolved_client_id = int(client_id)
        except (TypeError, ValueError):
            return jsonify({'success': False, 'error': 'Invalid client id.'}), 400

    if resolved_client_id is None:
        if exclude_id is None:
            return jsonify({'success': False, 'error': 'Client context is required.'}), 400
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT client_id FROM trainer_schedule WHERE id = %s AND trainer_id = %s",
                    (exclude_id, trainer_id),
                )
                row = cursor.fetchone()
                if not row:
                    return jsonify({'success': False, 'error': 'Booking not found.'}), 404
                resolved_client_id = row[0]

    with get_connection() as conn:
        with conn.cursor() as cursor:
            conflict, message = _schedule_conflicts(
                cursor,
                trainer_id,
                resolved_client_id,
                start_dt,
                end_dt,
                exclude_id=exclude_id,
            )

    return jsonify({'success': True, 'conflict': bool(conflict), 'message': message})


@app.route('/trainer/schedule/<int:event_id>', methods=['PATCH', 'DELETE'])
@login_required
def trainer_schedule_modify(event_id):
    trainer_id = session['user_id']
    trainer = _require_trainer(trainer_id)
    if not trainer:
        return jsonify({'success': False, 'error': 'Trainer access required'}), 403

    if request.method == 'DELETE':
        client_id = None
        summary_after_delete: dict | None = None
        counts_after_delete: dict[str, int | None] = {}
        with get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute(
                    "DELETE FROM trainer_schedule WHERE id = %s AND trainer_id = %s RETURNING client_id, status",
                    (event_id, trainer_id),
                )
                row = cursor.fetchone()
                if not row:
                    return jsonify({'success': False, 'error': 'Booking not found.'}), 404
                client_id = row['client_id']
                prior_status = (row.get('status') or 'booked').lower()
                if prior_status == 'booked':
                    _adjust_sessions_booked(cursor, client_id, -1)
                if prior_status == 'completed':
                    _adjust_workouts_completed(cursor, client_id, -1)
                conn.commit()
        if client_id:
            with get_connection() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                    cursor.execute(
                        "SELECT sessions_remaining, sessions_booked, workouts_completed FROM users WHERE id = %s",
                        (client_id,),
                    )
                    counts_after_delete = cursor.fetchone() or {}
                with conn.cursor() as cursor:
                    cursor.execute(
                        "SELECT COUNT(*) FROM trainer_schedule WHERE trainer_id = %s AND client_id = %s AND status = 'completed'",
                        (trainer_id, client_id),
                    )
                    completed_value = cursor.fetchone()[0]
                    counts_after_delete['sessions_completed'] = completed_value
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                    summary_after_delete = _resolve_client_session_summary(
                        cursor,
                        trainer_id,
                        client_id,
                        counts_after_delete.get('sessions_booked') or 0,
                        counts_after_delete.get('sessions_completed', 0) or 0,
                        counts_after_delete.get('sessions_remaining'),
                    )
        return jsonify({
            'success': True,
            'client_id': client_id,
            'sessions_booked': counts_after_delete.get('sessions_booked') if counts_after_delete else None,
            'sessions_completed': counts_after_delete.get('sessions_completed') if counts_after_delete else None,
            'workouts_completed': counts_after_delete.get('workouts_completed') if counts_after_delete else None,
            'sessions_remaining': (summary_after_delete.get('sessions_total') if summary_after_delete else counts_after_delete.get('sessions_remaining') if counts_after_delete else None),
            'sessions_left': summary_after_delete.get('sessions_left') if summary_after_delete else None,
        })

    payload = request.get_json(silent=True) or {}
    start_raw = payload.get('start_time')
    end_raw = payload.get('end_time')
    status_raw = payload.get('status')
    note_provided = 'note' in payload
    note_value = _sanitize_trainer_note_input(payload.get('note')) if note_provided else None

    if start_raw is None and end_raw is None and status_raw is None and not note_provided:
        return jsonify({'success': False, 'error': 'No changes specified.'}), 400

    if (start_raw is None) ^ (end_raw is None):
        return jsonify({'success': False, 'error': 'Both start and end times are required.'}), 400

    start_dt = end_dt = None
    if start_raw is not None and end_raw is not None:
        try:
            start_dt = _parse_iso_datetime(start_raw, 'start time')
            end_dt = _parse_iso_datetime(end_raw, 'end time')
            _validate_time_window(start_dt, end_dt)
        except ValueError as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400

    new_status = None
    if status_raw is not None:
        new_status = str(status_raw).strip().lower()
        allowed_statuses = {'booked', 'completed', 'cancelled'}
        if new_status not in allowed_statuses:
            return jsonify({'success': False, 'error': 'Invalid booking status.'}), 400

    session_logged = False
    session_log_error = None
    session_meta_payload = None

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT id, client_id, status
                  FROM trainer_schedule
                 WHERE id = %s AND trainer_id = %s
                """,
                (event_id, trainer_id),
            )
            row = cursor.fetchone()
            if not row:
                return jsonify({'success': False, 'error': 'Booking not found.'}), 404
            client_id = row['client_id']
            current_status = (row.get('status') or 'booked').lower()
            counts_snapshot: dict[str, int | None] = {}
            if new_status and new_status != current_status and new_status == 'booked':
                cursor.execute(
                    "SELECT sessions_remaining, sessions_booked FROM users WHERE id = %s",
                    (client_id,),
                )
                counts_snapshot = cursor.fetchone() or {}
                remaining = counts_snapshot.get('sessions_remaining')
                booked_now = int((counts_snapshot.get('sessions_booked') or 0))
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
                completed_now = int(completed_row.get('completed_count') or 0)
                counts_snapshot['sessions_completed'] = completed_now
                summary_snapshot = _resolve_client_session_summary(
                    cursor,
                    trainer_id,
                    client_id,
                    booked_now,
                    completed_now,
                    remaining,
                )
                counts_snapshot['sessions_summary'] = summary_snapshot
                remaining_quota = summary_snapshot.get('sessions_left')
                if remaining_quota is not None and remaining_quota <= 0:
                    return jsonify({'success': False, 'error': 'Client has no sessions remaining to mark as booked.'}), 400

        if start_dt and end_dt:
            with conn.cursor() as cursor:
                conflict, message = _schedule_conflicts(cursor, trainer_id, client_id, start_dt, end_dt, exclude_id=event_id)
                if conflict:
                    return jsonify({'success': False, 'error': message}), 409
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE trainer_schedule
                       SET start_time = %s,
                           end_time = %s
                     WHERE id = %s AND trainer_id = %s
                    """,
                    (start_dt, end_dt, event_id, trainer_id),
                )
                if cursor.rowcount == 0:
                    return jsonify({'success': False, 'error': 'Booking not found.'}), 404

        status_delta = 0
        workout_delta = 0
        if new_status and new_status != current_status:
            if current_status != 'completed' and new_status == 'completed':
                comp_success, comp_error, comp_meta = _complete_workout_for_user(client_id)
                if comp_success:
                    session_logged = True
                    session_meta_payload = comp_meta
                else:
                    session_log_error = comp_error
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE trainer_schedule
                       SET status = %s
                     WHERE id = %s AND trainer_id = %s
                    """,
                    (new_status, event_id, trainer_id),
                )
                if cursor.rowcount == 0:
                    return jsonify({'success': False, 'error': 'Booking not found.'}), 404
            if current_status == 'booked' and new_status != 'booked':
                status_delta = -1
            elif current_status != 'booked' and new_status == 'booked':
                status_delta = 1
            if current_status != 'completed' and new_status == 'completed':
                workout_delta = 1
            elif current_status == 'completed' and new_status != 'completed':
                workout_delta = -1
            if status_delta:
                with conn.cursor() as cursor:
                    _adjust_sessions_booked(cursor, client_id, status_delta)
            if current_status != 'completed' and new_status == 'completed':
                workout_delta = 0 if session_logged else 1
            elif current_status == 'completed' and new_status != 'completed':
                workout_delta = -1
        if note_provided:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE trainer_schedule
                       SET note = %s
                     WHERE id = %s AND trainer_id = %s
                    """,
                    (note_value, event_id, trainer_id),
                )
                if cursor.rowcount == 0:
                    return jsonify({'success': False, 'error': 'Booking not found.'}), 404
        if workout_delta:
            with conn.cursor() as cursor:
                _adjust_workouts_completed(cursor, client_id, workout_delta)

        conn.commit()

        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT ts.id, ts.trainer_id, ts.client_id, ts.start_time, ts.end_time, ts.status, ts.note,
                       c.name AS client_name, c.last_name AS client_last_name, c.username AS client_username
                  FROM trainer_schedule ts
                  JOIN users c ON c.id = ts.client_id
                 WHERE ts.id = %s
                """,
                (event_id,),
            )
            refreshed = cursor.fetchone()

    if session_logged and session_meta_payload:
        _attach_session_to_schedule(
            client_id,
            session_meta_payload,
            trainer_id=trainer_id,
            schedule_event_id=event_id,
        )

    counts_response = {}
    session_summary_response = {}
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                "SELECT sessions_remaining, sessions_booked FROM users WHERE id = %s",
                (client_id,),
            )
            counts_response = cursor.fetchone() or {}
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT COUNT(*) FROM trainer_schedule WHERE trainer_id = %s AND client_id = %s AND status = 'completed'",
                (trainer_id, client_id),
            )
            counts_response['sessions_completed'] = cursor.fetchone()[0]
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT workouts_completed FROM users WHERE id = %s",
                (client_id,),
            )
            row_wc = cursor.fetchone()
            counts_response['workouts_completed'] = row_wc[0] if row_wc else None
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            session_summary_response = _resolve_client_session_summary(
                cursor,
                trainer_id,
                client_id,
                counts_response.get('sessions_booked') or 0,
                counts_response.get('sessions_completed', 0) or 0,
                counts_response.get('sessions_remaining'),
            )

    event_payload = _serialize_schedule_row(refreshed) if refreshed else None
    if event_payload and event_payload.get('session_id'):
        event_payload['session_url'] = url_for('workout_session_view', session_id=event_payload['session_id'])

    payload = {
        'success': True,
        'event': event_payload,
        'sessions_remaining': session_summary_response.get('sessions_total') if session_summary_response else counts_response.get('sessions_remaining'),
        'sessions_left': session_summary_response.get('sessions_left') if session_summary_response else None,
        'sessions_booked': counts_response.get('sessions_booked'),
        'sessions_completed': counts_response.get('sessions_completed', 0),
        'workouts_completed': counts_response.get('workouts_completed'),
        'session_logged': session_logged,
    }
    if session_log_error:
        payload['session_log_error'] = session_log_error
    return jsonify(payload)


@app.route('/trainer/schedule/<int:event_id>/delete-weekday', methods=['POST'])
@login_required
def trainer_schedule_delete_weekday(event_id):
    trainer_id = session['user_id']
    trainer = _require_trainer(trainer_id)
    if not trainer:
        return jsonify({'success': False, 'error': 'Trainer access required'}), 403

    payload = request.get_json(silent=True) or {}
    tz_info = _timezone_from_payload(payload)
    rows: list[dict[str, object]] = []

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT id, client_id, status, start_time, end_time
                  FROM trainer_schedule
                 WHERE id = %s AND trainer_id = %s
                """,
                (event_id, trainer_id),
            )
            base_event = cursor.fetchone()
            if not base_event:
                return jsonify({'success': False, 'error': 'Booking not found.'}), 404

            base_status = (base_event.get('status') or 'booked').lower()
            if base_status != 'booked':
                return jsonify({'success': False, 'error': 'Only booked sessions can be deleted in bulk.'}), 400
            client_id = base_event.get('client_id')
            if not client_id:
                return jsonify({'success': False, 'error': 'Session is missing client information.'}), 400
            base_start = _ensure_aware_datetime(base_event.get('start_time'))
            base_end = _ensure_aware_datetime(base_event.get('end_time'))
            if not base_start:
                return jsonify({'success': False, 'error': 'Session start time is missing.'}), 400
            if not base_end:
                return jsonify({'success': False, 'error': 'Session end time is missing.'}), 400
            local_start = base_start.astimezone(tz_info)
            local_end = base_end.astimezone(tz_info)
            target_isodow = local_start.isoweekday()
            weekday_label = local_start.strftime('%A')
            target_start_hour = local_start.hour
            target_start_minute = local_start.minute
            target_end_hour = local_end.hour
            target_end_minute = local_end.minute
            _, _, time_range_label = _format_local_time_range(local_start, local_end)

            cursor.execute(
                """
                SELECT id, start_time, end_time
                  FROM trainer_schedule
                 WHERE trainer_id = %s
                   AND client_id = %s
                   AND status = 'booked'
                """,
                (trainer_id, client_id),
            )
            rows = cursor.fetchall() or []

    matching_ids: list[int] = []
    for row in rows:
        start_dt = _ensure_aware_datetime(row.get('start_time'))
        end_dt = _ensure_aware_datetime(row.get('end_time'))
        if not start_dt or not end_dt:
            continue
        if start_dt < base_start:
            continue
        start_local = start_dt.astimezone(tz_info)
        end_local = end_dt.astimezone(tz_info)
        if (
            start_local.isoweekday() == target_isodow
            and start_local.hour == target_start_hour
            and start_local.minute == target_start_minute
            and end_local.hour == target_end_hour
            and end_local.minute == target_end_minute
        ):
            matching_ids.append(row['id'])

    if not matching_ids:
        return jsonify({'success': False, 'error': 'No booked sessions found for that weekday and time.'}), 404

    deleted_ids: list[int] = []
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                """
                DELETE FROM trainer_schedule
                 WHERE trainer_id = %s
                   AND client_id = %s
                   AND status = 'booked'
                   AND id = ANY(%s)
                RETURNING id
                """,
                (trainer_id, client_id, matching_ids),
            )
            deleted_rows = cursor.fetchall() or []
            deleted_ids = [row['id'] for row in deleted_rows]
            deleted_count = len(deleted_ids)
            if not deleted_count:
                conn.rollback()
                return jsonify({'success': False, 'error': 'No booked sessions were removed.'}), 409

            _adjust_sessions_booked(cursor, client_id, -deleted_count)

        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                "SELECT sessions_remaining, sessions_booked, workouts_completed FROM users WHERE id = %s",
                (client_id,),
            )
            counts_row = cursor.fetchone() or {}

        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT COUNT(*) 
                  FROM trainer_schedule
                 WHERE trainer_id = %s
                   AND client_id = %s
                   AND status = 'completed'
                """,
                (trainer_id, client_id),
            )
            completed_count = cursor.fetchone()[0]

        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            summary_row = _resolve_client_session_summary(
                cursor,
                trainer_id,
                client_id,
                counts_row.get('sessions_booked') or 0,
                completed_count or 0,
                counts_row.get('sessions_remaining'),
            )

        conn.commit()

    response_payload = {
        'success': True,
        'deleted_ids': deleted_ids,
        'deleted_count': len(deleted_ids),
        'day_name': weekday_label,
        'time_range_label': time_range_label,
        'client_id': client_id,
        'sessions_booked': counts_row.get('sessions_booked'),
        'sessions_remaining': summary_row.get('sessions_total') if summary_row else counts_row.get('sessions_remaining'),
        'sessions_left': summary_row.get('sessions_left') if summary_row else None,
        'sessions_completed': completed_count,
        'workouts_completed': counts_row.get('workouts_completed'),
    }
    return jsonify(response_payload)


@app.route('/trainer/time-off', methods=['POST'])
@login_required
def trainer_time_off_create():
    trainer_id = session['user_id']
    trainer = _require_trainer(trainer_id)
    if not trainer:
        return jsonify({'success': False, 'error': 'Trainer access required'}), 403

    payload = request.get_json(silent=True) or {}
    start_raw = payload.get('start_time')
    end_raw = payload.get('end_time')
    title_raw = payload.get('title') or ''
    note_value = _sanitize_trainer_note_input(payload.get('note'))
    title = str(title_raw).strip() or 'Personal Time'
    if len(title) > 120:
        title = title[:120]

    try:
        start_dt = _parse_iso_datetime(start_raw, 'start time')
        end_dt = _parse_iso_datetime(end_raw, 'end time')
        _validate_time_window(start_dt, end_dt)
    except ValueError as exc:
        return jsonify({'success': False, 'error': str(exc)}), 400

    with get_connection() as conn:
        with conn.cursor() as cursor:
            conflict, message = _time_off_conflicts(cursor, trainer_id, start_dt, end_dt)
            if conflict:
                return jsonify({'success': False, 'error': message}), 409
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                """
                INSERT INTO trainer_time_off (trainer_id, start_time, end_time, title, note)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id, trainer_id, start_time, end_time, title, note
                """,
                (trainer_id, start_dt, end_dt, title, note_value),
            )
            row = cursor.fetchone()
            conn.commit()

    block = _serialize_time_off_row(row) if row else None
    return jsonify({'success': True, 'block': block})


@app.route('/trainer/time-off/<int:block_id>', methods=['PATCH', 'DELETE'])
@login_required
def trainer_time_off_modify(block_id):
    trainer_id = session['user_id']
    trainer = _require_trainer(trainer_id)
    if not trainer:
        return jsonify({'success': False, 'error': 'Trainer access required'}), 403

    if request.method == 'DELETE':
        with get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute(
                    "DELETE FROM trainer_time_off WHERE id = %s AND trainer_id = %s RETURNING id",
                    (block_id, trainer_id),
                )
                row = cursor.fetchone()
                if not row:
                    return jsonify({'success': False, 'error': 'Personal time block not found.'}), 404
                conn.commit()
        return jsonify({'success': True})

    payload = request.get_json(silent=True) or {}
    start_raw = payload.get('start_time')
    end_raw = payload.get('end_time')
    title_raw = payload.get('title')
    note_present = 'note' in payload
    note_value = _sanitize_trainer_note_input(payload.get('note')) if note_present else None

    if (start_raw is None) ^ (end_raw is None):
        return jsonify({'success': False, 'error': 'Both start and end times are required.'}), 400

    start_dt = end_dt = None
    if start_raw is not None and end_raw is not None:
        try:
            start_dt = _parse_iso_datetime(start_raw, 'start time')
            end_dt = _parse_iso_datetime(end_raw, 'end time')
            _validate_time_window(start_dt, end_dt)
        except ValueError as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400

    title = None
    if title_raw is not None:
        title = str(title_raw).strip() or 'Personal Time'
        if len(title) > 120:
            title = title[:120]

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT id, trainer_id, start_time, end_time, title, note
                  FROM trainer_time_off
                 WHERE id = %s AND trainer_id = %s
                """,
                (block_id, trainer_id),
            )
            existing = cursor.fetchone()
            if not existing:
                return jsonify({'success': False, 'error': 'Personal time block not found.'}), 404

        if start_dt and end_dt:
            with conn.cursor() as cursor:
                conflict, message = _time_off_conflicts(cursor, trainer_id, start_dt, end_dt, exclude_id=block_id)
                if conflict:
                    return jsonify({'success': False, 'error': message}), 409
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE trainer_time_off
                       SET start_time = %s,
                           end_time = %s
                     WHERE id = %s AND trainer_id = %s
                    """,
                    (start_dt, end_dt, block_id, trainer_id),
                )
                if cursor.rowcount == 0:
                    return jsonify({'success': False, 'error': 'Personal time block not found.'}), 404

        if title is not None:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE trainer_time_off
                       SET title = %s
                     WHERE id = %s AND trainer_id = %s
                    """,
                    (title, block_id, trainer_id),
                )

        if note_present:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE trainer_time_off
                       SET note = %s
                     WHERE id = %s AND trainer_id = %s
                    """,
                    (note_value, block_id, trainer_id),
                )

        conn.commit()

        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT id, trainer_id, start_time, end_time, title, note
                  FROM trainer_time_off
                 WHERE id = %s
                """,
                (block_id,),
            )
            refreshed = cursor.fetchone()

    block = _serialize_time_off_row(refreshed) if refreshed else None
    return jsonify({'success': True, 'block': block})


@app.route('/trainer/time-off/<int:block_id>/delete-weekday', methods=['POST'])
@login_required
def trainer_time_off_delete_weekday(block_id):
    trainer_id = session['user_id']
    trainer = _require_trainer(trainer_id)
    if not trainer:
        return jsonify({'success': False, 'error': 'Trainer access required'}), 403

    payload = request.get_json(silent=True) or {}
    tz_info = _timezone_from_payload(payload)
    rows: list[dict[str, object]] = []

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                "SELECT id, start_time, end_time FROM trainer_time_off WHERE id = %s AND trainer_id = %s",
                (block_id, trainer_id),
            )
            base_block = cursor.fetchone()
            if not base_block:
                return jsonify({'success': False, 'error': 'Personal time block not found.'}), 404
            base_start = _ensure_aware_datetime(base_block.get('start_time'))
            base_end = _ensure_aware_datetime(base_block.get('end_time'))
            if not base_start:
                return jsonify({'success': False, 'error': 'Personal time block start time is missing.'}), 400
            if not base_end:
                return jsonify({'success': False, 'error': 'Personal time block end time is missing.'}), 400
            local_start = base_start.astimezone(tz_info)
            local_end = base_end.astimezone(tz_info)
            target_isodow = local_start.isoweekday()
            weekday_label = local_start.strftime('%A')
            target_start_hour = local_start.hour
            target_start_minute = local_start.minute
            target_end_hour = local_end.hour
            target_end_minute = local_end.minute
            _, _, time_range_label = _format_local_time_range(local_start, local_end)

            cursor.execute(
                "SELECT id, start_time, end_time FROM trainer_time_off WHERE trainer_id = %s",
                (trainer_id,),
            )
            rows = cursor.fetchall() or []

    matching_ids: list[int] = []
    for row in rows:
        start_dt = _ensure_aware_datetime(row.get('start_time'))
        end_dt = _ensure_aware_datetime(row.get('end_time'))
        if not start_dt or not end_dt:
            continue
        if start_dt < base_start:
            continue
        start_local = start_dt.astimezone(tz_info)
        end_local = end_dt.astimezone(tz_info)
        if (
            start_local.isoweekday() == target_isodow
            and start_local.hour == target_start_hour
            and start_local.minute == target_start_minute
            and end_local.hour == target_end_hour
            and end_local.minute == target_end_minute
        ):
            matching_ids.append(row['id'])

    if not matching_ids:
        return jsonify({'success': False, 'error': 'No personal time blocks found for that weekday and time.'}), 404

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                "DELETE FROM trainer_time_off WHERE trainer_id = %s AND id = ANY(%s) RETURNING id",
                (trainer_id, matching_ids),
            )
            deleted_rows = cursor.fetchall() or []
            deleted_ids = [row['id'] for row in deleted_rows]
            deleted_count = len(deleted_ids)
            if not deleted_count:
                conn.rollback()
                return jsonify({'success': False, 'error': 'No personal time blocks were removed.'}), 409
            conn.commit()

    return jsonify({
        'success': True,
        'deleted_ids': deleted_ids,
        'deleted_count': deleted_count,
        'day_name': weekday_label,
        'time_range_label': time_range_label,
    })


@app.route('/trainer/time-off/<int:block_id>/repeat', methods=['POST'])
@login_required
def trainer_time_off_repeat(block_id):
    trainer_id = session['user_id']
    trainer = _require_trainer(trainer_id)
    if not trainer:
        return jsonify({'success': False, 'error': 'Trainer access required'}), 403

    payload = request.get_json(silent=True) or {}
    weeks_raw = payload.get('weeks') or 1
    tz_hint = None
    tz_name = payload.get('timezone')
    if isinstance(tz_name, str) and tz_name.strip():
        try:
            tz_hint = ZoneInfo(tz_name.strip())
        except Exception:
            tz_hint = None
    try:
        weeks_requested = int(weeks_raw)
    except (TypeError, ValueError):
        return jsonify({'success': False, 'error': 'Repeat weeks must be a whole number.'}), 400

    if weeks_requested <= 0:
        return jsonify({'success': False, 'error': 'Repeat weeks must be at least one.'}), 400

    weeks_requested = min(weeks_requested, 52)

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT id, trainer_id, start_time, end_time, title, note
                  FROM trainer_time_off
                 WHERE id = %s AND trainer_id = %s
                """,
                (block_id, trainer_id),
            )
            base_block = cursor.fetchone()

        if not base_block:
            return jsonify({'success': False, 'error': 'Personal time block not found.'}), 404

        base_start: datetime = base_block['start_time']
        base_end: datetime = base_block['end_time']
        block_title = base_block.get('title') or 'Personal Time'
        block_note = base_block.get('note')
        created_rows: list[dict[str, object]] = []
        skipped_conflicts: list[dict[str, object]] = []

        for offset in range(1, weeks_requested + 1):
            new_start, new_end = _shift_weekly_preserving_local(
                base_start,
                base_end,
                offset,
                tz_hint=tz_hint or base_start.tzinfo,
            )
            with conn.cursor() as cursor:
                conflict, message = _time_off_conflicts(cursor, trainer_id, new_start, new_end)
            if conflict:
                skipped_conflicts.append({'week_offset': offset, 'reason': message or 'Conflict detected.'})
                continue
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute(
                    """
                    INSERT INTO trainer_time_off (trainer_id, start_time, end_time, title, note)
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING id, trainer_id, start_time, end_time, title, note
                    """,
                    (trainer_id, new_start, new_end, block_title, block_note),
                )
                row = cursor.fetchone()
                if row:
                    created_rows.append(row)

        conn.commit()

    if not created_rows:
        error_message = 'No additional personal time blocks could be added.'
        if skipped_conflicts:
            error_message = 'All requested repeats conflicted with existing bookings or personal time.'
        return jsonify({'success': False, 'error': error_message, 'conflicts': skipped_conflicts}), 409

    created_blocks = [_serialize_time_off_row(row) for row in created_rows]
    return jsonify({
        'success': True,
        'created_count': len(created_blocks),
        'created_blocks': created_blocks,
        'conflicts': skipped_conflicts,
    })


def _fetch_client_sessions(
    cursor,
    trainer_id: int,
    client_id: int,
    limit: int | None,
    offset: int,
    start_time_from: datetime | None = None,
    start_time_to: datetime | None = None,
):
    base_conditions = ["trainer_id = %s", "client_id = %s"]
    base_params = [trainer_id, client_id]

    cursor.execute(
        f"""
        SELECT COUNT(*) AS total
          FROM trainer_schedule
         WHERE {' AND '.join(base_conditions)}
        """,
        base_params,
    )
    total_all_row = cursor.fetchone() or {}
    total_all = int(total_all_row.get('total') or 0)

    filtered_conditions = list(base_conditions)
    filtered_params = list(base_params)
    if start_time_from:
        filtered_conditions.append("start_time >= %s")
        filtered_params.append(start_time_from)
    if start_time_to:
        filtered_conditions.append("start_time < %s")
        filtered_params.append(start_time_to)
    where_clause = ' AND '.join(filtered_conditions)

    cursor.execute(
        f"""
        SELECT COUNT(*) AS total
          FROM trainer_schedule
         WHERE {where_clause}
        """,
        filtered_params,
    )
    filtered_row = cursor.fetchone() or {}
    filtered_total = int(filtered_row.get('total') or 0)

    query = f"""
        SELECT id, start_time, end_time, status, created_at
          FROM trainer_schedule
         WHERE {where_clause}
         ORDER BY start_time ASC
    """
    data_params = list(filtered_params)
    if limit is not None:
        query += " LIMIT %s OFFSET %s"
        data_params.extend([limit, offset])

    cursor.execute(query, data_params)
    rows = cursor.fetchall() or []
    return total_all, filtered_total, rows


def _fetch_trainer_sessions(
    cursor,
    trainer_id: int,
    limit: int | None,
    offset: int,
    start_time_from: datetime | None = None,
    start_time_to: datetime | None = None,
):
    # Trainers should only see client sessions in this agenda so filter out self bookings
    base_conditions = ["ts.trainer_id = %s", "ts.is_self_booked = FALSE"]
    base_params = [trainer_id]

    cursor.execute(
        f"""
        SELECT COUNT(*) AS total
          FROM trainer_schedule ts
         WHERE {' AND '.join(base_conditions)}
        """,
        base_params,
    )
    total_all_row = cursor.fetchone() or {}
    total_all = int(total_all_row.get('total') or 0)

    filtered_conditions = list(base_conditions)
    filtered_params = list(base_params)
    if start_time_from:
        filtered_conditions.append("start_time >= %s")
        filtered_params.append(start_time_from)
    if start_time_to:
        filtered_conditions.append("start_time < %s")
        filtered_params.append(start_time_to)
    where_clause = ' AND '.join(filtered_conditions)

    cursor.execute(
        f"""
        SELECT COUNT(*) AS total
          FROM trainer_schedule ts
         WHERE {where_clause}
        """,
        filtered_params,
    )
    filtered_row = cursor.fetchone() or {}
    filtered_total = int(filtered_row.get('total') or 0)

    query = f"""
        SELECT ts.id,
               ts.client_id,
               ts.start_time,
               ts.end_time,
               ts.status,
               ts.created_at,
               c.name AS client_name,
               c.last_name AS client_last_name,
               c.username AS client_username
          FROM trainer_schedule ts
          JOIN users c ON c.id = ts.client_id
         WHERE {where_clause}
         ORDER BY ts.start_time ASC
    """

    data_params = list(filtered_params)
    if limit is not None:
        query += " LIMIT %s OFFSET %s"
        data_params.extend([limit, offset])

    cursor.execute(query, data_params)
    rows = cursor.fetchall() or []
    return total_all, filtered_total, rows


def _fetch_trainer_self_sessions(
    cursor,
    user_id: int,
    limit: int | None,
    offset: int,
    start_time_from: datetime | None = None,
    start_time_to: datetime | None = None,
):
    base_conditions = [
        "ts.trainer_id = %s",
        "ts.client_id = %s",
        "ts.is_self_booked = TRUE",
    ]
    base_params = [user_id, user_id]

    cursor.execute(
        f"""
        SELECT COUNT(*) AS total
          FROM trainer_schedule ts
         WHERE {' AND '.join(base_conditions)}
        """,
        base_params,
    )
    total_all_row = cursor.fetchone() or {}
    total_all = int(total_all_row.get('total') or 0)

    filtered_conditions = list(base_conditions)
    filtered_params = list(base_params)
    if start_time_from:
        filtered_conditions.append("ts.start_time >= %s")
        filtered_params.append(start_time_from)
    if start_time_to:
        filtered_conditions.append("ts.start_time < %s")
        filtered_params.append(start_time_to)
    where_clause = ' AND '.join(filtered_conditions)

    cursor.execute(
        f"""
        SELECT COUNT(*) AS total
          FROM trainer_schedule ts
         WHERE {where_clause}
        """,
        filtered_params,
    )
    filtered_row = cursor.fetchone() or {}
    filtered_total = int(filtered_row.get('total') or 0)

    query = f"""
        SELECT ts.id,
               ts.start_time,
               ts.end_time,
               ts.status,
               ts.session_id,
               ts.session_category
          FROM trainer_schedule ts
         WHERE {where_clause}
         ORDER BY ts.start_time ASC
    """
    data_params = list(filtered_params)
    if limit is not None:
        query += " LIMIT %s OFFSET %s"
        data_params.extend([limit, offset])

    cursor.execute(query, data_params)
    rows = cursor.fetchall() or []
    return total_all, filtered_total, rows


@app.route('/trainer/clients/<int:client_id>/agenda', methods=['GET', 'POST'])
@login_required
def trainer_client_agenda(client_id):
    trainer_id = session['user_id']
    trainer = _require_trainer(trainer_id)
    if not trainer:
        flash("Trainer access required.", "danger")
        return redirect(url_for('home'))

    per_page_selections = (10, 30, 50, 100)
    per_page = session.get('client_agenda_per_page')
    if per_page not in per_page_selections:
        per_page = per_page_selections[0]
    per_page_arg = request.args.get('per_page')
    if per_page_arg is not None:
        try:
            per_page_candidate = int(per_page_arg)
        except (TypeError, ValueError):
            per_page_candidate = None
        if per_page_candidate in per_page_selections:
            per_page = per_page_candidate

    if not isinstance(per_page, int) or per_page <= 0:
        per_page = per_page_selections[0]

    if session.get('client_agenda_per_page') != per_page:
        session['client_agenda_per_page'] = per_page

    try:
        page = int(request.args.get('page', 1))
    except (TypeError, ValueError):
        page = 1
    page = max(page, 1)
    offset = (page - 1) * per_page

    allowed_views = {'last_week', 'all', 'today', 'week', 'month', 'custom'}
    selected_view = (request.args.get('view') or 'last_week').lower()
    if selected_view == 'upcoming':
        selected_view = 'last_week'
    if selected_view not in allowed_views:
        selected_view = 'last_week'

    start_date_raw = request.args.get('start_date') or ''
    end_date_raw = request.args.get('end_date') or ''
    if selected_view != 'custom' and (start_date_raw or end_date_raw):
        selected_view = 'custom'

    tz_info, timezone_name, tz_offset_minutes = _resolve_request_timezone('client_agenda')
    now_local = datetime.now(timezone.utc).astimezone(tz_info)
    tz_info = now_local.tzinfo or timezone.utc
    today_local = now_local.date()

    def _start_of_day(target_date: date | None):
        if not target_date:
            return None
        return datetime.combine(target_date, datetime.min.time(), tzinfo=tz_info)

    def _start_of_next_day(target_date: date | None):
        if not target_date:
            return None
        return _start_of_day(target_date + timedelta(days=1))

    def _parse_date(value: str):
        if not value:
            return None
        try:
            return datetime.strptime(value, '%Y-%m-%d').date()
        except (TypeError, ValueError):
            return None

    start_date_value = _parse_date(start_date_raw)
    end_date_value = _parse_date(end_date_raw)
    custom_date_error = False
    custom_error_message = ''
    if start_date_raw and not start_date_value:
        custom_date_error = True
        custom_error_message = 'Enter a valid start date.'
    if end_date_raw and not end_date_value:
        custom_date_error = True
        custom_error_message = 'Enter a valid end date.'
    if start_date_value and end_date_value and start_date_value > end_date_value:
        custom_date_error = True
        custom_error_message = 'Start date must be before the end date.'

    filter_start = None
    filter_end = None
    if selected_view == 'today':
        filter_start = _start_of_day(today_local)
        filter_end = _start_of_next_day(today_local)
    elif selected_view == 'week':
        week_start = today_local - timedelta(days=today_local.weekday())
        filter_start = _start_of_day(week_start)
        filter_end = _start_of_day(week_start + timedelta(days=7))
    elif selected_view == 'month':
        month_start = today_local.replace(day=1)
        if month_start.month == 12:
            next_month = date(month_start.year + 1, 1, 1)
        else:
            next_month = date(month_start.year, month_start.month + 1, 1)
        filter_start = _start_of_day(month_start)
        filter_end = _start_of_day(next_month)
    elif selected_view == 'all':
        filter_start = None
        filter_end = None
    elif selected_view == 'custom':
        if not custom_date_error:
            if start_date_value:
                filter_start = _start_of_day(start_date_value)
            if end_date_value:
                filter_end = _start_of_next_day(end_date_value)
    else:  # upcoming default
        filter_start = now_local  # show sessions from the current moment forward
        filter_end = None

    bulk_action = (request.form.get('bulk_action') or '').strip()
    selected_ids_raw = request.form.getlist('session_id')
    selected_ids: list[int] = []
    for value in selected_ids_raw:
        try:
            selected_ids.append(int(value))
        except (TypeError, ValueError):
            continue

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT id, trainer_id, name, last_name
                  FROM users
                 WHERE id = %s
                """,
                (client_id,),
            )
            client = cursor.fetchone()

        if not client:
            flash("Client not found.", "danger")
            return redirect(url_for('trainer_dashboard'))

        if client.get('trainer_id') != trainer_id and trainer.get('role') != 'admin':
            flash("You do not have access to that client.", "danger")
            return redirect(url_for('trainer_dashboard'))

        action_performed = False
        if request.method == 'POST':
            if not selected_ids:
                flash("Select at least one session before performing a bulk action.", "warning")
            elif bulk_action not in {'set_booked', 'set_completed', 'set_cancelled', 'delete'}:
                flash("Choose a valid bulk action.", "warning")
            else:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                    cursor.execute(
                        """
                        SELECT id, status
                          FROM trainer_schedule
                         WHERE trainer_id = %s
                           AND client_id = %s
                           AND id = ANY(%s)
                        """,
                        (trainer_id, client_id, selected_ids),
                    )
                    events = cursor.fetchall() or []

                if not events:
                    flash("No sessions matched your selection.", "warning")
                else:
                    if bulk_action == 'delete':
                        booked_count = sum(1 for ev in events if (ev.get('status') or 'booked').lower() == 'booked')
                        completed_count = sum(1 for ev in events if (ev.get('status') or 'booked').lower() == 'completed')
                        with conn.cursor() as cursor:
                            cursor.execute(
                                "DELETE FROM trainer_schedule WHERE trainer_id = %s AND client_id = %s AND id = ANY(%s)",
                                (trainer_id, client_id, selected_ids),
                            )
                            if booked_count:
                                _adjust_sessions_booked(cursor, client_id, -booked_count)
                            if completed_count:
                                _adjust_workouts_completed(cursor, client_id, -completed_count)
                            conn.commit()
                        flash(f"Removed {len(events)} session(s).", "success")
                        action_performed = True
                    else:
                        desired_status = {
                            'set_booked': 'booked',
                            'set_completed': 'completed',
                            'set_cancelled': 'cancelled',
                        }[bulk_action]

                        delta = 0
                        workout_delta = 0
                        current_statuses = [(ev['id'], (ev.get('status') or 'booked').lower()) for ev in events]
                        for _, status in current_statuses:
                            if status == desired_status:
                                continue
                            if status == 'booked' and desired_status != 'booked':
                                delta -= 1
                            elif status != 'booked' and desired_status == 'booked':
                                delta += 1
                            if status != 'completed' and desired_status == 'completed':
                                workout_delta += 1
                            elif status == 'completed' and desired_status != 'completed':
                                workout_delta -= 1

                        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                            cursor.execute(
                                "SELECT sessions_remaining, sessions_booked FROM users WHERE id = %s",
                                (client_id,),
                            )
                            counts = cursor.fetchone() or {}

                        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                            session_summary = _resolve_client_session_summary(
                                cursor,
                                trainer_id,
                                client_id,
                                counts.get('sessions_booked') or 0,
                                None,
                                counts.get('sessions_remaining'),
                            )
                        sessions_left = session_summary.get('sessions_left')
                        if delta > 0 and sessions_left is not None and delta > sessions_left:
                            flash("Not enough sessions remaining to mark those bookings as scheduled.", "danger")
                        else:
                            with conn.cursor() as cursor:
                                cursor.execute(
                                    """
                                    UPDATE trainer_schedule
                                       SET status = %s
                                     WHERE trainer_id = %s
                                       AND client_id = %s
                                       AND id = ANY(%s)
                                    """,
                                    (desired_status, trainer_id, client_id, selected_ids),
                                )
                                if delta:
                                    _adjust_sessions_booked(cursor, client_id, delta)
                                if workout_delta:
                                    _adjust_workouts_completed(cursor, client_id, workout_delta)
                                conn.commit()
                            flash(f"Updated {len(events)} session(s) to {desired_status}.", "success")
                            action_performed = True

        if action_performed:
            return redirect(request.url)

        with get_connection() as conn_read:
            with conn_read.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                total_all, total_filtered, sessions = _fetch_client_sessions(
                    cursor,
                    trainer_id,
                    client_id,
                    per_page,
                    offset,
                    filter_start,
                    filter_end,
                )

    total_pages = 1
    if total_filtered and per_page:
        total_pages = (total_filtered + per_page - 1) // per_page
    total_pages = max(total_pages, 1)
    if page > total_pages:
        args = request.args.to_dict(flat=True)
        args['page'] = total_pages
        return redirect(url_for('trainer_client_agenda', client_id=client_id, **args))

    def _format_local_time(dt):
        try:
            localized = dt.astimezone()
            return localized.strftime('%I:%M %p').lstrip('0')
        except Exception:
            return fmt_utc(dt)

    back_target = request.full_path or url_for('trainer_self_agenda_view')
    if back_target.endswith('?'):
        back_target = back_target[:-1]
    agenda_events = []
    for row in sessions:
        start_dt = row.get('start_time')
        end_dt = row.get('end_time')
        start_iso = start_dt.isoformat() if start_dt else None
        end_iso = end_dt.isoformat() if end_dt else None
        date_display = '—'
        start_time_display = '—'
        end_time_display = '—'
        if start_dt:
            try:
                start_local = start_dt.astimezone()
                date_display = start_local.strftime('%b %d, %Y')
                start_time_display = _format_local_time(start_dt)
            except Exception:
                start_time_display = fmt_utc(start_dt)
        if end_dt:
            end_time_display = _format_local_time(end_dt)
        agenda_events.append({
            'id': row['id'],
            'status': (row.get('status') or 'booked').lower(),
            'date': date_display,
            'start_time': start_time_display,
            'end_time': end_time_display,
            'start_time_iso': start_iso,
            'end_time_iso': end_iso,
        })

    page_totals = {
        'booked': 0,
        'cancelled': 0,
        'completed': 0,
    }
    for event in agenda_events:
        status = event.get('status')
        if status in page_totals:
            page_totals[status] += 1

    if total_filtered:
        page_start_index = offset + 1 if agenda_events else 0
        page_end_index = offset + len(agenda_events)
    else:
        page_start_index = 0
        page_end_index = 0

    window_radius = 2
    start_page = max(1, page - window_radius)
    end_page = min(total_pages, page + window_radius)
    if end_page - start_page < window_radius * 2:
        if start_page == 1:
            end_page = min(total_pages, start_page + window_radius * 2)
        elif end_page == total_pages:
            start_page = max(1, end_page - window_radius * 2)
    page_numbers = list(range(start_page, end_page + 1))

    quick_filters = [
        {'key': 'upcoming', 'label': 'Upcoming'},
        {'key': 'today', 'label': 'Today'},
        {'key': 'week', 'label': 'This Week'},
        {'key': 'month', 'label': 'This Month'},
        {'key': 'all', 'label': 'All'},
    ]

    start_date_input = start_date_value.isoformat() if start_date_value else (start_date_raw or '')
    end_date_input = end_date_value.isoformat() if end_date_value else (end_date_raw or '')

    return render_template(
        'client_agenda.html',
        trainer=trainer,
        client=client,
        events=agenda_events,
        total_sessions=total_all,
        filtered_total=total_filtered,
        page=page,
        total_pages=total_pages,
        per_page=per_page,
        per_page_options=per_page_selections,
        page_numbers=page_numbers,
        page_start_index=page_start_index,
        page_end_index=page_end_index,
        selected_view=selected_view,
        start_date_input=start_date_input,
        end_date_input=end_date_input,
        custom_date_error=custom_date_error,
        custom_date_error_message=custom_error_message,
        quick_filters=quick_filters,
        selected_ids=selected_ids if request.method == 'POST' and not action_performed else [],
        bulk_action=bulk_action if request.method == 'POST' else '',
        timezone_name=timezone_name,
        tz_offset_minutes=tz_offset_minutes,
        page_session_totals=page_totals,
    )


@app.route('/client/agenda')
@login_required
def client_self_agenda():
    user_id = session['user_id']
    role = session.get('role')
    if role in {'trainer', 'admin'}:
        return redirect(url_for('trainer_dashboard'))

    per_page_selections = (10, 30, 50, 100)
    per_page = session.get('self_agenda_per_page')
    if per_page not in per_page_selections:
        per_page = per_page_selections[0]
    per_page_arg = request.args.get('per_page')
    if per_page_arg is not None:
        try:
            per_page_candidate = int(per_page_arg)
        except (TypeError, ValueError):
            per_page_candidate = None
        if per_page_candidate in per_page_selections:
            per_page = per_page_candidate
    if not isinstance(per_page, int) or per_page <= 0:
        per_page = per_page_selections[0]
    if session.get('self_agenda_per_page') != per_page:
        session['self_agenda_per_page'] = per_page

    try:
        page = int(request.args.get('page', 1))
    except (TypeError, ValueError):
        page = 1
    page = max(page, 1)
    offset = (page - 1) * per_page

    allowed_views = {'upcoming', 'all', 'today', 'week', 'month', 'custom'}
    selected_view = (request.args.get('view') or 'upcoming').lower()
    if selected_view not in allowed_views:
        selected_view = 'upcoming'

    start_date_raw = request.args.get('start_date') or ''
    end_date_raw = request.args.get('end_date') or ''
    if selected_view != 'custom' and (start_date_raw or end_date_raw):
        selected_view = 'custom'

    tz_info, timezone_name, tz_offset_minutes = _resolve_request_timezone('client_agenda')
    now_local = datetime.now(timezone.utc).astimezone(tz_info)
    tz_info = now_local.tzinfo or timezone.utc
    today_local = now_local.date()

    def _start_of_day(target_date: date | None):
        if not target_date:
            return None
        return datetime.combine(target_date, datetime.min.time(), tzinfo=tz_info)

    def _start_of_next_day(target_date: date | None):
        if not target_date:
            return None
        return _start_of_day(target_date + timedelta(days=1))

    def _parse_date(value: str):
        if not value:
            return None
        try:
            return datetime.strptime(value, '%Y-%m-%d').date()
        except (TypeError, ValueError):
            return None

    start_date_value = _parse_date(start_date_raw)
    end_date_value = _parse_date(end_date_raw)
    custom_date_error = False
    custom_error_message = ''
    if start_date_raw and not start_date_value:
        custom_date_error = True
        custom_error_message = 'Enter a valid start date.'
    if end_date_raw and not end_date_value:
        custom_date_error = True
        custom_error_message = 'Enter a valid end date.'
    if start_date_value and end_date_value and start_date_value > end_date_value:
        custom_date_error = True
        custom_error_message = 'Start date must be before the end date.'

    filter_start = None
    filter_end = None
    if selected_view == 'today':
        filter_start = _start_of_day(today_local)
        filter_end = _start_of_next_day(today_local)
    elif selected_view == 'week':
        week_start = today_local - timedelta(days=today_local.weekday())
        filter_start = _start_of_day(week_start)
        filter_end = _start_of_day(week_start + timedelta(days=7))
    elif selected_view == 'month':
        month_start = today_local.replace(day=1)
        if month_start.month == 12:
            next_month = date(month_start.year + 1, 1, 1)
        else:
            next_month = date(month_start.year, month_start.month + 1, 1)
        filter_start = _start_of_day(month_start)
        filter_end = _start_of_day(next_month)
    elif selected_view == 'all':
        filter_start = None
        filter_end = None
    elif selected_view == 'custom':
        if not custom_date_error:
            if start_date_value:
                filter_start = _start_of_day(start_date_value)
            if end_date_value:
                filter_end = _start_of_next_day(end_date_value)
    else:
        filter_start = now_local  # upcoming view should start from right now
        filter_end = None

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT id, name, last_name
                  FROM users
                 WHERE id = %s
                """,
                (user_id,),
            )
            client = cursor.fetchone()

            if not client:
                flash("User not found.", "danger")
                return redirect(url_for('logout'))

            base_conditions = ["ts.client_id = %s"]
            base_params = [user_id]

            cursor.execute(
                f"""
                SELECT COUNT(*) AS total
                  FROM trainer_schedule ts
                 WHERE {' AND '.join(base_conditions)}
                """,
                base_params,
            )
            total_all_row = cursor.fetchone() or {}
            total_all = int(total_all_row.get('total') or 0)

            filtered_conditions = list(base_conditions)
            filtered_params = list(base_params)
            if filter_start:
                filtered_conditions.append("ts.start_time >= %s")
                filtered_params.append(filter_start)
            if filter_end:
                filtered_conditions.append("ts.start_time < %s")
                filtered_params.append(filter_end)
            where_clause = ' AND '.join(filtered_conditions)

            cursor.execute(
                f"""
                SELECT COUNT(*) AS total
                  FROM trainer_schedule ts
                 WHERE {where_clause}
                """,
                filtered_params,
            )
            filtered_row = cursor.fetchone() or {}
            filtered_total = int(filtered_row.get('total') or 0)

            query = f"""
                SELECT ts.id,
                       ts.start_time,
                       ts.end_time,
                       ts.status
                  FROM trainer_schedule ts
                 WHERE {where_clause}
                 ORDER BY ts.start_time ASC
            """
            data_params = list(filtered_params)
            if per_page:
                query += " LIMIT %s OFFSET %s"
                data_params.extend([per_page, offset])
            cursor.execute(query, data_params)
            sessions = cursor.fetchall() or []

    total_pages = 1
    if filtered_total and per_page:
        total_pages = (filtered_total + per_page - 1) // per_page
    total_pages = max(total_pages, 1)
    if page > total_pages:
        args = request.args.to_dict(flat=True)
        args['page'] = total_pages
        return redirect(url_for('client_self_agenda', **args))

    def _format_local_time(dt):
        try:
            localized = dt.astimezone()
            return localized.strftime('%I:%M %p').lstrip('0')
        except Exception:
            return fmt_utc(dt)

    agenda_events = []
    for row in sessions:
        start_dt = row.get('start_time')
        end_dt = row.get('end_time')
        start_iso = start_dt.isoformat() if start_dt else None
        end_iso = end_dt.isoformat() if end_dt else None
        date_display = '—'
        start_time_display = '—'
        end_time_display = '—'
        if start_dt:
            try:
                start_local = start_dt.astimezone()
                date_display = start_local.strftime('%b %d, %Y')
                start_time_display = _format_local_time(start_dt)
            except Exception:
                start_time_display = fmt_utc(start_dt)
        if end_dt:
            end_time_display = _format_local_time(end_dt)
        agenda_events.append({
            'id': row['id'],
            'status': (row.get('status') or 'booked').lower(),
            'date': date_display,
            'start_time': start_time_display,
            'end_time': end_time_display,
            'start_time_iso': start_iso,
            'end_time_iso': end_iso,
        })

    page_totals = {
        'booked': 0,
        'cancelled': 0,
        'completed': 0,
    }
    for event in agenda_events:
        status = event.get('status')
        if status in page_totals:
            page_totals[status] += 1

    if filtered_total:
        page_start_index = offset + 1 if agenda_events else 0
        page_end_index = offset + len(agenda_events)
    else:
        page_start_index = 0
        page_end_index = 0

    window_radius = 2
    start_page = max(1, page - window_radius)
    end_page = min(total_pages, page + window_radius)
    if end_page - start_page < window_radius * 2:
        if start_page == 1:
            end_page = min(total_pages, start_page + window_radius * 2)
        elif end_page == total_pages:
            start_page = max(1, end_page - window_radius * 2)
    page_numbers = list(range(start_page, end_page + 1))

    quick_filters = [
        {'key': 'upcoming', 'label': 'Upcoming'},
        {'key': 'today', 'label': 'Today'},
        {'key': 'week', 'label': 'This Week'},
        {'key': 'month', 'label': 'This Month'},
        {'key': 'all', 'label': 'All'},
    ]

    start_date_input = start_date_value.isoformat() if start_date_value else (start_date_raw or '')
    end_date_input = end_date_value.isoformat() if end_date_value else (end_date_raw or '')

    return render_template(
        'client_agenda.html',
        trainer=None,
        client=client,
        events=agenda_events,
        total_sessions=total_all,
        filtered_total=filtered_total,
        page=page,
        total_pages=total_pages,
        per_page=per_page,
        per_page_options=per_page_selections,
        page_numbers=page_numbers,
        page_start_index=page_start_index,
        page_end_index=page_end_index,
        selected_view=selected_view,
        start_date_input=start_date_input,
        end_date_input=end_date_input,
        custom_date_error=custom_date_error,
        custom_date_error_message=custom_error_message,
        quick_filters=quick_filters,
        selected_ids=[],
        bulk_action='',
        view_only=True,
        timezone_name=timezone_name,
        tz_offset_minutes=tz_offset_minutes,
        page_session_totals=page_totals,
    )


@app.route('/trainer/agenda', methods=['GET', 'POST'])
@login_required
def trainer_agenda():
    trainer_id = session['user_id']
    trainer = _require_trainer(trainer_id)
    if not trainer:
        flash("Trainer access required.", "danger")
        return redirect(url_for('home'))

    per_page_selections = (10, 30, 50, 100)
    per_page = session.get('trainer_agenda_per_page')
    if per_page not in per_page_selections:
        per_page = per_page_selections[0]
    per_page_arg = request.args.get('per_page')
    if per_page_arg is not None:
        try:
            per_page_candidate = int(per_page_arg)
        except (TypeError, ValueError):
            per_page_candidate = None
        if per_page_candidate in per_page_selections:
            per_page = per_page_candidate
    if not isinstance(per_page, int) or per_page <= 0:
        per_page = per_page_selections[0]
    if session.get('trainer_agenda_per_page') != per_page:
        session['trainer_agenda_per_page'] = per_page

    try:
        page = int(request.args.get('page', 1))
    except (TypeError, ValueError):
        page = 1
    page = max(page, 1)
    offset = (page - 1) * per_page

    allowed_views = {'upcoming', 'all', 'today', 'week', 'month', 'custom'}
    selected_view = (request.args.get('view') or 'upcoming').lower()
    if selected_view not in allowed_views:
        selected_view = 'upcoming'

    start_date_raw = request.args.get('start_date') or ''
    end_date_raw = request.args.get('end_date') or ''
    if selected_view != 'custom' and (start_date_raw or end_date_raw):
        selected_view = 'custom'

    tz_info, timezone_name, tz_offset_minutes = _resolve_request_timezone('trainer_agenda')
    now_local = datetime.now(timezone.utc).astimezone(tz_info)
    tz_info = now_local.tzinfo or timezone.utc
    today_local = now_local.date()

    def _start_of_day(target_date: date | None):
        if not target_date:
            return None
        return datetime.combine(target_date, datetime.min.time(), tzinfo=tz_info)

    def _start_of_next_day(target_date: date | None):
        if not target_date:
            return None
        return _start_of_day(target_date + timedelta(days=1))

    def _parse_date(value: str):
        if not value:
            return None
        try:
            return datetime.strptime(value, '%Y-%m-%d').date()
        except (TypeError, ValueError):
            return None

    start_date_value = _parse_date(start_date_raw)
    end_date_value = _parse_date(end_date_raw)
    custom_date_error = False
    custom_error_message = ''
    if start_date_raw and not start_date_value:
        custom_date_error = True
        custom_error_message = 'Enter a valid start date.'
    if end_date_raw and not end_date_value:
        custom_date_error = True
        custom_error_message = 'Enter a valid end date.'
    if start_date_value and end_date_value and start_date_value > end_date_value:
        custom_date_error = True
        custom_error_message = 'Start date must be before the end date.'

    filter_start = None
    filter_end = None
    if selected_view == 'today':
        filter_start = _start_of_day(today_local)
        filter_end = _start_of_next_day(today_local)
    elif selected_view == 'week':
        week_start = today_local - timedelta(days=today_local.weekday())
        filter_start = _start_of_day(week_start)
        filter_end = _start_of_day(week_start + timedelta(days=7))
    elif selected_view == 'month':
        month_start = today_local.replace(day=1)
        if month_start.month == 12:
            next_month = date(month_start.year + 1, 1, 1)
        else:
            next_month = date(month_start.year, month_start.month + 1, 1)
        filter_start = _start_of_day(month_start)
        filter_end = _start_of_day(next_month)
    elif selected_view == 'all':
        filter_start = None
        filter_end = None
    elif selected_view == 'custom':
        if not custom_date_error:
            if start_date_value:
                filter_start = _start_of_day(start_date_value)
            if end_date_value:
                filter_end = _start_of_next_day(end_date_value)
    else:  # upcoming default
        filter_start = now_local  # show sessions from the current moment forward
        filter_end = None

    bulk_action = (request.form.get('bulk_action') or '').strip()
    selected_ids_raw = request.form.getlist('session_id')
    selected_ids: list[int] = []
    for value in selected_ids_raw:
        try:
            selected_ids.append(int(value))
        except (TypeError, ValueError):
            continue

    action_performed = False

    with get_connection() as conn:
        if request.method == 'POST':
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                if not selected_ids:
                    flash("Select at least one session before performing a bulk action.", "warning")
                elif bulk_action not in {'set_booked', 'set_completed', 'set_cancelled', 'delete'}:
                    flash("Choose a valid bulk action.", "warning")
                else:
                    cursor.execute(
                        """
                        SELECT id, status, client_id
                          FROM trainer_schedule
                         WHERE trainer_id = %s
                           AND id = ANY(%s)
                        """,
                        (trainer_id, selected_ids),
                    )
                    events = cursor.fetchall() or []
                    if not events:
                        flash("No sessions matched your selection.", "warning")
                    else:
                        client_deltas: dict[int, int] = {}
                        client_workout_deltas: dict[int, int] = {}
                        client_ids: set[int] = set()
                        if bulk_action == 'delete':
                            booked_count_map: dict[int, int] = {}
                            completed_count_map: dict[int, int] = {}
                            for ev in events:
                                status = (ev.get('status') or 'booked').lower()
                                cid = ev.get('client_id')
                                if cid is None:
                                    continue
                                client_ids.add(cid)
                                if status == 'booked':
                                    booked_count_map[cid] = booked_count_map.get(cid, 0) + 1
                                elif status == 'completed':
                                    completed_count_map[cid] = completed_count_map.get(cid, 0) + 1
                            cursor.execute(
                                "DELETE FROM trainer_schedule WHERE trainer_id = %s AND id = ANY(%s)",
                                (trainer_id, selected_ids),
                            )
                            for cid, delta in booked_count_map.items():
                                _adjust_sessions_booked(cursor, cid, -delta)
                            for cid, delta in completed_count_map.items():
                                _adjust_workouts_completed(cursor, cid, -delta)
                            conn.commit()
                            flash(f"Removed {len(events)} session(s).", "success")
                            action_performed = True
                        else:
                            desired_status = {
                                'set_booked': 'booked',
                                'set_completed': 'completed',
                                'set_cancelled': 'cancelled',
                            }[bulk_action]

                            for ev in events:
                                cid = ev.get('client_id')
                                if cid is None:
                                    continue
                                client_ids.add(cid)
                                current_status = (ev.get('status') or 'booked').lower()
                                if current_status == desired_status:
                                    continue
                                if current_status == 'booked' and desired_status != 'booked':
                                    client_deltas[cid] = client_deltas.get(cid, 0) - 1
                                elif current_status != 'booked' and desired_status == 'booked':
                                    client_deltas[cid] = client_deltas.get(cid, 0) + 1
                                if current_status != 'completed' and desired_status == 'completed':
                                    client_workout_deltas[cid] = client_workout_deltas.get(cid, 0) + 1
                                elif current_status == 'completed' and desired_status != 'completed':
                                    client_workout_deltas[cid] = client_workout_deltas.get(cid, 0) - 1

                            positive_client_ids = [cid for cid, delta in client_deltas.items() if delta > 0]
                            if positive_client_ids:
                                cursor.execute(
                                    """
                                    SELECT id, sessions_remaining, sessions_booked
                                      FROM users
                                     WHERE id = ANY(%s)
                                    """,
                                    (positive_client_ids,),
                                )
                                counts_map = {row['id']: row for row in cursor.fetchall() or []}
                                over_limit_clients = []
                                for cid in positive_client_ids:
                                    row = counts_map.get(cid) or {}
                                    remaining = row.get('sessions_remaining')
                                    booked_now = row.get('sessions_booked') or 0
                                    delta = client_deltas.get(cid, 0)
                                    if remaining is not None and booked_now + delta > remaining:
                                        over_limit_clients.append(cid)
                                if over_limit_clients:
                                    flash("Not enough sessions remaining to mark those bookings as scheduled.", "danger")
                                else:
                                    cursor.execute(
                                        """
                                        UPDATE trainer_schedule
                                           SET status = %s
                                         WHERE trainer_id = %s
                                           AND id = ANY(%s)
                                        """,
                                        (desired_status, trainer_id, selected_ids),
                                    )
                                    for cid, delta in client_deltas.items():
                                        if delta:
                                            _adjust_sessions_booked(cursor, cid, delta)
                                    for cid, w_delta in client_workout_deltas.items():
                                        if w_delta:
                                            _adjust_workouts_completed(cursor, cid, w_delta)
                                    conn.commit()
                                    flash(f"Updated {len(events)} session(s) to {desired_status}.", "success")
                                    action_performed = True
                            else:
                                cursor.execute(
                                    """
                                    UPDATE trainer_schedule
                                       SET status = %s
                                     WHERE trainer_id = %s
                                       AND id = ANY(%s)
                                    """,
                                    (desired_status, trainer_id, selected_ids),
                                )
                                for cid, delta in client_deltas.items():
                                    if delta:
                                        _adjust_sessions_booked(cursor, cid, delta)
                                for cid, w_delta in client_workout_deltas.items():
                                    if w_delta:
                                        _adjust_workouts_completed(cursor, cid, w_delta)
                                conn.commit()
                                flash(f"Updated {len(events)} session(s) to {desired_status}.", "success")
                                action_performed = True

        if action_performed:
            return redirect(request.url)

        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            total_all, total_filtered, sessions = _fetch_trainer_sessions(
                cursor,
                trainer_id,
                per_page,
                offset,
                filter_start,
                filter_end,
            )

    total_pages = 1
    if total_filtered and per_page:
        total_pages = (total_filtered + per_page - 1) // per_page
    total_pages = max(total_pages, 1)
    if page > total_pages:
        args = request.args.to_dict(flat=True)
        args['page'] = total_pages
        return redirect(url_for('trainer_agenda', **args))

    def _format_local_time(dt):
        try:
            localized = dt.astimezone()
            return localized.strftime('%I:%M %p').lstrip('0')
        except Exception:
            return fmt_utc(dt)

    agenda_events = []
    for row in sessions:
        start_dt = row.get('start_time')
        end_dt = row.get('end_time')
        start_iso = start_dt.isoformat() if start_dt else None
        end_iso = end_dt.isoformat() if end_dt else None
        date_display = '—'
        start_time_display = '—'
        end_time_display = '—'
        if start_dt:
            try:
                start_local = start_dt.astimezone()
                date_display = start_local.strftime('%b %d, %Y')
                start_time_display = _format_local_time(start_dt)
            except Exception:
                start_time_display = fmt_utc(start_dt)
        if end_dt:
            end_time_display = _format_local_time(end_dt)
        agenda_events.append({
            'id': row['id'],
            'client_id': row.get('client_id'),
            'client_name': row.get('client_name'),
            'client_last_name': row.get('client_last_name'),
            'client_username': row.get('client_username'),
            'status': (row.get('status') or 'booked').lower(),
            'date': date_display,
            'start_time': start_time_display,
            'end_time': end_time_display,
            'start_time_iso': start_iso,
            'end_time_iso': end_iso,
        })

    page_totals = {
        'booked': 0,
        'cancelled': 0,
        'completed': 0,
    }
    for event in agenda_events:
        status = event.get('status')
        if status in page_totals:
            page_totals[status] += 1

    if total_filtered:
        page_start_index = offset + 1 if agenda_events else 0
        page_end_index = offset + len(agenda_events)
    else:
        page_start_index = 0
        page_end_index = 0

    window_radius = 2
    start_page = max(1, page - window_radius)
    end_page = min(total_pages, page + window_radius)
    if end_page - start_page < window_radius * 2:
        if start_page == 1:
            end_page = min(total_pages, start_page + window_radius * 2)
        elif end_page == total_pages:
            start_page = max(1, end_page - window_radius * 2)
    page_numbers = list(range(start_page, end_page + 1))

    quick_filters = [
        {'key': 'upcoming', 'label': 'Upcoming'},
        {'key': 'today', 'label': 'Today'},
        {'key': 'week', 'label': 'This Week'},
        {'key': 'month', 'label': 'This Month'},
        {'key': 'all', 'label': 'All'},
    ]

    start_date_input = start_date_value.isoformat() if start_date_value else (start_date_raw or '')
    end_date_input = end_date_value.isoformat() if end_date_value else (end_date_raw or '')

    return render_template(
        'trainer_agenda.html',
        trainer=trainer,
        events=agenda_events,
        total_sessions=total_all,
        filtered_total=total_filtered,
        page=page,
        total_pages=total_pages,
        per_page=per_page,
        per_page_options=per_page_selections,
        page_numbers=page_numbers,
        page_start_index=page_start_index,
        page_end_index=page_end_index,
        selected_view=selected_view,
        start_date_input=start_date_input,
        end_date_input=end_date_input,
        custom_date_error=custom_date_error,
        custom_date_error_message=custom_error_message,
        quick_filters=quick_filters,
        selected_ids=selected_ids if request.method == 'POST' and not action_performed else [],
        bulk_action=bulk_action if request.method == 'POST' else '',
        timezone_name=timezone_name,
        tz_offset_minutes=tz_offset_minutes,
        page_session_totals=page_totals,
    )


@app.route('/trainer/schedule/<int:event_id>/repeat', methods=['POST'])
@login_required
def trainer_schedule_repeat(event_id):
    trainer_id = session['user_id']
    trainer = _require_trainer(trainer_id)
    if not trainer:
        return jsonify({'success': False, 'error': 'Trainer access required'}), 403

    payload = request.get_json(silent=True) or {}
    weeks_raw = payload.get('weeks') or 1
    tz_hint = None
    tz_name = payload.get('timezone')
    if isinstance(tz_name, str) and tz_name.strip():
        try:
            tz_hint = ZoneInfo(tz_name.strip())
        except Exception:
            tz_hint = None
    try:
        weeks_requested = int(weeks_raw)
    except (TypeError, ValueError):
        return jsonify({'success': False, 'error': 'Repeat weeks must be a whole number.'}), 400

    if weeks_requested <= 0:
        return jsonify({'success': False, 'error': 'Repeat weeks must be at least one.'}), 400

    weeks_requested = min(weeks_requested, 52)

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT id, client_id, start_time, end_time, status, note
                  FROM trainer_schedule
                 WHERE id = %s AND trainer_id = %s
                """,
                (event_id, trainer_id),
            )
            base_event = cursor.fetchone()

        if not base_event:
            return jsonify({'success': False, 'error': 'Booking not found.'}), 404

        client_id = base_event['client_id']
        base_status = (base_event.get('status') or 'booked').lower()
        if base_status == 'cancelled':
            return jsonify({'success': False, 'error': 'Cannot repeat a cancelled booking.'}), 400

        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            link_row = _ensure_trainer_client_link(cursor, trainer_id, client_id, trainer.get('role'))
            if not link_row:
                return jsonify({'success': False, 'error': 'You are not linked with that client.'}), 403
            sessions_remaining = link_row.get('sessions_remaining') if isinstance(link_row, dict) else link_row[1]
            sessions_booked = link_row.get('sessions_booked') if isinstance(link_row, dict) else link_row[2]
            if sessions_booked is None:
                sessions_booked = 0
            sessions_booked = int(sessions_booked or 0)

        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT COUNT(*) 
                  FROM trainer_schedule
                 WHERE trainer_id = %s
                   AND client_id = %s
                   AND status = 'completed'
                """,
                (trainer_id, client_id),
            )
            completed_row = cursor.fetchone()
            sessions_completed = int(completed_row[0] or 0) if completed_row else 0

        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            session_summary = _resolve_client_session_summary(
                cursor,
                trainer_id,
                client_id,
                sessions_booked,
                sessions_completed,
                sessions_remaining,
            )

        remaining_quota = session_summary.get('sessions_left')
        if remaining_quota is not None and remaining_quota <= 0:
            return jsonify({'success': False, 'error': 'This client has no sessions remaining to repeat.'}), 400
        quota = remaining_quota

        base_start: datetime = base_event['start_time']
        base_end: datetime = base_event['end_time']
        base_note = base_event.get('note')
        created_ids: list[int] = []
        skipped_conflicts: list[dict[str, str | int]] = []

        for offset in range(1, weeks_requested + 1):
            if quota is not None and len(created_ids) >= quota:
                break
            new_start, new_end = _shift_weekly_preserving_local(
                base_start,
                base_end,
                offset,
                tz_hint=tz_hint or base_start.tzinfo,
            )

            with conn.cursor() as cursor:
                conflict, message = _schedule_conflicts(cursor, trainer_id, client_id, new_start, new_end)
            if conflict:
                skipped_conflicts.append({'week_offset': offset, 'reason': message or 'Conflict detected.'})
                continue

            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute(
                    """
                    INSERT INTO trainer_schedule (trainer_id, client_id, start_time, end_time, note)
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (trainer_id, client_id, new_start, new_end, base_note),
                )
                inserted = cursor.fetchone()
                new_id = inserted['id'] if isinstance(inserted, dict) else inserted[0]
                created_ids.append(new_id)

            with conn.cursor() as cursor:
                _adjust_sessions_booked(cursor, client_id, 1)

        if not created_ids:
            conn.commit()
            error_message = 'No additional sessions could be booked.'
            if skipped_conflicts:
                error_message = 'All requested repeats conflicted with existing bookings.'
            elif quota is not None and quota <= 0:
                error_message = 'Client has no remaining sessions to repeat.'
            return jsonify({'success': False, 'error': error_message, 'conflicts': skipped_conflicts}), 409

        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                "SELECT sessions_remaining, sessions_booked, workouts_completed FROM users WHERE id = %s",
                (client_id,),
            )
            counts = cursor.fetchone() or {}

        created_events = []
        for new_id in created_ids:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute(
                    """
                    SELECT ts.id, ts.trainer_id, ts.client_id, ts.start_time, ts.end_time, ts.status, ts.note,
                           c.name AS client_name, c.last_name AS client_last_name, c.username AS client_username
                      FROM trainer_schedule ts
                      JOIN users c ON c.id = ts.client_id
                     WHERE ts.id = %s
                    """,
                    (new_id,),
                )
                row = cursor.fetchone()
                if row:
                    created_events.append(_serialize_schedule_row(row))

        conn.commit()

    remaining_quota = None
    if quota is not None:
        remaining_quota = max(quota - len(created_ids), 0)

    with get_connection() as conn_fetch:
        with conn_fetch.cursor() as cursor:
            cursor.execute(
                "SELECT COUNT(*) FROM trainer_schedule WHERE trainer_id = %s AND client_id = %s AND status = 'completed'",
                (trainer_id, client_id),
            )
            sessions_completed_count = cursor.fetchone()[0]

        with conn_fetch.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            summary_after_repeat = _resolve_client_session_summary(
                cursor,
                trainer_id,
                client_id,
                counts.get('sessions_booked') if isinstance(counts, dict) else None,
                sessions_completed_count,
                counts.get('sessions_remaining') if isinstance(counts, dict) else None,
            )

    response_payload = {
        'success': True,
        'created_count': len(created_events),
        'created_events': created_events,
        'conflicts': skipped_conflicts,
        'remaining_quota': remaining_quota,
        'sessions_booked': counts.get('sessions_booked'),
        'sessions_remaining': summary_after_repeat.get('sessions_total') if summary_after_repeat else counts.get('sessions_remaining'),
        'sessions_left': summary_after_repeat.get('sessions_left') if summary_after_repeat else None,
        'sessions_completed': sessions_completed_count,
        'workouts_completed': counts.get('workouts_completed'),
    }
    return jsonify(response_payload)


@app.route('/client/schedule/data')
@login_required
def client_schedule_data():
    user_id = session['user_id']
    role = session.get('role')
    if role not in {'user', 'trainer', 'admin'}:
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    start_raw = request.args.get('start')
    end_raw = request.args.get('end')
    now_utc = datetime.now(timezone.utc)
    try:
        start_dt = _parse_iso_datetime(start_raw, 'start') if start_raw else (now_utc - timedelta(days=now_utc.weekday()))
        end_dt = _parse_iso_datetime(end_raw, 'end') if end_raw else start_dt + timedelta(days=7)
    except ValueError as exc:
        return jsonify({'success': False, 'error': str(exc)}), 400

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                "SELECT subscription_type FROM users WHERE id = %s",
                (user_id,),
            )
            user_row = cursor.fetchone()
            if not user_row or (user_row.get('subscription_type') or '').strip().lower() == 'free':
                return jsonify({'success': False, 'error': SCHEDULE_ACCESS_REQUIRED_MESSAGE}), 403

        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT ts.id, ts.trainer_id, ts.client_id, ts.start_time, ts.end_time, ts.status, ts.note,
                       ts.session_id, ts.session_category, ts.session_completed_at, ts.is_self_booked,
                       t.name AS trainer_name, t.last_name AS trainer_last_name,
                       t.username AS trainer_username
                  FROM trainer_schedule ts
                  JOIN users t ON t.id = ts.trainer_id
                 WHERE ts.client_id = %s
                   AND ts.start_time < %s
                   AND ts.end_time > %s
                 ORDER BY ts.start_time
                """,
                (user_id, end_dt, start_dt),
            )
            rows = cursor.fetchall() or []

    events = []
    for row in rows:
        event = _serialize_schedule_row(row)
        event.pop('note', None)
        if event.get('is_self_booked'):
            event['trainer_name'] = None
            event['trainer_last_name'] = None
            event['trainer_username'] = None
        else:
            event['trainer_name'] = row.get('trainer_name')
            event['trainer_last_name'] = row.get('trainer_last_name')
            event['trainer_username'] = row.get('trainer_username')
        if event.get('session_id'):
            event['session_url'] = url_for('workout_session_view', session_id=event['session_id'])
        events.append(event)

    return jsonify({'success': True, 'events': events})


@app.route('/client/schedule/preferences', methods=['GET', 'POST'])
@login_required
def client_schedule_preferences():
    user_id = session['user_id']
    role = session.get('role')
    if role not in {'user', 'trainer', 'admin'}:
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    if request.method == 'GET':
        source_start = DEFAULT_CALENDAR_WINDOW[0]
        source_end = DEFAULT_CALENDAR_WINDOW[1]
        with get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute(
                    "SELECT trainer_id, subscription_type FROM users WHERE id = %s",
                    (user_id,),
                )
                row = cursor.fetchone()
                if not row or (row.get('subscription_type') or '').strip().lower() == 'free':
                    return jsonify({'success': False, 'error': SCHEDULE_ACCESS_REQUIRED_MESSAGE}), 403
                trainer_id = row.get('trainer_id')

                cursor.execute(
                    "SELECT view_start, view_end, follow_trainer FROM client_schedule_preferences WHERE client_id = %s",
                    (user_id,),
                )
                pref_row = cursor.fetchone() or {}

                if pref_row.get('follow_trainer', True) and trainer_id:
                    cursor.execute(
                        "SELECT view_start, view_end FROM trainer_schedule_preferences WHERE trainer_id = %s",
                        (trainer_id,),
                    )
                    trainer_pref = cursor.fetchone() or {}
                    source_start = trainer_pref.get('view_start', source_start)
                    source_end = trainer_pref.get('view_end', source_end)
                else:
                    source_start = pref_row.get('view_start', source_start)
                    source_end = pref_row.get('view_end', source_end)

        view_start, view_end = _normalize_calendar_window(source_start, source_end)

        return jsonify({
            'success': True,
            'view_start': view_start,
            'view_end': view_end,
            'follow_trainer': pref_row.get('follow_trainer', True)
        })

    data = request.get_json(silent=True) or {}
    follow_trainer = bool(data.get('follow_trainer', False))
    try:
        view_start = int(data.get('view_start', 5))
        view_end = int(data.get('view_end', 21))
    except (TypeError, ValueError):
        return jsonify({'success': False, 'error': 'Invalid hours provided.'}), 400

    if not (0 <= view_start <= 23 and 1 <= view_end <= 24):
        return jsonify({'success': False, 'error': 'Hours must be between 0 and 24.'}), 400
    if view_end - view_start < MIN_CALENDAR_WINDOW_HOURS:
        return jsonify({'success': False, 'error': f'Viewing window must span at least {MIN_CALENDAR_WINDOW_HOURS} hours.'}), 400

    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT subscription_type FROM users WHERE id = %s",
                (user_id,),
            )
            subscription_row = cursor.fetchone()
            if not subscription_row or (subscription_row[0] or '').strip().lower() == 'free':
                return jsonify({'success': False, 'error': SCHEDULE_ACCESS_REQUIRED_MESSAGE}), 403

        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO client_schedule_preferences (client_id, view_start, view_end, follow_trainer)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (client_id)
                DO UPDATE SET view_start = EXCLUDED.view_start,
                              view_end = EXCLUDED.view_end,
                              follow_trainer = EXCLUDED.follow_trainer,
                              updated_at = CURRENT_TIMESTAMP
                """,
                (user_id, view_start, view_end, follow_trainer),
            )
            conn.commit()

    return jsonify({'success': True, 'view_start': view_start, 'view_end': view_end, 'follow_trainer': follow_trainer})


@app.route('/schedule')
@login_required
def client_schedule_view():
    user_id = session['user_id']
    check_and_downgrade_trial(user_id)
    check_subscription_expiry(user_id)
    role = session.get('role')

    if role == 'trainer' or role == 'admin':
        return redirect(url_for('trainer_dashboard'))

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                "SELECT trainer_id, subscription_type FROM users WHERE id = %s",
                (user_id,),
            )
            row = cursor.fetchone()
            if not row or (row.get('subscription_type') or '').strip().lower() == 'free':
                flash(SCHEDULE_ACCESS_REQUIRED_MESSAGE, 'warning')
                return redirect(url_for('plan_options'))

            trainer_id = row.get('trainer_id')

            trainer_info = None
            if trainer_id:
                cursor.execute(
                    "SELECT name, last_name, username FROM users WHERE id = %s",
                    (trainer_id,),
                )
                trainer_info = cursor.fetchone()

    return render_template('schedule.html', trainer_info=trainer_info)


@app.route('/trainer/my_workouts')
@login_required
def trainer_self_schedule_view():
    role = (session.get('role') or '').strip().lower()
    if role not in {'trainer', 'admin'}:
        flash("Trainer access required.", "danger")
        return redirect(url_for('home'))
    return render_template('trainer_self_schedule.html')


@app.route('/trainer/my_workouts/agenda')
@login_required
def trainer_self_agenda_view():
    user_id = session['user_id']
    role = (session.get('role') or '').strip().lower()
    if role not in {'trainer', 'admin'}:
        flash("Trainer access required.", "danger")
        return redirect(url_for('home'))

    per_page_selections = (10, 30, 50, 100)
    per_page = session.get('trainer_self_agenda_per_page')
    if per_page not in per_page_selections:
        per_page = per_page_selections[0]
    per_page_arg = request.args.get('per_page')
    if per_page_arg is not None:
        try:
            per_page_candidate = int(per_page_arg)
        except (TypeError, ValueError):
            per_page_candidate = None
        if per_page_candidate in per_page_selections:
            per_page = per_page_candidate
    if not isinstance(per_page, int) or per_page <= 0:
        per_page = per_page_selections[0]
    if session.get('trainer_self_agenda_per_page') != per_page:
        session['trainer_self_agenda_per_page'] = per_page

    try:
        page = int(request.args.get('page', 1))
    except (TypeError, ValueError):
        page = 1
    page = max(page, 1)
    offset = (page - 1) * per_page

    allowed_views = {'last_7_days', 'all', 'today', 'week', 'month', 'custom'}
    selected_view = (request.args.get('view') or 'last_7_days').lower()
    if selected_view in {'last_week', 'upcoming'}:
        selected_view = 'last_7_days'
    if selected_view not in allowed_views:
        selected_view = 'last_7_days'

    start_date_raw = request.args.get('start_date') or ''
    end_date_raw = request.args.get('end_date') or ''
    if selected_view != 'custom' and (start_date_raw or end_date_raw):
        selected_view = 'custom'

    tz_info, timezone_name, tz_offset_minutes = _resolve_request_timezone('trainer_self_agenda')
    now_local = datetime.now(timezone.utc).astimezone(tz_info)
    tz_info = now_local.tzinfo or timezone.utc
    today_local = now_local.date()

    def _start_of_day(target_date: date | None):
        if not target_date:
            return None
        return datetime.combine(target_date, datetime.min.time(), tzinfo=tz_info)

    def _start_of_next_day(target_date: date | None):
        if not target_date:
            return None
        return _start_of_day(target_date + timedelta(days=1))

    def _parse_date(value: str):
        if not value:
            return None
        try:
            return datetime.strptime(value, '%Y-%m-%d').date()
        except (TypeError, ValueError):
            return None

    start_date_value = _parse_date(start_date_raw)
    end_date_value = _parse_date(end_date_raw)
    custom_date_error = False
    custom_error_message = ''
    if start_date_raw and not start_date_value:
        custom_date_error = True
        custom_error_message = 'Enter a valid start date.'
    if end_date_raw and not end_date_value:
        custom_date_error = True
        custom_error_message = 'Enter a valid end date.'
    if start_date_value and end_date_value and start_date_value > end_date_value:
        custom_date_error = True
        custom_error_message = 'Start date must be before the end date.'

    filter_start = None
    filter_end = None
    if selected_view == 'last_7_days':
        seven_days_ago = today_local - timedelta(days=7)
        filter_start = _start_of_day(seven_days_ago)
        filter_end = _start_of_day(today_local)
    elif selected_view == 'today':
        filter_start = _start_of_day(today_local)
        filter_end = _start_of_next_day(today_local)
    elif selected_view == 'week':
        week_start = today_local - timedelta(days=today_local.weekday())
        filter_start = _start_of_day(week_start)
        filter_end = _start_of_day(week_start + timedelta(days=7))
    elif selected_view == 'month':
        month_start = today_local.replace(day=1)
        if month_start.month == 12:
            next_month = date(month_start.year + 1, 1, 1)
        else:
            next_month = date(month_start.year, month_start.month + 1, 1)
        filter_start = _start_of_day(month_start)
        filter_end = _start_of_day(next_month)
    elif selected_view == 'all':
        filter_start = None
        filter_end = None
    elif selected_view == 'custom':
        if not custom_date_error:
            if start_date_value:
                filter_start = _start_of_day(start_date_value)
            if end_date_value:
                filter_end = _start_of_next_day(end_date_value)
    else:  # fallback to last 7 days
        seven_days_ago = today_local - timedelta(days=7)
        filter_start = _start_of_day(seven_days_ago)
        filter_end = _start_of_day(today_local)

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            total_all, total_filtered, sessions = _fetch_trainer_self_sessions(
                cursor,
                user_id,
                per_page,
                offset,
                filter_start,
                filter_end,
            )

    total_pages = 1
    if total_filtered and per_page:
        total_pages = (total_filtered + per_page - 1) // per_page
    total_pages = max(total_pages, 1)
    if page > total_pages:
        args = request.args.to_dict(flat=True)
        args['page'] = total_pages
        return redirect(url_for('trainer_self_agenda_view', **args))

    def _localize(dt: datetime | None) -> datetime | None:
        if not dt:
            return None
        localized = dt
        if localized.tzinfo is None:
            localized = localized.replace(tzinfo=timezone.utc)
        try:
            return localized.astimezone(tz_info)
        except Exception:
            return localized

    def _format_local_time(dt):
        localized = _localize(dt)
        if not localized:
            return '—'
        return localized.strftime('%I:%M %p').lstrip('0')

    back_target = request.full_path or url_for('trainer_self_agenda_view')
    if back_target.endswith('?'):
        back_target = back_target[:-1]
    agenda_events = []
    for row in sessions:
        start_dt = row.get('start_time')
        end_dt = row.get('end_time')
        start_iso = start_dt.isoformat() if start_dt else None
        end_iso = end_dt.isoformat() if end_dt else None
        localized_start = _localize(start_dt)
        date_display = localized_start.strftime('%A, %B %d, %Y') if localized_start else '—'
        start_time_display = _format_local_time(start_dt)
        end_time_display = _format_local_time(end_dt)
        session_url = None
        session_id_val = row.get('session_id')
        if session_id_val:
            url_params = {'session_id': session_id_val}
            if timezone_name:
                url_params['timezone'] = timezone_name
            if tz_offset_minutes is not None:
                url_params['tz_offset'] = tz_offset_minutes
            if back_target:
                url_params['back'] = back_target
            session_url = url_for('workout_session_view', **url_params)

        agenda_events.append({
            'id': row.get('id'),
            'status': (row.get('status') or 'booked').capitalize(),
            'start_iso': start_iso,
            'end_iso': end_iso,
            'date_display': date_display,
            'start_display': start_time_display,
            'end_display': end_time_display,
            'session_category': row.get('session_category'),
            'session_url': session_url,
        })

    if total_filtered:
        page_start_index = offset + 1
        page_end_index = min(offset + len(agenda_events), total_filtered)
    else:
        page_start_index = 0
        page_end_index = 0

    per_page_options = list(per_page_selections)
    quick_filters = [
        {'key': 'last_7_days', 'label': 'Last 7 Days'},
        {'key': 'today', 'label': 'Today'},
        {'key': 'week', 'label': 'This Week'},
        {'key': 'month', 'label': 'This Month'},
        {'key': 'all', 'label': 'All'},
    ]

    return render_template(
        'trainer_self_agenda.html',
        events=agenda_events,
        total_sessions=total_all,
        filtered_total=total_filtered,
        page=page,
        total_pages=total_pages,
        per_page=per_page,
        per_page_options=per_page_options,
        selected_view=selected_view,
        start_date_input=start_date_raw,
        end_date_input=end_date_raw,
        custom_date_error=custom_date_error,
        custom_date_error_message=custom_error_message,
        quick_filters=quick_filters,
        timezone_name=timezone_name,
        tz_offset_minutes=tz_offset_minutes,
        page_start_index=page_start_index,
        page_end_index=page_end_index,
    )


@app.get('/trainer/my_workouts/data')
@login_required
def trainer_self_schedule_data():
    user_id = session['user_id']
    role = (session.get('role') or '').strip().lower()
    if role not in {'trainer', 'admin'}:
        return jsonify({'success': False, 'error': 'Trainer access required'}), 403

    start_raw = request.args.get('start')
    end_raw = request.args.get('end')
    now_utc = datetime.now(timezone.utc)
    try:
        start_dt = _parse_iso_datetime(start_raw, 'start') if start_raw else (now_utc - timedelta(days=now_utc.weekday()))
        end_dt = _parse_iso_datetime(end_raw, 'end') if end_raw else start_dt + timedelta(days=7)
    except ValueError as exc:
        return jsonify({'success': False, 'error': str(exc)}), 400

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT ts.id,
                       ts.trainer_id,
                       ts.client_id,
                       ts.start_time,
                       ts.end_time,
                       ts.status,
                       ts.note,
                       ts.session_id,
                       ts.session_category,
                       ts.session_completed_at
                  FROM trainer_schedule ts
                 WHERE ts.client_id = %s
                   AND ts.trainer_id = %s
                   AND ts.is_self_booked = TRUE
                   AND ts.start_time < %s
                   AND ts.end_time > %s
                 ORDER BY ts.start_time
                """,
                (user_id, user_id, end_dt, start_dt),
            )
            rows = cursor.fetchall() or []

    events = []
    for row in rows:
        event = _serialize_schedule_row(row)
        event.pop('note', None)
        event['trainer_name'] = None
        event['trainer_last_name'] = None
        event['trainer_username'] = None
        if event.get('session_id'):
            event['session_url'] = url_for('workout_session_view', session_id=event['session_id'])
        events.append(event)

    return jsonify({'success': True, 'events': events})


@app.route('/generate_client_workout/<int:client_id>', methods=['POST'])
@login_required
def generate_client_workout(client_id):
    trainer_id = session['user_id']
    trainer = _require_trainer(trainer_id)
    if not trainer:
        flash("Trainer access required.", "danger")
        return redirect(url_for('home'))
    trainer_can_generate_premium = trainer_has_premium_generation_access(trainer)

    selected_category = (request.form.get('category') or '').strip()
    if not selected_category:
        flash("Please choose a category before generating a workout.", "danger")
        return redirect(url_for('client_profile', client_id=client_id))
    def _flatten_custom_payload(entries):
        flattened = []
        for entry in entries or []:
            text = (entry or "").strip()
            if not text:
                continue
            if text.startswith("[") or text.startswith("{"):
                try:
                    decoded = json.loads(text)
                    if isinstance(decoded, (list, tuple)):
                        flattened.extend(decoded)
                        continue
                    if decoded:
                        flattened.append(decoded)
                        continue
                except (json.JSONDecodeError, TypeError, ValueError):
                    pass
            else:
                parts = [part for part in text.split(",") if part]
                if len(parts) > 1:
                    flattened.extend(parts)
                    continue
            flattened.append(text)
        return flattened

    raw_custom = request.form.getlist('custom_categories')
    if not raw_custom:
        raw_value = request.form.get('custom_categories')
        if raw_value:
            raw_custom = _flatten_custom_payload([raw_value])
    else:
        raw_custom = _flatten_custom_payload(raw_custom)
    raw_home_equipment = request.form.getlist('home_equipment')
    if not raw_home_equipment:
        raw_home_equipment = request.form.getlist('home_equipment[]')
    if not raw_home_equipment:
        raw_equipment_value = request.form.get('home_equipment')
        if raw_equipment_value:
            raw_home_equipment = [raw_equipment_value]
    raw_home_equipment = _flatten_custom_payload(raw_home_equipment)
    is_custom = selected_category in {CUSTOM_WORKOUT_TOKEN, HOME_WORKOUT_TOKEN}
    is_home = selected_category == HOME_WORKOUT_TOKEN
    custom_selection: list[str] = []
    home_equipment: list[str] = []

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT id, trainer_id, exercise_history,
                       COALESCE(workout_duration, 60) AS workout_duration,
                       subscription_type, trial_end_date
                  FROM users
                 WHERE id = %s
                """,
                (client_id,),
            )
            client = cursor.fetchone()

    if not client:
        flash("Client not found.", "danger")
        return redirect(url_for('trainer_dashboard'))

    if client.get('trainer_id') != trainer_id and trainer.get('role') != 'admin':
        flash("You do not have access to that client.", "danger")
        return redirect(url_for('trainer_dashboard'))

    try:
        duration_minutes = int(client.get('workout_duration') or 60)
    except (TypeError, ValueError):
        duration_minutes = 60
    subscription_type = client.get('subscription_type')
    trial_end_date = client.get('trial_end_date')

    if not trainer_can_generate_premium:
        today = datetime.today().date()
        if subscription_type == 'free' or (
            subscription_type == 'premium' and trial_end_date and today > trial_end_date
        ):
            if selected_category != FREE_SUBSCRIPTION_CATEGORY:
                flash("This client needs Premium access to use that category.", "warning")
                return redirect(url_for('client_profile', client_id=client_id))

    user_level = get_user_level(client.get('exercise_history'))
    if is_custom:
        custom_selection = normalize_custom_workout_categories(raw_custom)
        min_required, max_allowed = custom_selection_bounds(duration_minutes)
        count = len(custom_selection)
        if count < min_required or count > max_allowed:
            flash(
                f"Select between {min_required} and {max_allowed} categories for a {duration_minutes}-minute {selected_category}.",
                "warning",
            )
            return redirect(url_for('client_profile', client_id=client_id))
        if not custom_selection:
            flash(f"Choose at least one category before generating a {selected_category}.", "warning")
            return redirect(url_for('client_profile', client_id=client_id))
    if is_home:
        home_equipment = normalize_home_equipment_selection(raw_home_equipment)
        if not home_equipment:
            flash("Select at least one piece of equipment for a Custom Home Workout.", "warning")
            return redirect(url_for('client_profile', client_id=client_id))

    try:
        workout_plan, skipped_meta = generate_workout(
            selected_category,
            user_level,
            client_id,
            duration_minutes,
            custom_categories=custom_selection if is_custom else None,
            equipment_filters=home_equipment if is_home else None,
        )
    except ValueError as exc:
        flash(str(exc), "warning")
        return redirect(url_for('client_profile', client_id=client_id))
    workout_payload = {
        'plan': workout_plan,
        'duration_minutes': duration_minutes,
        'skipped': skipped_meta,
    }
    if is_custom:
        workout_payload['custom_categories'] = custom_selection
    if is_home:
        workout_payload['home_equipment'] = home_equipment
    set_active_workout(client_id, selected_category, workout_payload)

    flash_message = "Client workout generated and synced."
    skipped_summary = []
    if skipped_meta:
        categories = skipped_meta.get('categories') or []
        subcategories = skipped_meta.get('subcategories') or []
        combined = sorted(set(categories) | set(subcategories))
        if combined:
            skipped_summary.append(f"Skipped: {', '.join(combined)}")
        if skipped_meta.get('cardio_restriction'):
            skipped_summary.append("Cardio restricted")
    if skipped_summary:
        flash_message = f"{flash_message} ({'; '.join(skipped_summary)})"

    flash(flash_message, "success")
    return redirect(url_for('client_profile', client_id=client_id, focus='active'))


@app.route('/trainer/clients/<int:client_id>/complete_workout', methods=['POST'])
@login_required
def trainer_complete_client_workout(client_id):
    trainer_id = session['user_id']
    trainer = _require_trainer(trainer_id)
    if not trainer:
        flash("Trainer access required.", "danger")
        return redirect(url_for('home'))

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                "SELECT trainer_id FROM users WHERE id = %s",
                (client_id,),
            )
            row = cursor.fetchone()

    if not row:
        flash("Client not found.", "danger")
        return redirect(url_for('trainer_dashboard'))

    if row.get('trainer_id') != trainer_id and trainer.get('role') != 'admin':
        flash("You do not have access to that client.", "danger")
        return redirect(url_for('trainer_dashboard'))

    success, error, session_meta = _complete_workout_for_user(client_id)
    if success:
        event_to_complete = None
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO trainer_sessions (trainer_id, client_id)
                    VALUES (%s, %s)
                    """,
                    (trainer_id, client_id),
                )
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT id
                      FROM trainer_schedule
                     WHERE client_id = %s
                       AND trainer_id = %s
                       AND status = 'booked'
                     ORDER BY start_time ASC
                     LIMIT 1
                    """,
                    (client_id, trainer_id),
                )
                row = cursor.fetchone()
                if row:
                    event_to_complete = row[0]
                    cursor.execute(
                        "UPDATE trainer_schedule SET status = 'completed' WHERE id = %s",
                        (event_to_complete,),
                    )
                    _adjust_sessions_booked(cursor, client_id, -1)
            conn.commit()
        _attach_session_to_schedule(client_id, session_meta, trainer_id=trainer_id, schedule_event_id=event_to_complete)
        flash('Session marked complete for client.', 'success')
    else:
        flash(error or 'Unable to complete the workout for this client.', 'danger')

    return redirect(url_for('trainer_dashboard', focus=f'client-{client_id}'))

@app.route('/trainer/clients/<int:client_id>/remove', methods=['POST'])
@login_required
def trainer_remove_client(client_id):
    trainer_id = session['user_id']
    trainer = _require_trainer(trainer_id)
    if not trainer:
        flash("Trainer access required.", "danger")
        return redirect(url_for('home'))

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                "SELECT id, trainer_id, name, last_name FROM users WHERE id = %s",
                (client_id,),
            )
            client = cursor.fetchone()

    if not client:
        flash("Client not found.", "danger")
        return redirect(url_for('trainer_dashboard'))

    if client.get('trainer_id') != trainer_id and trainer.get('role') != 'admin':
        flash("You do not have access to that client.", "danger")
        return redirect(url_for('trainer_dashboard'))

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT status
                  FROM trainer_schedule
                 WHERE trainer_id = %s
                   AND client_id = %s
                """,
                (trainer_id, client_id),
            )
            events = cursor.fetchall() or []

        booked_events = sum(1 for ev in events if (ev.get('status') or 'booked').lower() == 'booked')

        with conn.cursor() as cursor:
            cursor.execute(
                "DELETE FROM trainer_schedule WHERE trainer_id = %s AND client_id = %s",
                (trainer_id, client_id),
            )
            if booked_events:
                cursor.execute(
                    """
                    UPDATE users
                       SET sessions_booked = GREATEST(COALESCE(sessions_booked, 0) - %s, 0)
                     WHERE id = %s
                    """,
                    (booked_events, client_id),
                )
            cursor.execute(
                "UPDATE users SET trainer_id = NULL WHERE id = %s",
                (client_id,),
            )
            conn.commit()

    client_name = f"{client.get('name') or ''} {client.get('last_name') or ''}".strip() or 'Client'
    flash(f"{client_name} removed from your client list.", "success")
    return redirect(url_for('trainer_dashboard'))


@app.route('/trainer/clients/<int:client_id>/sessions_remaining', methods=['POST'])
@login_required
def trainer_update_sessions_remaining(client_id):
    trainer_id = session['user_id']
    trainer = _require_trainer(trainer_id)
    if not trainer:
        flash("Trainer access required.", "danger")
        return redirect(url_for('home'))

    value_raw = (request.form.get('sessions_remaining') or '').strip()
    sessions_value = None
    if value_raw:
        try:
            sessions_value = int(value_raw)
        except ValueError:
            flash("Enter sessions remaining as a whole number.", "danger")
            return redirect(url_for('client_profile', client_id=client_id))
        if sessions_value < 0:
            flash("Sessions remaining cannot be negative.", "danger")
            return redirect(url_for('client_profile', client_id=client_id))

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                "SELECT trainer_id, sessions_booked FROM users WHERE id = %s",
                (client_id,),
            )
            client = cursor.fetchone()

            if not client:
                flash("Client not found.", "danger")
                return redirect(url_for('trainer_dashboard'))

            if client.get('trainer_id') != trainer_id and trainer.get('role') != 'admin':
                flash("You do not have access to that client.", "danger")
                return redirect(url_for('trainer_dashboard'))

            booked = int(client.get('sessions_booked') or 0)
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
            completed = int(completed_row.get('completed_count') or 0)
            consumed = booked + completed
            if sessions_value is not None and sessions_value < consumed:
                flash(
                    f"This client already has {consumed} session(s) booked or completed. Increase the total or cancel sessions before lowering it.",
                    'danger'
                )
                return redirect(url_for('client_profile', client_id=client_id))

            cursor.execute(
                "UPDATE users SET sessions_remaining = %s WHERE id = %s",
                (sessions_value, client_id),
            )
            conn.commit()

    flash("Sessions remaining updated.", "success")
    return redirect(url_for('client_profile', client_id=client_id))


@app.route('/trainer/clients/<int:client_id>/session_packages', methods=['POST'])
@login_required
def trainer_add_session_package(client_id):
    trainer_id = session['user_id']
    trainer = _require_trainer(trainer_id)
    if not trainer:
        flash("Trainer access required.", "danger")
        return redirect(url_for('home'))

    sessions_raw = (request.form.get('sessions_purchased') or '').strip()
    label = (request.form.get('label') or '').strip() or None
    price_raw = (request.form.get('price_paid') or '').strip()
    currency_raw = (request.form.get('currency') or 'USD').strip().upper()
    currency = (currency_raw or 'USD')[:3] or 'USD'
    note = (request.form.get('note') or '').strip() or None

    if not sessions_raw:
        flash("Enter how many sessions were purchased.", "danger")
        return redirect(url_for('client_profile', client_id=client_id))
    try:
        sessions_count = int(sessions_raw)
    except ValueError:
        flash("Sessions purchased must be a whole number.", "danger")
        return redirect(url_for('client_profile', client_id=client_id))
    if sessions_count <= 0:
        flash("Sessions purchased must be greater than zero.", "danger")
        return redirect(url_for('client_profile', client_id=client_id))

    price_value = None
    if price_raw:
        try:
            price_value = Decimal(price_raw)
        except (InvalidOperation, ValueError):
            flash("Enter a valid price paid for the package.", "danger")
            return redirect(url_for('client_profile', client_id=client_id))
        if price_value < 0:
            flash("Price paid cannot be negative.", "danger")
            return redirect(url_for('client_profile', client_id=client_id))

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                "SELECT trainer_id FROM users WHERE id = %s",
                (client_id,),
            )
            client = cursor.fetchone()

        if not client:
            flash("Client not found.", "danger")
            return redirect(url_for('trainer_dashboard'))

        if client.get('trainer_id') != trainer_id and trainer.get('role') != 'admin':
            flash("You do not have access to that client.", "danger")
            return redirect(url_for('trainer_dashboard'))

        package_trainer_id = trainer_id
        if trainer.get('role') == 'admin' and client.get('trainer_id'):
            package_trainer_id = client['trainer_id']

        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO client_session_packages (client_id, trainer_id, label, sessions_purchased, price_paid, currency, note)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (client_id, package_trainer_id, label, sessions_count, price_value, currency or 'USD', note),
            )
            conn.commit()

    flash("Session package added to purchase history.", "success")
    return redirect(url_for('client_profile', client_id=client_id, focus='sessions'))


@app.route('/trainer/clients/<int:client_id>/workout_duration', methods=['POST'])
@login_required
def trainer_update_client_duration(client_id):
    trainer = _require_trainer(session['user_id'])
    if not trainer:
        return jsonify({'success': False, 'error': 'Trainer access required'}), 403

    data = request.get_json(silent=True) or {}
    raw = str(data.get('workout_duration', '')).strip()
    allowed = {'20', '30', '45', '60'}
    if raw not in allowed:
        return jsonify({'success': False, 'error': 'Invalid duration'}), 400

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                "SELECT trainer_id FROM users WHERE id = %s",
                (client_id,),
            )
            client = cursor.fetchone()

            if not client:
                return jsonify({'success': False, 'error': 'Client not found'}), 404

            if client.get('trainer_id') != session['user_id'] and trainer.get('role') != 'admin':
                return jsonify({'success': False, 'error': 'You do not have access to that client.'}), 403

            cursor.execute(
                "UPDATE users SET workout_duration = %s WHERE id = %s",
                (int(raw), client_id),
            )
            conn.commit()

    return jsonify({'success': True, 'workout_duration': int(raw)})


@app.route('/trainer/clients/<int:client_id>/injury', methods=['POST'])
@login_required
def trainer_update_client_injury(client_id):
    trainer = _require_trainer(session['user_id'])
    if not trainer:
        flash("Trainer access required.", "danger")
        return redirect(url_for('home'))

    injury_status = (request.form.get('injury_status') or 'No').strip().title()
    injury_payload_raw = request.form.get('injury') or '[]'
    injury_details = (request.form.get('injury_details') or '').strip()
    cardio_flag_input = request.form.get('cardio_restriction') == 'yes'

    injury_payload_form = parse_injury_payload(injury_payload_raw)
    injury_regions_selected = injury_payload_form['regions']
    cardio_restriction_value = cardio_flag_input or injury_payload_form['cardio']

    if injury_status not in ('Yes', 'No'):
        flash("Please specify if this client currently has injuries or restrictions.", "danger")
        return redirect(url_for('client_profile', client_id=client_id))

    if injury_status == 'No':
        injury_regions_selected = []
        cardio_restriction_value = False
        injury_details = ''
    else:
        if not injury_regions_selected and not cardio_restriction_value:
            flash("Select at least one area or cardio to skip when injury status is Yes.", "danger")
            return redirect(url_for('client_profile', client_id=client_id))
        if not injury_details:
            flash("Please add a brief note describing the injury or restriction.", "danger")
            return redirect(url_for('client_profile', client_id=client_id))

    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT trainer_id FROM users WHERE id = %s", (client_id,))
            row = cursor.fetchone()

    if not row:
        flash("Client not found.", "danger")
        return redirect(url_for('trainer_dashboard'))

    client_trainer_id = row[0]
    if client_trainer_id != session['user_id'] and trainer.get('role') != 'admin':
        flash("You do not have permission to update this client's restrictions.", "danger")
        return redirect(url_for('trainer_dashboard'))

    injury_json = json.dumps(injury_regions_selected)
    is_injury_free = (injury_status == 'No')
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE users
                   SET injury = %s,
                       injury_details = %s,
                       cardio_restriction = %s,
                       injury_free_since = CASE WHEN %s THEN COALESCE(injury_free_since, CURRENT_DATE) ELSE NULL END
                 WHERE id = %s
                """,
                (injury_json, injury_details, cardio_restriction_value, is_injury_free, client_id),
            )
            conn.commit()

    skipped = compute_injury_exclusions(injury_regions_selected, cardio_restriction_value)
    skipped_display = ", ".join(token.replace('_', ' ').title() for token in sorted(skipped)) if skipped else "no categories"
    flash(f"Injury settings updated. Skipping: {skipped_display}.", "success")
    return redirect(url_for('client_profile', client_id=client_id))


@app.route('/trainer/clients/<int:client_id>/training_profile', methods=['POST'])
@login_required
def trainer_update_client_training_profile(client_id):
    trainer = _require_trainer(session['user_id'])
    if not trainer:
        flash("Trainer access required.", "danger")
        return redirect(url_for('home'))

    goals = [goal.strip() for goal in request.form.getlist('fitness_goals') if goal and goal.strip()]
    exercise_history = (request.form.get('exercise_history') or '').strip()
    commitment = (request.form.get('commitment') or '').strip()

    if not exercise_history:
        flash("Please choose an exercise history option.", "danger")
        return redirect(url_for('client_profile', client_id=client_id))

    if not commitment:
        flash("Please choose a weekly commitment.", "danger")
        return redirect(url_for('client_profile', client_id=client_id))

    if not goals or len(goals) > 2:
        flash("Select one or two fitness goals.", "danger")
        return redirect(url_for('client_profile', client_id=client_id))

    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT trainer_id FROM users WHERE id = %s", (client_id,))
            row = cursor.fetchone()

    if not row:
        flash("Client not found.", "danger")
        return redirect(url_for('trainer_dashboard'))

    client_trainer_id = row[0]
    if client_trainer_id != session['user_id'] and trainer.get('role') != 'admin':
        flash("You do not have permission to update this client's profile.", "danger")
        return redirect(url_for('trainer_dashboard'))

    fitness_goals_str = ", ".join(goals)

    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE users
                   SET exercise_history = %s,
                       fitness_goals = %s,
                       commitment = %s
                 WHERE id = %s
                """,
                (exercise_history, fitness_goals_str, commitment, client_id),
            )
            conn.commit()

    flash("Training profile updated for this client.", "success")
    return redirect(url_for('client_profile', client_id=client_id))


@app.route('/trainer/clients/<int:client_id>/update_pr', methods=['POST'])
@login_required
def trainer_update_pr(client_id):
    trainer = _require_trainer(session['user_id'])
    if not trainer:
        return jsonify({'success': False, 'error': 'Trainer access required'}), 403

    data = request.get_json() or {}
    workout_id = data.get('workout_id')
    if not workout_id:
        return jsonify({'success': False, 'error': 'Missing workout id'}), 400

    max_weight_raw = data.get('max_weight')
    max_reps_raw = data.get('max_reps')

    max_weight = None
    if isinstance(max_weight_raw, (int, float)):
        max_weight = float(max_weight_raw)
    elif isinstance(max_weight_raw, str) and max_weight_raw.strip():
        try:
            max_weight = float(max_weight_raw)
        except ValueError:
            max_weight = None

    max_reps = None
    if isinstance(max_reps_raw, (int, float)):
        max_reps = int(max_reps_raw)
    elif isinstance(max_reps_raw, str) and max_reps_raw.strip():
        try:
            max_reps = int(float(max_reps_raw))
        except ValueError:
            max_reps = None

    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT trainer_id FROM users WHERE id = %s", (client_id,))
            row = cursor.fetchone()
    if not row:
        return jsonify({'success': False, 'error': 'Client not found'}), 404

    trainer_id = row[0]
    if trainer_id != session['user_id'] and trainer.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    result = _apply_pr_update(client_id, int(workout_id), max_weight, max_reps)
    return jsonify(result)


@app.route('/trainer/clients/<int:client_id>/update_notes', methods=['POST'])
@login_required
def trainer_update_notes(client_id):
    trainer = _require_trainer(session['user_id'])
    if not trainer:
        return jsonify({'success': False, 'error': 'Trainer access required'}), 403

    data = request.get_json(silent=True) or {}
    workout_id_raw = data.get('workout_id')
    try:
        workout_id = int(str(workout_id_raw).strip())
    except (TypeError, ValueError):
        return jsonify({'success': False, 'error': 'Invalid workout id'}), 400

    notes_raw = data.get('notes')
    notes = None
    if notes_raw is not None:
        cleaned = str(notes_raw).strip()
        if cleaned:
            notes = cleaned

    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT trainer_id FROM users WHERE id = %s", (client_id,))
            row = cursor.fetchone()
    if not row:
        return jsonify({'success': False, 'error': 'Client not found'}), 404

    trainer_id = row[0]
    if trainer_id != session['user_id'] and trainer.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    result = _apply_notes_update(client_id, workout_id, notes)
    return jsonify(result)


@app.route('/add_client', methods=['GET', 'POST'])
@login_required
def add_client():
    trainer_id = session['user_id']
    trainer = _require_trainer(trainer_id)
    if not trainer:
        flash("Trainer access required.", "danger")
        return redirect(url_for('home'))

    if request.method == 'POST':
        form_data = request.form
        name = (form_data.get('name') or '').strip() or None
        last_name = (form_data.get('last_name') or '').strip() or None
        raw_email = (form_data.get('email') or '').strip()
        email = normalize_email(raw_email)
        sessions_remaining = int_or_none(form_data.get('sessions_remaining'))

        errors = {}
        if not email:
            errors['email'] = 'Email is required.'
        elif not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
            errors['email'] = 'Enter a valid email address.'
        if sessions_remaining is not None and sessions_remaining < 0:
            errors['sessions_remaining'] = 'Sessions remaining must be zero or more.'

        if errors:
            for msg in errors.values():
                flash(msg, 'danger')
            return render_template('trainer_add_client.html', trainer=trainer, form_data=form_data)

        invite_context = None
        link_context = None
        try:
            with get_connection() as conn:
                conn.autocommit = False
                existing_user = None
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                    cursor.execute(
                        "SELECT id, status, trainer_id, name, last_name, email FROM users WHERE lower(email) = %s LIMIT 1",
                        (email.lower(),)
                    )
                    existing_user = cursor.fetchone()

                if existing_user and existing_user.get('status') == 'active':
                    if existing_user.get('trainer_id') == trainer_id:
                        conn.rollback()
                        flash('That client is already connected to you.', 'info')
                        return render_template('trainer_add_client.html', trainer=trainer, form_data=form_data)
                    if existing_user.get('trainer_id') and existing_user.get('trainer_id') != trainer_id:
                        conn.rollback()
                        flash('This user is already linked to another trainer.', 'danger')
                        return render_template('trainer_add_client.html', trainer=trainer, form_data=form_data)

                    raw_token, expires_at, token_id = issue_single_use_token(conn, existing_user['id'], 'trainer_link', INVITE_TTL_HOURS)
                    with conn.cursor() as cursor:
                        cursor.execute(
                            """
                            DELETE FROM trainer_link_invites
                             WHERE client_id = %s
                               AND trainer_id = %s
                               AND accepted_at IS NULL
                            """,
                            (existing_user['id'], trainer_id)
                        )
                        cursor.execute(
                            """
                            INSERT INTO trainer_link_invites (token_id, trainer_id, client_id, sessions_remaining)
                            VALUES (%s, %s, %s, %s)
                            """,
                            (token_id, trainer_id, existing_user['id'], sessions_remaining)
                        )
                    conn.commit()
                    link_context = {
                        'email': existing_user.get('email') or email,
                        'first_name': existing_user.get('name') or name or 'there',
                        'trainer_display': _trainer_display_name(trainer),
                        'invite_url': url_for('trainer_link_accept', token=raw_token, _external=True),
                        'sessions_note': _format_sessions_note(sessions_remaining),
                    }
                else:
                    try:
                        user_id = upsert_invited_user(
                            conn,
                            email=email,
                            first=name,
                            last=last_name,
                            role='user',
                            subscription='premium',
                            invited_by=trainer_id,
                            trainer_id=trainer_id,
                            sessions_remaining=sessions_remaining,
                        )
                    except ValueError as ve:
                        conn.rollback()
                        flash(str(ve), 'danger')
                        return render_template('trainer_add_client.html', trainer=trainer, form_data=form_data)

                    raw_token, expires_at, _token_id = issue_single_use_token(conn, user_id, 'invite', INVITE_TTL_HOURS)
                    conn.commit()
                    invite_context = {
                        'invite_url': url_for('accept_invite', token=raw_token, _external=True),
                        'email': email,
                        'first_name': name or 'there',
                        'admin_note': _build_trainer_invite_note(trainer, sessions_remaining),
                    }

        except psycopg2.Error:
            current_app.logger.exception('Failed creating client invite')
            flash('Error creating client invite.', 'danger')
            return render_template('trainer_add_client.html', trainer=trainer, form_data=form_data)

        if link_context:
            try:
                send_trainer_link_email(
                    to_email=link_context['email'],
                    first_name=link_context['first_name'],
                    trainer_display_name=link_context['trainer_display'],
                    invite_url=link_context['invite_url'],
                    sessions_summary=link_context['sessions_note'],
                )
                flash(
                    Markup(
                        f"Trainer link invite sent to <strong>{link_context['email']}</strong>. "
                        f"<button type=\"button\" class=\"btn btn-sm btn-link text-decoration-none flash-copy\" data-link=\"{link_context['invite_url']}\">Copy invite link</button>"
                    ),
                    'success',
                )
            except Exception:
                current_app.logger.exception('Failed to send trainer link email to existing client')
                flash(
                    Markup(
                        f"Link invite created, but email failed to send. Share it manually: "
                        f"<a href=\"{link_context['invite_url']}\">{link_context['invite_url']}</a>"
                    ),
                    'warning',
                )
            return redirect(url_for('trainer_dashboard'))

        if invite_context:
            try:
                send_invite_email(
                    to_email=invite_context['email'],
                    first_name=invite_context['first_name'],
                    invite_url=invite_context['invite_url'],
                    admin_note=invite_context['admin_note'],
                )
                flash(
                    Markup(
                        f"Invitation sent to <strong>{invite_context['email']}</strong>. "
                        f"<button type=\"button\" class=\"btn btn-sm btn-link text-decoration-none flash-copy\" data-link=\"{invite_context['invite_url']}\">Copy invite link</button>"
                    ),
                    'success',
                )
            except Exception:
                current_app.logger.exception('Failed to send invite email to new client')
                flash(
                    Markup(
                        f"Invite link created, but email failed to send. Share it manually: "
                        f"<a href=\"{invite_context['invite_url']}\">{invite_context['invite_url']}</a>"
                    ),
                    'warning',
                )
            return redirect(url_for('trainer_dashboard'))

        flash('Unable to create that invite. Please try again.', 'danger')
        return render_template('trainer_add_client.html', trainer=trainer, form_data=form_data)

    return render_template('trainer_add_client.html', trainer=trainer)


@app.route('/update_workout_duration', methods=['POST'])
@login_required
def update_workout_duration():
    data = request.get_json(silent=True) or {}
    raw = str(data.get('workout_duration', '')).strip()
    allowed = {'20', '30', '45', '60'}
    if raw not in allowed:
        return jsonify({'success': False, 'error': 'Invalid duration'}), 400

    user_id = session['user_id']
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("UPDATE users SET workout_duration = %s WHERE id = %s", (int(raw), user_id))
            conn.commit()

    return jsonify({'success': True})


@app.route('/generate_workout')
@login_required
def generate_workout_route():
    selected_category = (request.args.get('category') or '').strip()
    if not selected_category:
        return jsonify({'success': False, 'error': 'No category selected'}), 400
    raw_custom = request.args.getlist('custom_categories')
    if not raw_custom:
        raw_custom = request.args.getlist('custom_categories[]')
    if not raw_custom:
        raw_value = request.args.get('custom_categories')
        if raw_value:
            raw_custom = [part for part in raw_value.split(',') if part]
    raw_home_equipment = request.args.getlist('home_equipment')
    if not raw_home_equipment:
        raw_home_equipment = request.args.getlist('home_equipment[]')
    if not raw_home_equipment:
        raw_equipment_value = request.args.get('home_equipment')
        if raw_equipment_value:
            raw_home_equipment = [part for part in raw_equipment_value.split(',') if part]
    is_custom = selected_category in {CUSTOM_WORKOUT_TOKEN, HOME_WORKOUT_TOKEN}
    is_home = selected_category == HOME_WORKOUT_TOKEN
    custom_selection: list[str] = []
    home_equipment: list[str] = []

    user_id = session['user_id']

    # Fetch the user's level
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT exercise_history, COALESCE(workout_duration, 60) AS workout_duration, subscription_type, trial_end_date 
                FROM users 
                WHERE id = %s
            """, (user_id,))
            row = cursor.fetchone()
            exercise_history = row[0]
            duration_minutes = int(row[1])
            subscription_type = row[2]
            trial_end_date = row[3]

            today = datetime.today().date()
            if subscription_type == 'free' or (subscription_type == 'premium' and trial_end_date and today > trial_end_date):
                if selected_category != FREE_SUBSCRIPTION_CATEGORY:
                    return jsonify({'success': False, 'error': 'Upgrade to Premium to access this category.'})

            user_level = get_user_level(exercise_history)
            if is_custom:
                custom_selection = normalize_custom_workout_categories(raw_custom)
                min_required, max_allowed = custom_selection_bounds(duration_minutes)
                count = len(custom_selection)
                if count < min_required or count > max_allowed:
                    message = f"Select between {min_required} and {max_allowed} categories for a {duration_minutes}-minute {selected_category}."
                    return jsonify({'success': False, 'error': message}), 400
                if not custom_selection:
                    return jsonify({'success': False, 'error': f'Choose at least one category for a {selected_category}.'}), 400
            if is_home:
                home_equipment = normalize_home_equipment_selection(raw_home_equipment)
                if not home_equipment:
                    return jsonify({'success': False, 'error': 'Select at least one piece of equipment for a Custom Home Workout.'}), 400

    # Generate the workout
    try:
        workout_plan, skipped_meta = generate_workout(
            selected_category,
            user_level,
            user_id,
            duration_minutes,
            custom_categories=custom_selection if is_custom else None,
            equipment_filters=home_equipment if is_home else None,
        )
    except ValueError as exc:
        return jsonify({'success': False, 'error': str(exc)}), 400
    workout_payload = {
        'plan': workout_plan,
        'duration_minutes': duration_minutes,
        'skipped': skipped_meta,
    }
    if is_custom:
        workout_payload['custom_categories'] = custom_selection
    if is_home:
        workout_payload['home_equipment'] = home_equipment

    set_active_workout(user_id, selected_category, workout_payload)

    formatted_workout = format_workout_for_response(selected_category, workout_plan)

    return jsonify({
        'success': True,
        'category': selected_category,
        'duration_minutes': duration_minutes,
        'workout': formatted_workout,
        'skipped': skipped_meta,
        'custom_categories': custom_selection if is_custom else [],
        'home_equipment': home_equipment if is_home else [],
    })


@app.route('/get_active_workout')
@login_required
def get_active_workout_route():
    user_id = session['user_id']
    row = get_active_workout(user_id)
    if not row:
        return jsonify({'success': False})

    data = row.get('workout_data') or {}
    plan = data.get('plan') if isinstance(data, dict) else None
    if not plan:
        return jsonify({'success': False})

    formatted_workout = format_workout_for_response(row['category'], plan)

    return jsonify({
        'success': True,
        'category': row['category'],
        'duration_minutes': data.get('duration_minutes'),
        'workout': formatted_workout,
        'skipped': data.get('skipped', {}),
        'custom_categories': data.get('custom_categories', []),
        'home_equipment': data.get('home_equipment', []),
    })


@app.post('/clear_active_workout')
@login_required
def clear_active_workout_route():
    user_id = session['user_id']
    clear_active_workout(user_id)
    return jsonify({'success': True})


def _apply_pr_update(user_id: int, workout_id: int, max_weight, max_reps):
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO user_exercise_progress (user_id, workout_id, name, max_weight, max_reps)
                SELECT %s, w.id, w.name, %s, %s
                  FROM workouts w
                 WHERE w.id = %s
                ON CONFLICT (user_id, workout_id) DO UPDATE
                SET name = EXCLUDED.name,
                    max_weight = EXCLUDED.max_weight,
                    max_reps = EXCLUDED.max_reps,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (user_id, max_weight, max_reps, workout_id),
            )

        _record_exercise_history(user_id, workout_id, max_weight, max_reps)

        active_updated = False
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT category, workout_data FROM active_workouts WHERE user_id = %s",
                (user_id,),
            )
            active = cur.fetchone()

        if active and active.get('workout_data') is not None:
            payload = active['workout_data']
            workout_id_str = str(workout_id)

            def update_exercise_entry(entry):
                nonlocal active_updated
                if isinstance(entry, dict):
                    if str(entry.get('workout_id')) == workout_id_str:
                        entry = {**entry}
                        entry['max_weight'] = max_weight
                        entry['max_reps'] = max_reps
                        active_updated = True
                    return entry
                if isinstance(entry, (list, tuple)):
                    if entry and str(entry[0]) == workout_id_str:
                        entry_list = list(entry)
                        while len(entry_list) <= 7:
                            entry_list.append(None)
                        entry_list[6] = max_weight
                        entry_list[7] = max_reps
                        active_updated = True
                        return entry_list
                return entry

            def update_structure(node):
                if isinstance(node, dict):
                    if 'workout_id' in node or 'exercise_id' in node:
                        return update_exercise_entry(node)
                    return {key: update_structure(value) for key, value in node.items()}
                if isinstance(node, list):
                    if node and not isinstance(node[0], (dict, list, tuple)) and str(node[0]) == workout_id_str:
                        return update_exercise_entry(node)
                    return [update_structure(item) for item in node]
                return node

            updated_payload = update_structure(payload)
            if active_updated:
                with get_connection() as conn:
                    with conn.cursor() as cursor:
                        cursor.execute(
                            """
                            UPDATE active_workouts
                               SET workout_data = %s
                             WHERE user_id = %s
                            """,
                            (psycopg2.extras.Json(updated_payload), user_id),
                        )
                        conn.commit()

    return {'success': True, 'max_weight': max_weight, 'max_reps': max_reps}


def _apply_notes_update(user_id: int, workout_id: int, notes: str | None):
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO user_exercise_progress (user_id, workout_id, name, notes)
                SELECT %s, w.id, w.name, %s
                  FROM workouts w
                 WHERE w.id = %s
                ON CONFLICT (user_id, workout_id) DO UPDATE
                SET name = EXCLUDED.name,
                    notes = EXCLUDED.notes,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (user_id, notes, workout_id),
            )

        active_updated = False
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT category, workout_data FROM active_workouts WHERE user_id = %s",
                (user_id,),
            )
            active = cur.fetchone()

        if active and active.get('workout_data') is not None:
            payload = active['workout_data']
            workout_id_str = str(workout_id)

            def update_exercise_entry(entry):
                nonlocal active_updated
                if isinstance(entry, dict):
                    if str(entry.get('workout_id')) == workout_id_str:
                        entry = {**entry}
                        entry['notes'] = notes
                        active_updated = True
                    return entry
                if isinstance(entry, (list, tuple)):
                    if entry and str(entry[0]) == workout_id_str:
                        entry_list = list(entry)
                        while len(entry_list) <= 8:
                            entry_list.append(None)
                        entry_list[8] = notes
                        active_updated = True
                        return entry_list
                return entry

            def update_structure(node):
                if isinstance(node, dict):
                    if 'workout_id' in node or 'exercise_id' in node:
                        return update_exercise_entry(node)
                    return {key: update_structure(value) for key, value in node.items()}
                if isinstance(node, list):
                    if node and not isinstance(node[0], (dict, list, tuple)) and str(node[0]) == workout_id_str:
                        return update_exercise_entry(node)
                    return [update_structure(item) for item in node]
                return node

            updated_payload = update_structure(payload)
            if active_updated:
                with get_connection() as conn:
                    with conn.cursor() as cursor:
                        cursor.execute(
                            """
                            UPDATE active_workouts
                               SET workout_data = %s
                             WHERE user_id = %s
                            """,
                            (psycopg2.extras.Json(updated_payload), user_id),
                        )
                        conn.commit()

    return {'success': True, 'notes': notes or ''}


def _complete_workout_for_user(user_id: int) -> tuple[bool, str | None, dict | None]:
    active = get_active_workout(user_id)
    if not active:
        return False, 'No workout generated', None

    workout_data = active.get('workout_data') or {}
    stored_plan = workout_data.get('plan') if isinstance(workout_data, dict) else None
    if not stored_plan:
        return False, 'No workout data available', None

    workout_category = active.get('category')
    workout_payload_meta = {}
    custom_tokens_seen = set()
    custom_tokens = []
    custom_pretty = []
    if isinstance(workout_data, dict):
        raw_custom = workout_data.get('custom_categories')
        if isinstance(raw_custom, list):
            for token in raw_custom:
                if not token:
                    continue
                token_str = str(token).strip()
                if not token_str:
                    continue
                normalized_token = token_str.upper()
                if normalized_token in custom_tokens_seen:
                    continue
                custom_tokens_seen.add(normalized_token)
                custom_tokens.append(normalized_token)
                pretty = token_str.lower().replace('_', ' ').title()
                custom_pretty.append(pretty)
    if custom_pretty:
        display_category = ', '.join(custom_pretty)
        workout_payload_meta = {
            'custom_categories': custom_tokens,
            'custom_categories_pretty': custom_pretty,
        }
    else:
        display_category = workout_category

    refreshed_workout = OrderedDict()
    session_entries: list[dict] = []

    with get_connection() as conn:
        with conn.cursor() as cursor:
            for subcat, exercises in _normalize_plan_for_iteration(stored_plan):
                refreshed_workout[subcat] = []
                for ex in exercises or []:
                    workout_id = ex.get('workout_id') if isinstance(ex, dict) else ex[0]
                    cursor.execute(
                        """
                        SELECT w.name,
                               w.description,
                               uep.max_weight,
                               uep.max_reps,
                               uep.notes
                          FROM workouts w
                     LEFT JOIN user_exercise_progress uep
                            ON w.id = uep.workout_id AND uep.user_id = %s
                         WHERE w.id = %s
                        """,
                        (user_id, workout_id),
                    )
                    result = cursor.fetchone()
                    if not result:
                        continue
                    name, description, max_weight, max_reps, notes = result
                    weight_value = _coerce_float(max_weight)
                    reps_value = None
                    if max_reps is not None:
                        try:
                            reps_value = int(float(max_reps))
                        except (TypeError, ValueError):
                            reps_value = None
                    refreshed_workout[subcat].append({
                        "workout_id": workout_id,
                        "name": name,
                        "description": description,
                        "max_weight": weight_value,
                        "max_reps": reps_value,
                        "notes": notes,
                    })
                    session_entries.append({
                        "workout_id": workout_id,
                        "subcategory": subcat,
                        "weight": weight_value,
                        "reps": reps_value,
                        "notes": notes,
                    })

            subcategory_order = list(refreshed_workout.keys())

            session_id, completed_at = _log_workout_session_history(
                user_id,
                display_category or workout_category or '',
                session_entries,
            )

            meta_payload = dict(workout_payload_meta) if workout_payload_meta else {}
            if subcategory_order:
                meta_payload['subcategory_order'] = subcategory_order
            if session_id:
                meta_payload['session_id'] = session_id
            if completed_at:
                meta_payload['completed_at'] = completed_at.isoformat()
            if meta_payload:
                refreshed_workout['_meta'] = meta_payload

            cursor.execute(
                """
                UPDATE users
                   SET workouts_completed = COALESCE(workouts_completed, 0) + 1,
                       last_workout_completed = %s,
                       last_workout_details = %s
                 WHERE id = %s
                """,
                (display_category, json.dumps(refreshed_workout), user_id),
            )
            conn.commit()

    clear_active_workout(user_id)
    session_meta = {
        'session_id': session_id,
        'completed_at': completed_at.isoformat() if completed_at else None,
        'payload': refreshed_workout,
        'display_category': display_category,
        'category_key': workout_category,
    }
    return True, None, session_meta


def _exercise_entry_workout_id(entry):
    if isinstance(entry, dict):
        return entry.get('workout_id')
    if isinstance(entry, (list, tuple)) and entry:
        return entry[0]
    return None


def _apply_formatted_exercise(entry, formatted_exercise):
    fields = [
        formatted_exercise.get('workout_id'),
        formatted_exercise.get('name'),
        formatted_exercise.get('description'),
        formatted_exercise.get('youtube_id'),
        formatted_exercise.get('image_exercise_start'),
        formatted_exercise.get('image_exercise_end'),
        formatted_exercise.get('max_weight'),
        formatted_exercise.get('max_reps'),
        formatted_exercise.get('notes'),
    ]
    if isinstance(entry, dict):
        updated = dict(entry)
        updated.update({
            'workout_id': fields[0],
            'name': fields[1],
            'description': fields[2],
            'youtube_id': fields[3],
            'image_exercise_start': fields[4],
            'image_exercise_end': fields[5],
            'max_weight': fields[6],
            'max_reps': fields[7],
            'notes': fields[8],
        })
        return updated
    if isinstance(entry, list):
        entry_list = list(entry)
        while len(entry_list) < len(fields):
            entry_list.append(None)
        for idx, value in enumerate(fields):
            entry_list[idx] = value
        return entry_list


def _resolve_refresh_context(workout_payload, subcategory, workout_id):
    if not isinstance(workout_payload, dict):
        return None, ({'success': False, 'error': 'Active workout plan is missing.'}, 400)
    plan = workout_payload.get('plan')
    if not isinstance(plan, list):
        return None, ({'success': False, 'error': 'Active workout plan is missing.'}, 400)
    normalized_subcategory = (subcategory or '').strip().lower()
    target_block = None
    for block in plan:
        label = str(block.get('subcategory') or '').strip()
        if label.lower() == normalized_subcategory:
            target_block = block
            break
    if not target_block:
        return None, ({'success': False, 'error': 'Workout category not found.'}, 404)
    exercises = target_block.get('exercises') or []
    if not exercises:
        return None, ({'success': False, 'error': 'No exercises available for this category.'}, 400)
    existing_ids = set()
    replacement_index = None
    for idx, entry in enumerate(exercises):
        entry_id = _exercise_entry_workout_id(entry)
        if entry_id is None:
            return None, ({'success': False, 'error': 'An exercise is missing its identifier.'}, 400)
        try:
            entry_int = int(entry_id)
        except (TypeError, ValueError):
            return None, ({'success': False, 'error': 'Invalid exercise identifier detected.'}, 400)
        existing_ids.add(entry_int)
        if entry_int == workout_id:
            replacement_index = idx
    if replacement_index is None:
        return None, ({'success': False, 'error': 'Exercise not found in this workout.'}, 404)

    equipment_tokens = []
    raw_equipment = workout_payload.get('home_equipment')
    if raw_equipment:
        equipment_tokens = normalize_home_equipment_selection(raw_equipment)
    equipment_clause = ""
    equipment_params = []
    allow_cardio_bodyweight = False
    if equipment_tokens:
        equipment_clause, equipment_params, allow_cardio_bodyweight = build_home_equipment_clause(equipment_tokens)
    restrict_barbell = bool(equipment_tokens) and 'BARBELL' not in equipment_tokens
    restrict_dumbbell = bool(equipment_tokens) and 'DUMBBELL' not in equipment_tokens

    subcategory_key = (subcategory or "").strip().upper()
    use_cardio_override = allow_cardio_bodyweight and subcategory_key == 'CARDIO'

    context = {
        'target_block': target_block,
        'exercises': exercises,
        'replacement_index': replacement_index,
        'existing_ids': existing_ids,
        'equipment_clause': equipment_clause,
        'equipment_params': equipment_params,
        'use_cardio_override': use_cardio_override,
        'restrict_barbell': restrict_barbell,
        'restrict_dumbbell': restrict_dumbbell,
    }
    return context, None


def _build_alternate_exercise_query(
    target_user_id,
    subcategory,
    user_level,
    existing_ids,
    equipment_clause,
    equipment_params,
    use_cardio_override,
    restrict_barbell,
    restrict_dumbbell,
    *,
    selected_workout_id=None,
    random_order=True,
):
    query_parts = [
        """
        SELECT
            w.id AS workout_id,
            w.name,
            w.description,
            w.youtube_id,
            w.image_exercise_start,
            w.image_exercise_end,
            uep.max_weight,
            uep.max_reps,
            uep.notes
        FROM workouts w
        LEFT JOIN user_exercise_progress uep
            ON w.id = uep.workout_id AND uep.user_id = %s
        WHERE w.category = %s
          AND w.level <= %s
        """
    ]
    params = [target_user_id, subcategory, user_level]
    excluded_ids = sorted(existing_ids or [])
    if excluded_ids:
        placeholders = ','.join(['%s'] * len(excluded_ids))
        query_parts.append(f" AND w.id NOT IN ({placeholders})")
        params.extend(excluded_ids)
    equipment_clause = equipment_clause or ""
    equipment_params = list(equipment_params or [])
    if equipment_clause:
        if use_cardio_override:
            placeholders = ",".join(["%s"] * len(CARDIO_BODYWEIGHT_WORKOUTS))
            query_parts.append(f" AND (({equipment_clause}) OR w.name IN ({placeholders}))")
            params.extend(equipment_params)
            params.extend(CARDIO_BODYWEIGHT_WORKOUTS)
        else:
            query_parts.append(f" AND {equipment_clause}")
            params.extend(equipment_params)
    elif use_cardio_override:
        placeholders = ",".join(["%s"] * len(CARDIO_BODYWEIGHT_WORKOUTS))
        query_parts.append(f" AND w.name IN ({placeholders})")
        params.extend(CARDIO_BODYWEIGHT_WORKOUTS)
    if restrict_barbell:
        query_parts.append(" AND LOWER(w.name) NOT LIKE %s")
        params.append("%barbell%")
    if restrict_dumbbell:
        query_parts.append(" AND LOWER(w.name) NOT LIKE %s")
        params.append("%dumbbell%")
    if selected_workout_id:
        query_parts.append(" AND w.id = %s")
        params.append(selected_workout_id)
    if random_order:
        query_parts.append(" ORDER BY RANDOM() LIMIT 1")
    else:
        query_parts.append(
            """
            ORDER BY
                CASE w.movement_type
                    WHEN 'compound' THEN 1
                    WHEN 'accessory' THEN 2
                    ELSE 3
                END,
                w.name
            """
        )
    return "".join(query_parts), params
    return fields


def _attach_session_to_schedule(
    user_id: int,
    session_meta: dict | None,
    *,
    trainer_id: int | None = None,
    schedule_event_id: int | None = None,
    as_self_session: bool = False,
) -> None:
    if not session_meta:
        return
    session_id = session_meta.get('session_id')
    payload = session_meta.get('payload')
    completed_at = session_meta.get('completed_at')
    display_category = session_meta.get('display_category') or session_meta.get('category_key') or 'Workout Session'
    if not session_id or not payload:
        return

    if isinstance(completed_at, str):
        try:
            completed_dt = datetime.fromisoformat(completed_at)
        except ValueError:
            completed_dt = datetime.now(timezone.utc)
    elif isinstance(completed_at, datetime):
        completed_dt = completed_at
    else:
        completed_dt = datetime.now(timezone.utc)
    if completed_dt.tzinfo is None:
        completed_dt = completed_dt.replace(tzinfo=timezone.utc)

    try:
        uuid.UUID(str(session_id))
    except (ValueError, TypeError):
        return

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                "SELECT trainer_id, workout_duration FROM users WHERE id = %s",
                (user_id,),
            )
            user_row = cursor.fetchone()
            if not user_row:
                return

        duration_minutes = user_row.get('workout_duration') or 60
        try:
            duration_minutes = int(duration_minutes)
        except (TypeError, ValueError):
            duration_minutes = 60
        if duration_minutes <= 0:
            duration_minutes = 60
        start_dt = completed_dt - timedelta(minutes=duration_minutes)

        target_event_id = None
        def _validate_event(event_id: int | None) -> bool:
            if not event_id:
                return False
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute(
                    """
                    SELECT client_id, trainer_id, is_self_booked
                      FROM trainer_schedule
                     WHERE id = %s
                    """,
                    (event_id,),
                )
                row = cursor.fetchone()
            if not row:
                return False
            if as_self_session:
                return row.get('client_id') == user_id and row.get('is_self_booked')
            if trainer_id:
                return row.get('client_id') == user_id and row.get('trainer_id') == trainer_id and not row.get('is_self_booked')
            expected_trainer = user_row.get('trainer_id')
            return row.get('client_id') == user_id and row.get('trainer_id') == expected_trainer and not row.get('is_self_booked')

        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                "SELECT id FROM trainer_schedule WHERE session_id = %s",
                (session_id,),
            )
            existing = cursor.fetchone()
            if existing:
                target_event_id = existing.get('id')

        if not target_event_id and schedule_event_id:
            if _validate_event(schedule_event_id):
                target_event_id = schedule_event_id

        if not target_event_id:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                conditions = [
                    "client_id = %s",
                    "start_time <= %s",
                    "end_time >= %s",
                ]
                params = [user_id, completed_dt, completed_dt]
                if as_self_session:
                    conditions.append("is_self_booked = TRUE")
                cursor.execute(
                    f"""
                    SELECT id
                      FROM trainer_schedule
                     WHERE {' AND '.join(conditions)}
                     ORDER BY start_time DESC
                     LIMIT 1
                    """,
                    params,
                )
                match_row = cursor.fetchone()
                if match_row:
                    target_event_id = match_row.get('id')

        created_event = False
        if target_event_id and not _validate_event(target_event_id):
            target_event_id = None

        if not target_event_id:
            if as_self_session:
                assigned_trainer = user_id
            else:
                assigned_trainer = trainer_id or user_row.get('trainer_id')
            if not assigned_trainer:
                return
            is_self_booked = bool(as_self_session)
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute(
                    """
                    INSERT INTO trainer_schedule (
                        trainer_id,
                        client_id,
                        start_time,
                        end_time,
                        status,
                        note,
                        is_self_booked
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        assigned_trainer,
                        user_id,
                        start_dt,
                        completed_dt,
                        'completed',
                        'Session logged from completed workout',
                        is_self_booked,
                    ),
                )
                new_row = cursor.fetchone()
                target_event_id = new_row['id'] if isinstance(new_row, dict) else new_row[0]
                created_event = True

        if not target_event_id:
            conn.rollback()
            return

        note_value = None
        if isinstance(payload, dict):
            meta_block = payload.get('_meta')
            if isinstance(meta_block, dict):
                note_value = meta_block.get('notes')

        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE trainer_schedule
                   SET session_id = %s,
                       session_payload = %s,
                       session_category = %s,
                       session_completed_at = %s,
                       status = 'completed',
                       is_self_booked = CASE WHEN %s THEN TRUE ELSE is_self_booked END,
                       note = CASE
                                WHEN (note IS NULL OR note = '') AND %s IS NOT NULL THEN %s
                                ELSE note
                              END
                 WHERE id = %s
                """,
                (
                    session_id,
                    psycopg2.extras.Json(payload),
                    display_category,
                    completed_dt,
                    created_event,
                    note_value,
                    note_value,
                    target_event_id,
                ),
            )
            conn.commit()


@app.post('/training/workout/reorder')
@login_required
def personal_reorder_workout_exercises():
    user_id = session['user_id']
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                "SELECT role, subscription_type FROM users WHERE id = %s",
                (user_id,),
            )
            user_row = cursor.fetchone()
    if not _user_can_customize_personal_workout(user_row):
        return jsonify({'success': False, 'error': 'Trainer Pro access required.'}), 403

    payload = request.get_json(silent=True) or {}
    subcategory = (payload.get('subcategory') or '').strip()
    order_list = payload.get('order')
    if not subcategory or not isinstance(order_list, list) or not order_list:
        return jsonify({'success': False, 'error': 'Invalid reorder payload.'}), 400

    sanitized_order = []
    for value in order_list:
        key = str(value).strip()
        if not key:
            continue
        sanitized_order.append(key)
    if len(sanitized_order) != len(order_list):
        return jsonify({'success': False, 'error': 'Invalid exercise identifiers provided.'}), 400
    if len(set(sanitized_order)) != len(sanitized_order):
        return jsonify({'success': False, 'error': 'Duplicate exercise identifiers provided.'}), 400

    active = get_active_workout(user_id)
    if not active:
        return jsonify({'success': False, 'error': 'No active workout to update.'}), 404
    workout_payload = active.get('workout_data') or {}
    plan = workout_payload.get('plan')
    if not isinstance(plan, list):
        return jsonify({'success': False, 'error': 'Active workout plan is missing.'}), 400

    target_label = subcategory.lower()
    target_block = None
    for block in plan:
        label = str(block.get('subcategory') or '').strip()
        if label.lower() == target_label:
            target_block = block
            break
    if not target_block:
        return jsonify({'success': False, 'error': 'Workout category not found.'}), 404

    exercises = target_block.get('exercises') or []
    if len(exercises) != len(sanitized_order):
        return jsonify({'success': False, 'error': 'Exercise count mismatch. Refresh and try again.'}), 400

    lookup = {}
    for entry in exercises:
        workout_id = _exercise_entry_workout_id(entry)
        if workout_id is None:
            return jsonify({'success': False, 'error': 'An exercise is missing its identifier.'}), 400
        lookup[str(workout_id)] = entry
    if set(lookup.keys()) != set(sanitized_order):
        return jsonify({'success': False, 'error': 'Invalid exercise order submitted.'}), 400

    target_block['exercises'] = [lookup[wid] for wid in sanitized_order]

    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE active_workouts
                   SET workout_data = %s
                 WHERE user_id = %s
                """,
                (psycopg2.extras.Json(workout_payload), user_id),
            )
            conn.commit()

    return jsonify({'success': True})


@app.get('/training/workout/exercises/<int:workout_id>/alternatives')
@login_required
def personal_list_workout_alternatives(workout_id):
    user_id = session['user_id']
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                "SELECT role, subscription_type, exercise_history FROM users WHERE id = %s",
                (user_id,),
            )
            user_row = cursor.fetchone()
    if not _user_can_customize_personal_workout(user_row):
        return jsonify({'success': False, 'error': 'Trainer Pro access required.'}), 403

    subcategory = (request.args.get('subcategory') or '').strip()
    if not subcategory:
        return jsonify({'success': False, 'error': 'Workout category is required.'}), 400

    active = get_active_workout(user_id)
    if not active:
        return jsonify({'success': False, 'error': 'No active workout to update.'}), 404
    workout_payload = active.get('workout_data') or {}
    context, error = _resolve_refresh_context(workout_payload, subcategory, workout_id)
    if error:
        payload, status = error
        return jsonify(payload), status

    user_level = get_user_level(user_row.get('exercise_history'))
    query, params = _build_alternate_exercise_query(
        user_id,
        subcategory,
        user_level,
        context['existing_ids'],
        context['equipment_clause'],
        context['equipment_params'],
        context['use_cardio_override'],
        context['restrict_barbell'],
        context['restrict_dumbbell'],
        random_order=False,
    )
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(query, params)
            rows = cursor.fetchall() or []

    formatted = [_format_exercise(subcategory, row) for row in rows]
    return jsonify({
        'success': True,
        'exercises': formatted,
        'subcategory': context['target_block'].get('subcategory') or subcategory,
    })


@app.post('/training/workout/exercises/<int:workout_id>/refresh')
@login_required
def personal_refresh_workout_exercise(workout_id):
    user_id = session['user_id']
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                "SELECT role, subscription_type, exercise_history FROM users WHERE id = %s",
                (user_id,),
            )
            user_row = cursor.fetchone()
    if not _user_can_customize_personal_workout(user_row):
        return jsonify({'success': False, 'error': 'Trainer Pro access required.'}), 403

    payload = request.get_json(silent=True) or {}
    subcategory = (payload.get('subcategory') or '').strip()
    if not subcategory:
        return jsonify({'success': False, 'error': 'Workout category is required.'}), 400
    replacement_id_raw = payload.get('replacement_workout_id')
    replacement_workout_id = None
    if replacement_id_raw not in (None, ''):
        try:
            replacement_workout_id = int(replacement_id_raw)
        except (TypeError, ValueError):
            return jsonify({'success': False, 'error': 'Invalid alternate exercise selected.'}), 400
        if replacement_workout_id <= 0:
            return jsonify({'success': False, 'error': 'Invalid alternate exercise selected.'}), 400

    active = get_active_workout(user_id)
    if not active:
        return jsonify({'success': False, 'error': 'No active workout to update.'}), 404
    workout_payload = active.get('workout_data') or {}
    context, error = _resolve_refresh_context(workout_payload, subcategory, workout_id)
    if error:
        payload, status = error
        return jsonify(payload), status
    if replacement_workout_id and replacement_workout_id in context['existing_ids']:
        return jsonify({'success': False, 'error': 'That exercise is already in this workout.'}), 400

    user_level = get_user_level(user_row.get('exercise_history'))
    query, params = _build_alternate_exercise_query(
        user_id,
        subcategory,
        user_level,
        context['existing_ids'],
        context['equipment_clause'],
        context['equipment_params'],
        context['use_cardio_override'],
        context['restrict_barbell'],
        context['restrict_dumbbell'],
        selected_workout_id=replacement_workout_id,
        random_order=replacement_workout_id is None,
    )

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(query, params)
            replacement_row = cursor.fetchone()
        if not replacement_row:
            error_msg = (
                'Selected exercise is no longer available.'
                if replacement_workout_id
                else "No alternates match your level or equipment setup right now."
            )
            return jsonify({'success': False, 'error': error_msg}), 404

        formatted_exercise = _format_exercise(subcategory, replacement_row)
        exercises = context['exercises']
        replacement_index = context['replacement_index']
        exercises[replacement_index] = _apply_formatted_exercise(
            exercises[replacement_index],
            formatted_exercise,
        )

        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE active_workouts
                   SET workout_data = %s
                 WHERE user_id = %s
                """,
                (psycopg2.extras.Json(workout_payload), user_id),
            )
        conn.commit()

    return jsonify({
        'success': True,
        'exercise': formatted_exercise,
        'workout_id': formatted_exercise.get('workout_id'),
        'subcategory': context['target_block'].get('subcategory') or subcategory,
    })


@app.post('/trainer/clients/<int:client_id>/workout/reorder')
@login_required
def trainer_reorder_client_workout_exercises(client_id):
    trainer_id = session['user_id']
    trainer = _require_trainer(trainer_id)
    if not trainer:
        return jsonify({'success': False, 'error': 'Trainer access required.'}), 403

    payload = request.get_json(silent=True) or {}
    subcategory = (payload.get('subcategory') or '').strip()
    order_list = payload.get('order')
    if not subcategory or not isinstance(order_list, list) or not order_list:
        return jsonify({'success': False, 'error': 'Invalid reorder payload.'}), 400

    sanitized_order = []
    for value in order_list:
        key = str(value).strip()
        if not key:
            continue
        sanitized_order.append(key)
    if len(sanitized_order) != len(order_list):
        return jsonify({'success': False, 'error': 'Invalid exercise identifiers provided.'}), 400
    if len(set(sanitized_order)) != len(sanitized_order):
        return jsonify({'success': False, 'error': 'Duplicate exercise identifiers provided.'}), 400

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute("SELECT trainer_id FROM users WHERE id = %s", (client_id,))
            client_row = cursor.fetchone()
    if not client_row:
        return jsonify({'success': False, 'error': 'Client not found.'}), 404
    is_admin = (trainer.get('role') or '').lower() == 'admin'
    if client_row.get('trainer_id') != trainer_id and not is_admin:
        return jsonify({'success': False, 'error': 'You do not have access to that client.'}), 403

    active = get_active_workout(client_id)
    if not active:
        return jsonify({'success': False, 'error': 'No active workout to update.'}), 404
    workout_payload = active.get('workout_data') or {}
    plan = workout_payload.get('plan')
    if not isinstance(plan, list):
        return jsonify({'success': False, 'error': 'Active workout plan is missing.'}), 400

    target_label = subcategory.lower()
    target_block = None
    for block in plan:
        label = str(block.get('subcategory') or '').strip()
        if label.lower() == target_label:
            target_block = block
            break
    if not target_block:
        return jsonify({'success': False, 'error': 'Workout category not found.'}), 404

    exercises = target_block.get('exercises') or []
    if len(exercises) != len(sanitized_order):
        return jsonify({'success': False, 'error': 'Exercise count mismatch. Refresh and try again.'}), 400

    lookup = {}
    for entry in exercises:
        workout_id = _exercise_entry_workout_id(entry)
        if workout_id is None:
            return jsonify({'success': False, 'error': 'An exercise is missing its identifier.'}), 400
        key = str(workout_id)
        lookup[key] = entry
    if set(lookup.keys()) != set(sanitized_order):
        return jsonify({'success': False, 'error': 'Invalid exercise order submitted.'}), 400

    target_block['exercises'] = [lookup[wid] for wid in sanitized_order]

    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE active_workouts
                   SET workout_data = %s
                 WHERE user_id = %s
                """,
                (psycopg2.extras.Json(workout_payload), client_id),
            )
            conn.commit()

    return jsonify({'success': True})


@app.get('/trainer/clients/<int:client_id>/workout/exercises/<int:workout_id>/alternatives')
@login_required
def trainer_list_client_workout_alternates(client_id, workout_id):
    trainer_id = session['user_id']
    trainer = _require_trainer(trainer_id)
    if not trainer:
        return jsonify({'success': False, 'error': 'Trainer access required.'}), 403

    subcategory = (request.args.get('subcategory') or '').strip()
    if not subcategory:
        return jsonify({'success': False, 'error': 'Workout category is required.'}), 400

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                "SELECT trainer_id, exercise_history FROM users WHERE id = %s",
                (client_id,),
            )
            client_row = cursor.fetchone()
    if not client_row:
        return jsonify({'success': False, 'error': 'Client not found.'}), 404
    is_admin = (trainer.get('role') or '').lower() == 'admin'
    if client_row.get('trainer_id') != trainer_id and not is_admin:
        return jsonify({'success': False, 'error': 'You do not have access to that client.'}), 403

    active = get_active_workout(client_id)
    if not active:
        return jsonify({'success': False, 'error': 'No active workout to update.'}), 404
    workout_payload = active.get('workout_data') or {}
    context, error = _resolve_refresh_context(workout_payload, subcategory, workout_id)
    if error:
        payload, status = error
        return jsonify(payload), status

    user_level = get_user_level(client_row.get('exercise_history'))
    query, params = _build_alternate_exercise_query(
        client_id,
        subcategory,
        user_level,
        context['existing_ids'],
        context['equipment_clause'],
        context['equipment_params'],
        context['use_cardio_override'],
        context['restrict_barbell'],
        context['restrict_dumbbell'],
        random_order=False,
    )
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(query, params)
            rows = cursor.fetchall() or []

    formatted = [_format_exercise(subcategory, row) for row in rows]
    return jsonify({
        'success': True,
        'exercises': formatted,
        'subcategory': context['target_block'].get('subcategory') or subcategory,
    })


@app.post('/trainer/clients/<int:client_id>/workout/exercises/<int:workout_id>/refresh')
@login_required
def trainer_refresh_client_workout_exercise(client_id, workout_id):
    trainer_id = session['user_id']
    trainer = _require_trainer(trainer_id)
    if not trainer:
        return jsonify({'success': False, 'error': 'Trainer access required.'}), 403

    payload = request.get_json(silent=True) or {}
    subcategory = (payload.get('subcategory') or '').strip()
    if not subcategory:
        return jsonify({'success': False, 'error': 'Workout category is required.'}), 400
    replacement_id_raw = payload.get('replacement_workout_id')
    replacement_workout_id = None
    if replacement_id_raw not in (None, ''):
        try:
            replacement_workout_id = int(replacement_id_raw)
        except (TypeError, ValueError):
            return jsonify({'success': False, 'error': 'Invalid alternate exercise selected.'}), 400
        if replacement_workout_id <= 0:
            return jsonify({'success': False, 'error': 'Invalid alternate exercise selected.'}), 400

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                "SELECT trainer_id, exercise_history FROM users WHERE id = %s",
                (client_id,),
            )
            client_row = cursor.fetchone()
    if not client_row:
        return jsonify({'success': False, 'error': 'Client not found.'}), 404
    is_admin = (trainer.get('role') or '').lower() == 'admin'
    if client_row.get('trainer_id') != trainer_id and not is_admin:
        return jsonify({'success': False, 'error': 'You do not have access to that client.'}), 403

    active = get_active_workout(client_id)
    if not active:
        return jsonify({'success': False, 'error': 'No active workout to update.'}), 404
    workout_payload = active.get('workout_data') or {}
    context, error = _resolve_refresh_context(workout_payload, subcategory, workout_id)
    if error:
        payload, status = error
        return jsonify(payload), status
    if replacement_workout_id and replacement_workout_id in context['existing_ids']:
        return jsonify({'success': False, 'error': 'That exercise is already in this workout.'}), 400

    user_level = get_user_level(client_row.get('exercise_history'))
    query, params = _build_alternate_exercise_query(
        client_id,
        subcategory,
        user_level,
        context['existing_ids'],
        context['equipment_clause'],
        context['equipment_params'],
        context['use_cardio_override'],
        context['restrict_barbell'],
        context['restrict_dumbbell'],
        selected_workout_id=replacement_workout_id,
        random_order=replacement_workout_id is None,
    )

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(query, params)
            replacement_row = cursor.fetchone()
        if not replacement_row:
            error_msg = (
                'Selected exercise is no longer available.'
                if replacement_workout_id
                else "No alternates match this client's level or equipment setup right now."
            )
            return jsonify({'success': False, 'error': error_msg}), 404

        formatted_exercise = _format_exercise(subcategory, replacement_row)
        exercises = context['exercises']
        replacement_index = context['replacement_index']
        exercises[replacement_index] = _apply_formatted_exercise(
            exercises[replacement_index],
            formatted_exercise,
        )

        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE active_workouts
                   SET workout_data = %s
                 WHERE user_id = %s
                """,
                (psycopg2.extras.Json(workout_payload), client_id),
            )
        conn.commit()

    card_html = render_template(
        'components/exercise_card.html',
        exercise=formatted_exercise,
        subcategory_name=context['target_block'].get('subcategory') or subcategory,
        exercise_loop_index=replacement_index,
        notes_placeholder=WORKOUT_NOTES_PLACEHOLDER,
        client_id=client_id,
    )

    return jsonify({
        'success': True,
        'exercise': formatted_exercise,
        'workout_id': formatted_exercise.get('workout_id'),
        'card_html': card_html,
    })


@app.get('/exercise_progress/<int:workout_id>')
@login_required
def get_exercise_progress_route(workout_id):
    user_id = session['user_id']

    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT max_weight, max_reps
                  FROM user_exercise_progress
                 WHERE user_id = %s AND workout_id = %s
                LIMIT 1
                """,
                (user_id, workout_id),
            )
            row = cursor.fetchone()

    if not row:
        return jsonify({'success': True, 'max_weight': None, 'max_reps': None})

    max_weight = row[0]
    if max_weight is not None:
        try:
            max_weight = float(max_weight)
        except (TypeError, ValueError):
            max_weight = None

    max_reps = row[1]
    if max_reps is not None:
        try:
            max_reps = int(max_reps)
        except (TypeError, ValueError):
            max_reps = None

    return jsonify({'success': True, 'max_weight': max_weight, 'max_reps': max_reps})


@app.route('/complete_workout', methods=['POST'])
@login_required
def complete_workout():
    user_id = session['user_id']
    success, error, session_meta = _complete_workout_for_user(user_id)
    if not success:
        return jsonify({'success': False, 'error': error}), 400
    _attach_session_to_schedule(user_id, session_meta, as_self_session=True)
    return jsonify({'success': True})


def _load_last_workout_payload(user_id: int, category: str) -> tuple[OrderedDict | None, str, dict | None]:
    """Return the stored workout payload (if any), its label, and metadata."""
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT last_workout_details
                  FROM users
                 WHERE id = %s AND last_workout_completed = %s
                """,
                (user_id, category),
            )
            row = cursor.fetchone()

    if not row or not row[0]:
        return None, category, None

    try:
        workouts = json.loads(row[0], object_pairs_hook=OrderedDict)
    except (TypeError, json.JSONDecodeError):
        return None, category, None

    display_category = category
    metadata = None
    if isinstance(workouts, dict):
        metadata = workouts.pop('_meta', None)
        pretty_custom = None
        if isinstance(metadata, dict):
            pretty_custom = metadata.get('custom_categories_pretty')
        if isinstance(pretty_custom, list) and pretty_custom:
            display_category = ', '.join(pretty_custom)

    return workouts, display_category, metadata


def _fetch_session_subcategory_order(session_uuid: str) -> list[str] | None:
    """Attempt to reconstruct subcategory order for a session from exercise history."""
    if not session_uuid:
        return None
    try:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT subcategory
                      FROM user_exercise_history
                     WHERE session_id = %s
                       AND subcategory IS NOT NULL
                     ORDER BY id ASC
                    """,
                    (session_uuid,),
                )
                order = []
                for row in cursor:
                    subcat = row[0]
                    if not subcat:
                        continue
                    if subcat not in order:
                        order.append(subcat)
                return order or None
    except psycopg2.errors.UndefinedTable:
        return None
    except Exception:
        logging.exception("Failed to fetch subcategory order for session_id=%s", session_uuid)
        return None


@app.route('/workout_details/<category>', methods=['GET'])
@login_required
def workout_details(category):
    user_id = session['user_id']

    tz_info, _, _ = _resolve_request_timezone('workout_session')
    tz_info = tz_info or timezone.utc
    workouts, display_category, workout_meta = _load_last_workout_payload(user_id, category)
    completion_label = None
    completion_dt = None
    if isinstance(workout_meta, dict):
        completed_raw = workout_meta.get('completed_at')
        if completed_raw:
            try:
                completion_dt = datetime.fromisoformat(completed_raw)
                if completion_dt.tzinfo is None:
                    completion_dt = completion_dt.replace(tzinfo=timezone.utc)
                try:
                    localized_dt = completion_dt.astimezone(tz_info)
                except Exception:
                    localized_dt = completion_dt.astimezone()
                completion_dt = localized_dt
                completion_label = localized_dt.strftime("%B %d, %Y at %I:%M %p")
            except ValueError:
                completion_dt = None
                completion_label = None
    return render_template(
        'workout_details.html',
        category=category,
        display_category=display_category,
        workouts=workouts,
        workout_meta=workout_meta or {},
        completion_label=completion_label,
        completion_dt=completion_dt,
        back_url=url_for('home'),
    )



@app.route('/trainer/clients/<int:client_id>/workout_details/<category>', methods=['GET'])
@login_required
def trainer_client_workout_details(client_id, category):
    trainer = _require_trainer(session['user_id'])
    if not trainer:
        flash("Trainer access required.", "danger")
        return redirect(url_for('home'))

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                "SELECT id, trainer_id, name, last_name FROM users WHERE id = %s",
                (client_id,),
            )
            client = cursor.fetchone()

    if not client:
        flash("Client not found.", "danger")
        return redirect(url_for('trainer_dashboard'))

    if client.get('trainer_id') != trainer.get('id') and trainer.get('role') != 'admin':
        flash("You do not have access to that client's workouts.", "danger")
        return redirect(url_for('trainer_dashboard'))

    workouts, display_category, workout_meta = _load_last_workout_payload(client_id, category)
    tz_info, _, _ = _resolve_request_timezone('workout_session')
    tz_info = tz_info or timezone.utc

    def _localize_completion(dt: datetime | None) -> datetime | None:
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        try:
            return dt.astimezone(tz_info)
        except Exception:
            return dt

    completion_label = None
    completion_dt = None
    if isinstance(workout_meta, dict):
        completed_raw = workout_meta.get('completed_at')
        if completed_raw:
            try:
                completion_dt = datetime.fromisoformat(completed_raw)
                localized_dt = _localize_completion(completion_dt)
                if localized_dt:
                    completion_dt = localized_dt
                    completion_label = localized_dt.strftime("%B %d, %Y at %I:%M %p")
            except ValueError:
                completion_dt = None
                completion_label = None
    fallback_back_url = url_for('client_profile', client_id=client_id)
    back_url = _resolve_back_link(fallback_back_url)
    return render_template(
        'workout_details.html',
        category=category,
        display_category=display_category,
        workouts=workouts,
        workout_meta=workout_meta or {},
        completion_label=completion_label,
        completion_dt=completion_dt,
        back_url=back_url,
    )


@app.route('/workout_session/<session_id>', methods=['GET'])
@login_required
def workout_session_view(session_id):
    user_id = session['user_id']
    role = (session.get('role') or 'user').strip().lower()
    tz_info, _, _ = _resolve_request_timezone('workout_session')
    tz_info = tz_info or timezone.utc

    def _apply_subcategory_order(workout_mapping, meta):
        if not isinstance(workout_mapping, dict) or not isinstance(meta, dict):
            return workout_mapping
        order = meta.get('subcategory_order')
        if not isinstance(order, list) or not order:
            return workout_mapping
        ordered = OrderedDict()
        for key in order:
            if key in workout_mapping:
                ordered[key] = workout_mapping[key]
        for key, value in workout_mapping.items():
            if key not in ordered:
                ordered[key] = value
        return ordered

    try:
        session_uuid = uuid.UUID(str(session_id))
    except (ValueError, TypeError):
        abort(404)

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT client_id,
                       trainer_id,
                       session_payload,
                       session_category,
                       session_completed_at
                  FROM trainer_schedule
                 WHERE session_id = %s
                """,
                (str(session_uuid),),
            )
            row = cursor.fetchone()

    if not row:
        abort(404)

    client_id = row.get('client_id')
    trainer_owner_id = row.get('trainer_id')
    if role in {'trainer', 'admin'}:
        trainer = _require_trainer(user_id)
        if not trainer:
            flash("Trainer access required.", "danger")
            return redirect(url_for('home'))
        if role != 'admin' and trainer_owner_id != user_id:
            flash("You do not have access to that workout session.", "danger")
            return redirect(url_for('trainer_dashboard'))
        fallback_back_url = url_for('trainer_self_schedule_view')
    else:
        if client_id != user_id:
            abort(403)
        fallback_back_url = url_for('client_schedule_view')

    back_url = _resolve_back_link(fallback_back_url)

    raw_payload = row.get('session_payload')
    if raw_payload is None:
        flash("Workout details are unavailable for this session.", "warning")
        return redirect(back_url)

    if isinstance(raw_payload, str):
        try:
            payload = json.loads(raw_payload, object_pairs_hook=OrderedDict)
        except (TypeError, json.JSONDecodeError):
            payload = None
    else:
        payload = raw_payload

    if not payload:
        flash("Workout details are unavailable for this session.", "warning")
        return redirect(back_url)

    workouts = payload
    metadata = None
    if isinstance(payload, dict):
        workouts = OrderedDict(payload)
        metadata = workouts.pop('_meta', None)
        if not isinstance(metadata, dict):
            metadata = {}
        if not metadata.get('subcategory_order'):
            inferred_order = _fetch_session_subcategory_order(str(session_uuid))
            if inferred_order:
                metadata['subcategory_order'] = inferred_order
        workouts = _apply_subcategory_order(workouts, metadata)

    display_category = row.get('session_category')
    if isinstance(metadata, dict):
        pretty_custom = metadata.get('custom_categories_pretty')
        if isinstance(pretty_custom, list) and pretty_custom:
            display_category = ', '.join(pretty_custom)
        elif metadata.get('session_label'):
            display_category = metadata.get('session_label')
    if not display_category:
        display_category = 'Workout Session'

    completed_at = row.get('session_completed_at')
    completion_label = None
    if isinstance(completed_at, datetime):
        localized_completed = completed_at
        if localized_completed.tzinfo is None:
            localized_completed = localized_completed.replace(tzinfo=timezone.utc)
        try:
            localized_completed = localized_completed.astimezone(tz_info)
        except Exception:
            pass
        completion_label = localized_completed.strftime("%B %d, %Y at %I:%M %p")

    return render_template(
        'workout_details.html',
        category=row.get('session_category') or display_category,
        display_category=display_category,
        workouts=workouts,
        workout_meta=metadata or {},
        completion_label=completion_label,
        back_url=back_url,
    )


@app.route('/update_notes', methods=['POST'])
@login_required
def update_notes():
    data = request.get_json(silent=True) or {}
    workout_id_raw = data.get('workout_id')
    try:
        workout_id = int(str(workout_id_raw).strip())
    except (TypeError, ValueError):
        return jsonify({'success': False, 'error': 'Invalid workout id'}), 400

    notes_raw = data.get('notes')
    notes = None
    if notes_raw is not None:
        notes_text = str(notes_raw).strip()
        if notes_text:
            notes = notes_text

    user_id = session['user_id']
    result = _apply_notes_update(user_id, workout_id, notes)
    payload = result.get('notes', notes or '') if isinstance(result, dict) else (notes or '')
    return jsonify({'success': True, 'notes': payload})



@app.route('/update_pr', methods=['POST'])
@login_required
def update_pr():
    data = request.get_json() or {}
    user_id = session['user_id']
    workout_id = data.get('workout_id')
    if not workout_id:
        return jsonify({'success': False, 'error': 'Missing workout id'}), 400

    max_weight_raw = data.get('max_weight')
    max_reps_raw = data.get('max_reps')

    max_weight = None
    if isinstance(max_weight_raw, (int, float)):
        max_weight = float(max_weight_raw)
    elif isinstance(max_weight_raw, str) and max_weight_raw.strip():
        try:
            max_weight = float(max_weight_raw)
        except ValueError:
            max_weight = None

    max_reps = None
    if isinstance(max_reps_raw, (int, float)):
        max_reps = int(max_reps_raw)
    elif isinstance(max_reps_raw, str) and max_reps_raw.strip():
        try:
            max_reps = int(float(max_reps_raw))
        except ValueError:
            max_reps = None

    result = _apply_pr_update(user_id, int(workout_id), max_weight, max_reps)
    return jsonify(result)


@app.get('/exercise_history_data')
@login_required
def exercise_history_data():
    workout_id_raw = request.args.get('workout_id')
    try:
        workout_id = int(str(workout_id_raw).strip())
    except (TypeError, ValueError):
        return jsonify({'success': False, 'error': 'Invalid workout id'}), 400

    client_id_raw = request.args.get('client_id')
    client_id = None
    target_user_id = session['user_id']
    trainer = None

    if client_id_raw:
        trainer = _require_trainer(session['user_id'])
        if not trainer:
            return jsonify({'success': False, 'error': 'Trainer access required'}), 403
        try:
            client_id = int(str(client_id_raw).strip())
        except (TypeError, ValueError):
            return jsonify({'success': False, 'error': 'Invalid client id'}), 400

    window_key = (request.args.get('window') or '').strip().lower()
    if window_key not in HISTORY_WINDOW_DELTAS:
        window_key = DEFAULT_HISTORY_WINDOW
    window_delta = HISTORY_WINDOW_DELTAS.get(window_key)
    max_points = HISTORY_WINDOW_LIMITS.get(window_key, 200)
    now_utc = datetime.now(timezone.utc)

    valid_window_sequence = ['90d', '1y', 'all']
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            if client_id:
                linked = _ensure_trainer_client_link(cursor, session['user_id'], client_id, trainer.get('role'))
                if not linked:
                    return jsonify({'success': False, 'error': 'Access denied'}), 403
                target_user_id = client_id

            cursor.execute(
                """
                SELECT id, name, category
                  FROM workouts
                 WHERE id = %s
                """,
                (workout_id,),
            )
            workout_row = cursor.fetchone()
            if not workout_row:
                return jsonify({'success': False, 'error': 'Workout not found'}), 404

            workout_name = workout_row.get('name')
            history_query = [
                "SELECT weight, reps, recorded_at",
                "  FROM user_exercise_history",
                " WHERE user_id = %s",
                "   AND workout_id = %s",
            ]
            params = [target_user_id, workout_id]
            history_query.append("   AND (source IS NULL OR source = 'pr_update')")
            if window_delta:
                window_start = now_utc - window_delta
                history_query.append("   AND recorded_at >= %s")
                params.append(window_start)
            history_query.append(" ORDER BY recorded_at ASC")
            if max_points:
                history_query.append(" LIMIT %s")
                params.append(max_points)
            cursor.execute("\n".join(history_query), params)
            history_rows = cursor.fetchall() or []

            used_window = window_key
            if not history_rows:
                for candidate in valid_window_sequence:
                    if candidate == window_key:
                        continue
                    candidate_delta = HISTORY_WINDOW_DELTAS.get(candidate)
                    candidate_limit = HISTORY_WINDOW_LIMITS.get(candidate)
                    candidate_query = [
                        "SELECT weight, reps, recorded_at",
                        "  FROM user_exercise_history",
                        " WHERE user_id = %s",
                        "   AND workout_id = %s",
                    ]
                    candidate_params = [target_user_id, workout_id]
                    candidate_query.append("   AND (source IS NULL OR source = 'pr_update')")
                    if candidate_delta:
                        candidate_start = now_utc - candidate_delta
                        candidate_query.append("   AND recorded_at >= %s")
                        candidate_params.append(candidate_start)
                    candidate_query.append(" ORDER BY recorded_at ASC")
                    if candidate_limit:
                        candidate_query.append(" LIMIT %s")
                        candidate_params.append(candidate_limit)
                    cursor.execute("\n".join(candidate_query), candidate_params)
                    history_rows = cursor.fetchall() or []
                    if history_rows:
                        used_window = candidate
                        window_delta = candidate_delta
                        max_points = candidate_limit
                        break

    category_label = (workout_row.get('category') or '').strip()
    is_cardio = category_label.lower() == 'cardio'
    is_time_hold = _is_plank_exercise(workout_name)
    is_bodyweight_name = _is_bodyweight_exercise(workout_name)
    use_rep_trend = bool(is_bodyweight_name and not is_cardio and not is_time_hold)
    history_payload = []
    best_value = None

    for row in history_rows:
        weight_val = _coerce_float(row.get('weight'))
        reps_numeric = _coerce_float(row.get('reps'))
        reps_value = None
        if reps_numeric is not None:
            if is_cardio:
                reps_value = reps_numeric
            elif is_time_hold:
                reps_value = int(round(reps_numeric))
            else:
                reps_value = int(round(reps_numeric))

        est_one_rm = None if (is_cardio or use_rep_trend) else _estimate_one_rep_max(weight_val, reps_value)
        if is_cardio or is_time_hold or use_rep_trend:
            display_value = reps_value
        else:
            display_value = est_one_rm

        recorded_at = row.get('recorded_at')
        if recorded_at and hasattr(recorded_at, 'isoformat'):
            try:
                if recorded_at.tzinfo is None:
                    recorded_at = recorded_at.replace(tzinfo=timezone.utc)
                recorded_label = recorded_at.isoformat()
            except Exception:
                recorded_label = str(recorded_at)
        else:
            recorded_label = None

        history_entry = {
            'recorded_at': recorded_label,
            'weight': weight_val,
            'reps': reps_value,
            'est_one_rm': est_one_rm,
            'display_value': display_value,
        }

        history_payload.append(history_entry)
        if display_value is not None:
            if best_value is None:
                best_value = display_value
            elif is_cardio or is_time_hold:
                best_value = max(best_value, display_value)
            else:
                best_value = max(best_value, display_value)

    raw_history = history_payload[:]
    history_payload = _downsample_history(raw_history, max_points or len(raw_history))

    summary = None
    if raw_history:
        latest_entry = raw_history[-1]
        summary = {
            'latest_weight': latest_entry.get('weight'),
            'latest_reps': latest_entry.get('reps'),
            'latest_one_rm': latest_entry.get('est_one_rm'),
            'latest_value': latest_entry.get('display_value'),
            'best_value': best_value,
        }

    if is_cardio:
        chart_label = "Time (min)"
        chart_unit = "min"
        value_mode = "cardio"
    elif is_time_hold:
        chart_label = "Hold Time"
        chart_unit = "seconds"
        value_mode = "time_hold"
    elif use_rep_trend:
        chart_label = "Best Reps"
        chart_unit = "reps"
        value_mode = "bodyweight_reps"
    else:
        chart_label = "Estimated 1RM (lbs)"
        chart_unit = "lbs"
        value_mode = "strength"

    return jsonify({
        'success': True,
        'workout': {
            'id': workout_id,
            'name': workout_row.get('name'),
            'category': workout_row.get('category'),
        },
        'is_cardio': is_cardio,
        'is_time_hold': is_time_hold,
        'is_bodyweight_reps': use_rep_trend,
        'value_mode': value_mode,
        'chart_label': chart_label,
        'chart_unit': chart_unit,
        'history': history_payload,
        'summary': summary,
        'window': used_window,
    })


@app.route("/search")
@login_required
def search():
    user_id = session['user_id']
    check_and_downgrade_trial(user_id)
    check_subscription_expiry(user_id)
    query = request.args.get("q", "").strip()

    if not query:
        flash("Please enter a search term.", "warning")
        return render_template(
            "search_results.html",
            query="",
            results=[],
            NOTES_PLACEHOLDER=WORKOUT_NOTES_PLACEHOLDER,
        )

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT w.id AS workout_id,
                       w.name,
                       w.description,
                       w.category,
                       w.image_exercise_start,
                       w.image_exercise_end,
                       uep.max_weight,
                       uep.max_reps,
                       uep.notes
                 FROM workouts w
            LEFT JOIN user_exercise_progress uep
                   ON w.id = uep.workout_id
                  AND uep.user_id = %s
                WHERE LOWER(w.name) LIKE LOWER(%s)
                 ORDER BY CASE w.movement_type
                              WHEN 'compound' THEN 1
                              WHEN 'accessory' THEN 2
                              ELSE 3
                          END,
                          w.name
                """,
                (user_id, f"%{query}%"),
            )
            results = cursor.fetchall() or []

    return render_template(
        "search_results.html",
        query=query,
        results=results,
        NOTES_PLACEHOLDER=WORKOUT_NOTES_PLACEHOLDER,
    )


@app.route('/update_goals', methods=['POST'])
@login_required
def update_goals():
    user_id = session['user_id']
    fitness_goals = request.form.getlist('fitness_goals')

    if len(fitness_goals) < 1 or len(fitness_goals) > 2:
        flash("Please select 1 or 2 goals.", "danger")
        return redirect(url_for('home'))

    fitness_goals_str = ", ".join([goal.title() for goal in fitness_goals])

    try:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE users
                    SET fitness_goals = %s
                    WHERE id = %s
                """, (fitness_goals_str, user_id))
                conn.commit()

        flash("Your goals have been updated!", "success")
    except Exception as e:
        flash(f"An error occurred: {e}", "danger")

    return redirect(url_for('home'))


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email_input = (request.form.get('email') or '').strip().lower()

        # Uniform message 
        generic_msg = "If an account with that email exists and is verified, a reset link has been sent."

        if not email_input:
            flash("Please enter your email.", "danger")
            return render_template("forgot_password.html")

        try:
            with get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT id, email_verified
                        FROM users
                        WHERE lower(email) = lower(%s)
                        LIMIT 1
                    """, (email_input,))
                    row = cur.fetchone()

                if not row:
                    flash(generic_msg, "info")
                    return redirect(url_for('login'))

                user_id, email_verified = row

                if not email_verified:
                    flash(generic_msg, "info")
                    return redirect(url_for('login'))

                # Issue single-use reset token
                raw_token, expires_at, _token_id = issue_single_use_token(conn, user_id, "reset_password", RESET_TTL_HOURS)
                reset_url = url_for("reset_password", token=raw_token, _external=True)
                conn.commit()

                try:
                    # Send to the email the user entered (matches DB row)
                    send_password_reset_email(email_input, reset_url)
                except Exception:
                    current_app.logger.exception("Failed sending password reset email")

                flash(generic_msg, "info")
                return redirect(url_for('login'))

        except Exception:
            current_app.logger.exception("Error during forgot_password")
            flash("Something went wrong. Please try again.", "danger")
            return render_template("forgot_password.html")

    # GET
    return render_template("forgot_password.html")


@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    token = ((request.args.get('token') if request.method == 'GET' else request.form.get('token')) or '').strip()
    if not token:
        flash("Missing or invalid reset link.", "danger")
        return redirect(url_for('forgot_password'))

    if request.method == 'GET':
        with get_connection() as conn:
            info = validate_token(conn, token, "reset_password")
            if not info:
                flash("Your reset link is invalid or has expired. Please request a new one.", "danger")
                return redirect(url_for('forgot_password'))
            expires_label = fmt_utc(info["expires_at"])
        return render_template("reset_password.html", token=token, expires_at=expires_label)

    # POST
    password = request.form.get('password') or ""
    confirmation = request.form.get('confirmation') or ""

    try:
        with get_connection() as conn:
            conn.autocommit = False

            # Validate first so we always have expires_label for re-render
            info = validate_token(conn, token, "reset_password")
            if not info:
                conn.rollback()
                flash("Your reset link is invalid or has expired. Please request a new one.", "danger")
                return redirect(url_for('forgot_password'))

            expires_label = fmt_utc(info["expires_at"])
            user_id = info["user_id"]

            # Now do your checks and include expires_at on errors
            if len(password) < 8:
                flash("Password must be at least 8 characters.", "danger")
                return render_template("reset_password.html", token=token, expires_at=expires_label)
            if password != confirmation:
                flash("Passwords do not match.", "danger")
                return render_template("reset_password.html", token=token, expires_at=expires_label)

            pwd_hash = generate_password_hash(password)
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE users
                       SET hash = %s,
                           updated_at = now(),
                           session_version = COALESCE(session_version, 0) + 1
                     WHERE id = %s
                """, (pwd_hash, user_id))

            mark_token_used(conn, info["token_id"])
            conn.commit()

        flash("Password updated! Please log in.", "success")
        return redirect(url_for('login'))

    except Exception:
        current_app.logger.exception("Error resetting password")
        flash("Something went wrong. Please try again.", "danger")
        return render_template("reset_password.html", token=token, expires_at=locals().get('expires_label'))


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    user_id = session.get('user_id')

    # Fetch user info to pre-fill the form
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT username, name, last_name, email, age, weight, height_feet, height_inches,
                       gender, exercise_history, fitness_goals, injury, injury_details, cardio_restriction,
                       commitment, additional_notes, form_completed, workout_duration,
                       subscription_type, trial_end_date, trainer_id
                FROM users
                WHERE id = %s
            """, (user_id,))
            row = cursor.fetchone()
    columns = ['username', 'name', 'last_name', 'email', 'age', 'weight', 'height_feet', 'height_inches',
               'gender', 'exercise_history', 'fitness_goals', 'injury', 'injury_details', 'cardio_restriction',
               'commitment', 'additional_notes', 'form_completed', 'workout_duration',
               'subscription_type', 'trial_end_date', 'trainer_id']

    user = dict(zip(columns, row)) if row else {k: "" for k in columns}
    for k in columns:
        if user.get(k) is None:
            user[k] = ""

    form_completed = bool(user.get('form_completed'))
    injury_payload_db = parse_injury_payload(user.get('injury'))
    cardio_restriction_prefill = bool(user.get('cardio_restriction')) or injury_payload_db['cardio']
    injury_regions_prefill = injury_payload_db['regions']
    injury_details_prefill = user.get('injury_details') or ''
    injury_status_prefill = 'Yes' if (injury_regions_prefill or cardio_restriction_prefill or injury_details_prefill.strip()) else 'No'
    injury_excluded_categories_prefill = compute_injury_exclusions(injury_regions_prefill, cardio_restriction_prefill)
    template_prefill_kwargs = dict(
        injury_regions=injury_regions_prefill,
        injury_details=injury_details_prefill,
        injury_status=injury_status_prefill,
        cardio_restriction=cardio_restriction_prefill,
        injury_excluded_categories=injury_excluded_categories_prefill,
        injury_skipped_subcategories=[],
    )

    def render_settings_template(
        user_context,
        form_completed_flag,
        *,
        injury_regions=None,
        injury_details='',
        injury_status='No',
        cardio_restriction=False,
        injury_excluded_categories=None,
        injury_skipped_subcategories=None,
    ):
        regions = injury_regions or []
        details = injury_details or ''
        status = injury_status or 'No'
        cardio_flag = bool(cardio_restriction)
        excluded = injury_excluded_categories
        if excluded is None:
            excluded = compute_injury_exclusions(regions, cardio_flag)
        skipped = injury_skipped_subcategories or []
        return render_template(
            'settings.html',
            user=user_context,
            form_completed=form_completed_flag,
            injury_regions=regions,
            injury_details=details,
            injury_status=status,
            cardio_restriction=cardio_flag,
            injury_excluded_categories=sorted(excluded),
            injury_skipped_subcategories=skipped,
            current_date=date.today(),
        )

    if request.method == 'POST':
            # Get form fields
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Check if user is trying to change password only (and hasn't completed form)
        password_only = password and not all([
            request.form.get('username'),
            request.form.get('name'),
            request.form.get('last_name'),
            request.form.get('age'),
            request.form.get('weight'),
            request.form.get('height_feet'),
            request.form.get('height_inches'),
            request.form.get('gender'),
            request.form.get('exercise_history'),
            request.form.get('commitment'),
        ])

        # Handle password-only update (regardless of form_completed status)
        if password_only:
            if password != confirm_password:
                flash("Passwords do not match.", "danger")
                return render_settings_template(user, form_completed, **template_prefill_kwargs)
            if len(password) < 8:
                flash("Password must be at least 8 characters long.", "danger")
                return render_settings_template(user, form_completed, **template_prefill_kwargs)
            if not any(char.isupper() for char in password):
                flash("Password must include at least one uppercase letter.", "danger")
                return render_settings_template(user, form_completed, **template_prefill_kwargs)
            if not any(char in "!@#$%^&*()-_+=<>?/{}~" for char in password):
                flash("Password must include at least one special character.", "danger")
                return render_settings_template(user, form_completed, **template_prefill_kwargs)

            hashed_password = generate_password_hash(password)
            with get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("UPDATE users SET hash = %s, session_version=session_version+1 WHERE id = %s", (hashed_password, user_id))
                    conn.commit()

            flash("Password updated successfully!", "success")
            return render_settings_template(user, form_completed, **template_prefill_kwargs)
    
        # Get all other form fields
        username = (request.form.get('username') or '').strip()
        name     = (request.form.get('name') or '').strip()
        last_name = (request.form.get('last_name') or '').strip()
        email    = normalize_email(request.form.get('email') or None) 
        age = int_or_none(request.form.get('age'))
        weight = float_or_none(request.form.get('weight'))
        height_feet = int_or_none(request.form.get('height_feet'))
        height_inches = inches_0_11_or_none(request.form.get('height_inches'))
        gender = request.form.get('gender')
        exercise_history = request.form.get('exercise_history')
        fitness_goals = request.form.getlist('fitness_goals')
        fitness_goals_cleaned = ", ".join(goal.strip() for goal in fitness_goals if goal.strip())
        injury_status = request.form.get('injury_status') or 'No'
        injury_payload_raw = request.form.get('injury') or '[]'
        injury_details = (request.form.get('injury_details') or '').strip()
        cardio_restriction_input = (request.form.get('cardio_restriction') == 'yes')
        injury_payload_form = parse_injury_payload(injury_payload_raw)
        injury_regions_selected = injury_payload_form['regions']
        cardio_restriction_value = cardio_restriction_input or injury_payload_form['cardio']
        commitment = request.form.get('commitment')
        additional_notes = request.form.get('additional_notes')

        workout_duration_raw = request.form.get('workout_duration')
        allowed_durations = {"20", "30", "45", "60"}
        if workout_duration_raw not in allowed_durations:
            flash("Please select a valid workout duration.", "danger")
            return render_settings_template(
                user,
                form_completed,
                injury_regions=injury_regions_selected or injury_regions_prefill,
                injury_details=injury_details or injury_details_prefill,
                injury_status=injury_status,
                cardio_restriction=cardio_restriction_value,
                injury_excluded_categories=compute_injury_exclusions(injury_regions_selected, cardio_restriction_value),
            )
        workout_duration = int(workout_duration_raw)

        duration_only = (workout_duration_raw in allowed_durations) and not any([
            request.form.get('username'),
            request.form.get('name'),
            request.form.get('last_name'),
            request.form.get('age'),
            request.form.get('weight'),
            request.form.get('height_feet'),
            request.form.get('height_inches'),
            request.form.get('gender'),
            request.form.get('exercise_history'),
            request.form.get('commitment'),
            len(request.form.getlist('fitness_goals')) > 0,
            injury_status.strip().lower() == 'yes',
            bool(injury_regions_selected),
            bool(injury_details),
            request.form.get('additional_notes'),
            password, confirm_password,
        ])

        if duration_only:
            with get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("UPDATE users SET workout_duration = %s WHERE id = %s",
                                (workout_duration, user_id))
                    conn.commit()
            flash("Preferred workout duration updated!", "success")

            # Refetch to refresh the page with updated value
            with get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        SELECT username, name, last_name, email, age, weight, height_feet, height_inches,
                            gender, exercise_history, fitness_goals, injury, injury_details, cardio_restriction,
                            commitment, additional_notes, form_completed, workout_duration,
                            subscription_type, trial_end_date
                        FROM users
                        WHERE id = %s
                    """, (user_id,))
                    row = cursor.fetchone()

            user = dict(zip(columns, row)) if row else {k: "" for k in columns}
            for k in columns:
                if user.get(k) is None:
                    user[k] = ""
            form_completed = bool(user.get('form_completed'))

            injury_payload_updated = parse_injury_payload(user.get('injury'))
            cardio_restriction_updated = bool(user.get('cardio_restriction')) or injury_payload_updated['cardio']
            injury_regions_updated = injury_payload_updated['regions']
            injury_details_updated = user.get('injury_details') or ''
            injury_status_updated = 'Yes' if (injury_regions_updated or cardio_restriction_updated or injury_details_updated.strip()) else 'No'
            injury_excluded_categories_updated = compute_injury_exclusions(injury_regions_updated, cardio_restriction_updated)

            return render_settings_template(
                user,
                form_completed,
                injury_regions=injury_regions_updated,
                injury_details=injury_details_updated,
                injury_status=injury_status_updated,
                cardio_restriction=cardio_restriction_updated,
                injury_excluded_categories=injury_excluded_categories_updated,
            )

        # Validate required fields
        missing_required = (
            not username or
            not name or
            not last_name or
            age is None or
            weight is None or
            height_feet is None or
            height_inches is None or  # <-- allows 0, only None fails
            not gender or
            not exercise_history or
            not commitment
        )

        if missing_required:
            flash("Please fill out all required fields.", "danger")
            return render_settings_template(
                user,
                form_completed,
                injury_regions=injury_regions_selected or injury_regions_prefill,
                injury_details=injury_details or injury_details_prefill,
                injury_status=injury_status,
                cardio_restriction=cardio_restriction_value,
                injury_excluded_categories=compute_injury_exclusions(injury_regions_selected, cardio_restriction_value),
            )

        if not (1 <= len(fitness_goals) <= 2):
            flash("Please select 1 or 2 fitness goals.", "danger")
            return render_settings_template(
                user,
                form_completed,
                injury_regions=injury_regions_selected or injury_regions_prefill,
                injury_details=injury_details or injury_details_prefill,
                injury_status=injury_status,
                cardio_restriction=cardio_restriction_value,
                injury_excluded_categories=compute_injury_exclusions(injury_regions_selected, cardio_restriction_value),
            )

        injury_status_normalized = injury_status.strip().title()
        if injury_status_normalized not in ("Yes", "No"):
            flash("Please let us know if you currently have injuries or restrictions.", "danger")
            return render_settings_template(
                user,
                form_completed,
                injury_regions=injury_regions_selected or injury_regions_prefill,
                injury_details=injury_details or injury_details_prefill,
                injury_status=injury_status,
                cardio_restriction=cardio_restriction_value,
                injury_excluded_categories=compute_injury_exclusions(injury_regions_selected, cardio_restriction_value),
            )

        if injury_status_normalized == "No":
            injury_regions_selected = []
            cardio_restriction_value = False
            injury_details = ''
        else:
            if not injury_regions_selected and not cardio_restriction_value:
                flash("Please choose at least one area FitBaseAI should skip.", "danger")
                return render_settings_template(
                    user,
                    form_completed,
                    injury_regions=injury_regions_selected,
                    injury_details=injury_details,
                    injury_status=injury_status_normalized,
                    cardio_restriction=cardio_restriction_value,
                    injury_excluded_categories=compute_injury_exclusions(injury_regions_selected, cardio_restriction_value),
                )
            if not injury_details:
                flash("Please share a few details about the injury or restriction.", "danger")
                return render_settings_template(
                    user,
                    form_completed,
                    injury_regions=injury_regions_selected,
                    injury_details=injury_details,
                    injury_status=injury_status_normalized,
                    cardio_restriction=cardio_restriction_value,
                    injury_excluded_categories=compute_injury_exclusions(injury_regions_selected, cardio_restriction_value),
                )

        injury_json = json.dumps(injury_regions_selected)
        injury_status = injury_status_normalized
        is_injury_free = (injury_status == 'No')

        # Validate password if provided
        hashed_password = None
        if password:
            if password != confirm_password:
                flash("Passwords do not match.", "danger")
                return render_settings_template(
                    user,
                    form_completed,
                    injury_regions=injury_regions_selected or injury_regions_prefill,
                    injury_details=injury_details,
                    injury_status=injury_status,
                    cardio_restriction=cardio_restriction_value,
                    injury_excluded_categories=compute_injury_exclusions(injury_regions_selected, cardio_restriction_value),
                )
            if len(password) < 8:
                flash("Password must be at least 8 characters long.", "danger")
                return render_settings_template(
                    user,
                    form_completed,
                    injury_regions=injury_regions_selected or injury_regions_prefill,
                    injury_details=injury_details,
                    injury_status=injury_status,
                    cardio_restriction=cardio_restriction_value,
                    injury_excluded_categories=compute_injury_exclusions(injury_regions_selected, cardio_restriction_value),
                )
            if not any(char.isupper() for char in password):
                flash("Password must include at least one uppercase letter.", "danger")
                return render_settings_template(
                    user,
                    form_completed,
                    injury_regions=injury_regions_selected or injury_regions_prefill,
                    injury_details=injury_details,
                    injury_status=injury_status,
                    cardio_restriction=cardio_restriction_value,
                    injury_excluded_categories=compute_injury_exclusions(injury_regions_selected, cardio_restriction_value),
                )
            if not any(char in "!@#$%^&*()-_+=<>?/{}~" for char in password):
                flash("Password must include at least one special character.", "danger")
                return render_settings_template(
                    user,
                    form_completed,
                    injury_regions=injury_regions_selected or injury_regions_prefill,
                    injury_details=injury_details,
                    injury_status=injury_status,
                    cardio_restriction=cardio_restriction_value,
                    injury_excluded_categories=compute_injury_exclusions(injury_regions_selected, cardio_restriction_value),
                )

            hashed_password = generate_password_hash(password)

        # Check for duplicate username/email
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT id FROM users WHERE lower(username) = lower(%s) AND id != %s",
                    (username, user_id)
                )
                if cursor.fetchone():
                    flash("That username is already taken.", "danger")
                    return render_settings_template(
                        user,
                        form_completed,
                        injury_regions=injury_regions_selected or injury_regions_prefill,
                        injury_details=injury_details,
                        injury_status=injury_status,
                        cardio_restriction=cardio_restriction_value,
                        injury_excluded_categories=compute_injury_exclusions(injury_regions_selected, cardio_restriction_value),
                    )

                if email:
                    cursor.execute(
                        "SELECT id FROM users WHERE lower(email) = lower(%s) AND id != %s",
                        (email, user_id)
                    )
                    if cursor.fetchone():
                        flash("That email is already in use.", "danger")
                        return render_settings_template(
                            user,
                            form_completed,
                            injury_regions=injury_regions_selected or injury_regions_prefill,
                            injury_details=injury_details,
                            injury_status=injury_status,
                            cardio_restriction=cardio_restriction_value,
                            injury_excluded_categories=compute_injury_exclusions(injury_regions_selected, cardio_restriction_value),
                        )
                    
            new_form_completed = all([
                age is not None,
                weight is not None,
                height_feet is not None,
                height_inches is not None,
                bool(gender),
                bool(exercise_history),
                bool(fitness_goals_cleaned),
                bool(commitment),
            ])

            # Update everything (account info, training info, and optionally password)
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE users
                    SET username = %s, name = %s, last_name = %s, email = %s,
                        age = %s, weight = %s, height_feet = %s, height_inches = %s,
                        gender = %s, exercise_history = %s, fitness_goals = %s,
                        injury = %s, injury_details = %s, cardio_restriction = %s, commitment = %s,
                        additional_notes = %s, form_completed = %s, workout_duration = %s,
                        injury_free_since = CASE WHEN %s THEN COALESCE(injury_free_since, CURRENT_DATE) ELSE NULL END
                    WHERE id = %s
                """, (
                    username, name, last_name, email, age, weight, height_feet,
                    height_inches, gender, exercise_history, fitness_goals_cleaned,
                    injury_json, injury_details, cardio_restriction_value, commitment, additional_notes, new_form_completed, 
                    workout_duration, is_injury_free,
                    user_id
                ))

                if hashed_password:
                    cursor.execute("UPDATE users SET hash = %s, session_version=session_version+1 WHERE id = %s", (hashed_password, user_id))

                conn.commit()

        flash("Settings updated successfully!", "success")

        # Refetch updated user data
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT username, name, last_name, email, age, weight, height_feet, height_inches,
                        gender, exercise_history, fitness_goals, injury, injury_details, cardio_restriction,
                        commitment, additional_notes, form_completed, workout_duration,
                        subscription_type, trial_end_date
                    FROM users
                    WHERE id = %s
                """, (user_id,))
                row = cursor.fetchone()
        user = dict(zip(columns, row)) if row else {k: "" for k in columns}
        for k in columns:
            if user.get(k) is None:
                user[k] = ""
        form_completed = new_form_completed
        updated_payload = parse_injury_payload(user.get('injury'))
        updated_cardio_flag = bool(user.get('cardio_restriction')) or updated_payload['cardio']
        updated_regions = updated_payload['regions']
        updated_details = user.get('injury_details') or ''
        updated_status = 'Yes' if (updated_regions or updated_cardio_flag or updated_details.strip()) else 'No'
        updated_exclusions = compute_injury_exclusions(updated_regions, updated_cardio_flag)

        return render_settings_template(
            user,
            form_completed,
            injury_regions=updated_regions,
            injury_details=updated_details,
            injury_status=updated_status,
            cardio_restriction=updated_cardio_flag,
            injury_excluded_categories=updated_exclusions,
        )

    return render_settings_template(user, form_completed, **template_prefill_kwargs)


@app.route('/admin/users', methods=['GET'])
@login_required
def admin_users():
    user_id = session['user_id']

    if not is_admin(user_id):
        return "Access denied", 403

    with get_connection() as conn:
        with conn.cursor() as cursor:
            search_term = request.args.get('search', '')
            if search_term:
                query = """
                    SELECT id, username, name, last_name, email, subscription_type, email_verified, role, form_completed, workouts_completed
                    FROM users
                    WHERE 
                        username ILIKE %s OR
                        name ILIKE %s OR 
                        last_name ILIKE %s OR 
                        email ILIKE %s OR 
                        (name || ' ' || last_name) ILIKE %s
                    ORDER BY id
                """
                like_term = f'%{search_term}%'
                cursor.execute(query, (like_term, like_term, like_term, like_term, like_term))
            else:
                cursor.execute("""
                    SELECT id, username, name, last_name, email, subscription_type, email_verified, role, form_completed, workouts_completed
                    FROM users
                    ORDER BY id
                """)
            users = cursor.fetchall()

            cursor.execute("""
                SELECT COUNT(*) AS total_users,
                       COALESCE(SUM(workouts_completed), 0) AS total_workouts_completed
                FROM users
            """)
            counts_row = cursor.fetchone() or (0, 0)
            total_users = counts_row[0] or 0
            total_workouts_completed = counts_row[1] or 0

    return render_template(
        'admin_dashboard.html',
        users=users,
        search_term=search_term,
        total_users=total_users,
        total_workouts_completed=total_workouts_completed
    )


@app.context_processor
def inject_user_role():
    uid = session.get('user_id')
    return dict(is_admin=is_admin(uid) if uid else False)


@app.route('/admin/user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def admin_user_profile(user_id):
    # Check admin access
    if not is_admin(session['user_id']):
        return "Access denied", 403

    # Handle update
    if request.method == 'POST':
        username_clean = (request.form.get('username') or '').strip() or None
        email_clean = (request.form.get('email') or '').strip().lower() or None

        goals = request.form.getlist('fitness_goals')
        fitness_goals_str = ", ".join(g.title().strip() for g in goals) or None

        injury_status_input = (request.form.get('injury_status') or 'No').strip().title()
        injury_payload_raw = request.form.get('injury') or '[]'
        injury_details = (request.form.get('injury_details') or '').strip()
        cardio_input_flag = request.form.get('cardio_restriction') == 'yes'
        injury_payload_form = parse_injury_payload(injury_payload_raw)
        injury_regions_selected = injury_payload_form['regions']
        cardio_restriction_value = cardio_input_flag or injury_payload_form['cardio']

        if injury_status_input not in ('Yes', 'No'):
            flash("Please specify if the user currently has injuries or restrictions.", "danger")
            return redirect(url_for('admin_user_profile', user_id=user_id))

        if injury_status_input == 'No':
            injury_regions_selected = []
            cardio_restriction_value = False
            injury_details = ''
        else:
            if not injury_regions_selected and not cardio_restriction_value:
                flash("Select at least one restricted area or cardio when injury status is Yes.", "danger")
                return redirect(url_for('admin_user_profile', user_id=user_id))
            if not injury_details:
                flash("Please add a brief note describing the injury or restriction.", "danger")
                return redirect(url_for('admin_user_profile', user_id=user_id))

        injury_json = json.dumps(injury_regions_selected)
        is_injury_free = (injury_status_input == 'No')

        data = {
            'name': request.form.get('name') or None,
            'last_name': request.form.get('last_name') or None,
            'role': request.form.get('role'),
            'subscription_type': request.form.get('subscription_type'),
            'email_verified': 'email_verified' in request.form,
            'form_completed': 'form_completed' in request.form,
            'age': request.form.get('age') or None,
            'weight': request.form.get('weight') or None,
            'height_feet': request.form.get('height_feet') or None,
            'height_inches': request.form.get('height_inches') or None,
            'gender': request.form.get('gender'),
            'exercise_history': request.form.get('exercise_history'),
            'injury': injury_json,
            'injury_details': injury_details,
            'cardio_restriction': cardio_restriction_value,
            'commitment': request.form.get('commitment'),
            'additional_notes': request.form.get('additional_notes'),
            'workouts_completed': request.form.get('workouts_completed') or 0,
            'sessions_remaining': int_or_none(request.form.get('sessions_remaining'))
        }

        trainer_id_raw = (request.form.get('trainer_id') or '').strip()
        try:
            trainer_id_val = int(trainer_id_raw) if trainer_id_raw else None
        except ValueError:
            trainer_id_val = None

        with get_connection() as conn:
            with conn.cursor() as cursor:
                update_query = """
                    UPDATE users SET
                        username = %s,
                        name = %s,
                        last_name = %s,
                        email = %s,
                        role = %s,
                        subscription_type = %s,
                        email_verified = %s,
                        form_completed = %s,
                        age = %s,
                        weight = %s,
                        height_feet = %s,
                        height_inches = %s,
                        gender = %s,
                        exercise_history = %s,
                        fitness_goals = %s,
                        injury = %s,
                        injury_details = %s,
                        cardio_restriction = %s,
                        commitment = %s,
                        additional_notes = %s,
                        injury_free_since = CASE WHEN %s THEN COALESCE(injury_free_since, CURRENT_DATE) ELSE NULL END,
                        workouts_completed = %s,
                        sessions_remaining = %s,
                        trainer_id = %s
                    WHERE id = %s
                """
                try:
                    cursor.execute(update_query, (
                        username_clean, data['name'], data['last_name'], email_clean,
                        data['role'], data['subscription_type'], data['email_verified'],
                        data['form_completed'], data['age'], data['weight'],
                        data['height_feet'], data['height_inches'], data['gender'],
                        data['exercise_history'], fitness_goals_str, data['injury'],
                        data['injury_details'], data['cardio_restriction'], data['commitment'], data['additional_notes'],
                        is_injury_free,
                        data['workouts_completed'], data['sessions_remaining'], trainer_id_val, user_id
                    ))
                    conn.commit()
                    flash("User profile updated successfully.", "success")
                    return redirect(url_for('admin_user_profile', user_id=user_id)) 
                except psycopg2.errors.UniqueViolation:
                    conn.rollback()
                    flash("Username or email already in use.", "danger")
                    return redirect(url_for('admin_user_profile', user_id=user_id))

    # Load user info
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            user = cursor.fetchone()
            if not user:
                return "User not found", 404

            cursor.execute(
                """
                SELECT id, name, last_name, username, role
                  FROM users
                 WHERE role IN ('trainer', 'admin')
                 ORDER BY role DESC, name NULLS LAST, last_name NULLS LAST, username
                """
            )
            trainers = cursor.fetchall() or []

    invite_url = request.args.get('invite_url')
    invite_expires_in = request.args.get('invite_expires_in')
    injury_payload = parse_injury_payload(user.get('injury'))
    cardio_flag = bool(user.get('cardio_restriction')) or injury_payload['cardio']
    injury_regions = injury_payload['regions']
    injury_details = (user.get('injury_details') or '').strip()
    injury_status = 'Yes' if (injury_regions or cardio_flag or injury_details) else 'No'
    injury_excluded_categories = compute_injury_exclusions(injury_regions, cardio_flag)

    return render_template(
        'admin_user_profile.html',
        user=user,
        invite_url=invite_url,
        invite_expires_in=invite_expires_in,
        trainers=trainers,
        injury_status=injury_status,
        injury_regions=injury_regions,
        injury_details=injury_details,
        cardio_restriction=cardio_flag,
        injury_excluded_categories=sorted(injury_excluded_categories),
        injury_skipped_subcategories=[],
    )


@app.route('/admin/users/add', methods=['GET'])
@login_required
def admin_add_user():
    if not is_admin(session['user_id']):
        return "Access denied", 403
    invite_url = request.args.get('invite_url')
    invite_expires_in = request.args.get('invite_expires_in')
    return render_template('admin_add_user.html',
                           invite_url=invite_url,
                           invite_expires_in=invite_expires_in)


@app.route("/admin/users/invite", methods=["GET", "POST"])
@login_required
def admin_invite_user():
    # reuse existing admin check
    if not is_admin(session['user_id']):
        return "Access denied", 403

    if request.method == "GET":
        return render_template("admin_add_user.html")

    # POST
    action = (request.form.get("action") or "copy_link").strip().lower()
    if action not in {"send_invite", "copy_link"}:
        action = "copy_link"
    name = (request.form.get("name") or "").strip()
    last_name = (request.form.get("last_name") or "").strip()
    email = normalize_email(request.form.get("email") or "")
    role = (request.form.get("role") or "user").strip()
    subscription = (request.form.get("subscription_type") or "free").strip()
    admin_note = (request.form.get("admin_note") or "").strip() or None

    # validations → use global toast categories (message first, category second)
    if not email:
        flash("Email is required.", "danger")
        return render_template("admin_add_user.html")
    if role not in ALLOWED_ROLES:
        flash("Invalid role selected.", "danger")
        return render_template("admin_add_user.html")
    if subscription not in ALLOWED_SUBS:
        flash("Invalid subscription type selected.", "danger")
        return render_template("admin_add_user.html")

    invited_by = session.get("user_id")

    try:
        with get_connection() as conn:
            conn.autocommit = False

            try:
                user_id = upsert_invited_user(
                    conn, email=email, first=name, last=last_name,
                    role=role, subscription=subscription, invited_by=invited_by
                )
            except ValueError as ve:
                conn.rollback()
                flash(str(ve), "danger")
                return render_template("admin_add_user.html")

            raw_token, expires_at, _token_id = issue_single_use_token(conn, user_id, "invite", INVITE_TTL_HOURS)
            invite_url = url_for("accept_invite", token=raw_token, _external=True)
            invite_expires_in = fmt_utc(expires_at)

            conn.commit()

    except Exception:
        current_app.logger.exception("DB error while inviting user")
        flash("Database error while creating the invite.", "danger")
        return render_template("admin_add_user.html")

    if action == "send_invite":
        try:
            send_invite_email(
                to_email=email, 
                first_name=name or "there",
                invite_url=invite_url, 
                admin_note=admin_note
            )
            flash(f"Invite sent to {email}.", "success")
            return redirect(url_for(
                "admin_add_user",
                invite_url=invite_url,
                invite_expires_in=invite_expires_in
            ))
        except Exception:
            current_app.logger.exception("Failed to send invite email")
            flash("Invite created, but email failed to send. Copy the link below and share it manually.", "warning")
            return redirect(url_for(
                "admin_add_user",
                invite_url=invite_url,
                invite_expires_in=invite_expires_in
            ))

    # Default (copy_link)
    flash("Invite link created.", "success")
    return redirect(url_for(
        "admin_add_user",
        invite_url=invite_url,
        invite_expires_in=invite_expires_in
    ))


@app.get("/accept-invite")
def accept_invite():
    # If someone is already logged in, send them home
    if session.get("user_id"):
        return redirect(url_for("home"))

    token = (request.args.get("token") or "").strip()
    if not token:
        flash("Missing invite token.", "danger")
        return redirect(url_for("login"))

    with get_connection() as conn:
        info = validate_token(conn, token, "invite")
        if not info:
            flash("Your invite link is invalid or has expired. Ask the admin to resend it.", "danger")
            return redirect(url_for("login"))

        # Show the invited email on the page
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT email, name, last_name FROM users WHERE id=%s", (info["user_id"],))
            user = cur.fetchone()

    return render_template("accept_invite.html", token=token, email=(user["email"] if user else None))


@app.post("/accept-invite")
def accept_invite_post():
    token = (request.form.get("token") or "").strip()
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    password2 = request.form.get("password2") or ""

    if not token:
        flash("Missing invite token.", "danger")
        return redirect(url_for("login"))
    if not username:
        flash("Please choose a username.", "danger")
        return redirect(url_for("accept_invite", token=token))
    if len(username) < 3 or len(username) > 50:
        flash("Username must be 3–50 characters.", "danger")
        return redirect(url_for("accept_invite", token=token))
    if len(password) < 8:
        flash("Password must be at least 8 characters.", "danger")
        return redirect(url_for("accept_invite", token=token))
    if password != password2:
        flash("Passwords do not match.", "danger")
        return redirect(url_for("accept_invite", token=token))

    try:
        with get_connection() as conn:
            conn.autocommit = False

            info = validate_token(conn, token, "invite")
            if not info:
                conn.rollback()
                flash("Your invite link is invalid or has expired. Ask the admin to resend it.", "danger")
                return redirect(url_for("login"))

            user_id = info["user_id"]

            # Friendly check first
            if not username_available(conn, username):
                conn.rollback()
                flash("That username is taken. Please pick another.", "danger")
                return redirect(url_for("accept_invite", token=token))

            pwd_hash = generate_password_hash(password)

            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE users
                       SET username = %s,
                           hash = %s,
                           status = 'active',
                           email_verified = true,
                           email_verified_at = now(),
                           accepted_at = now(),
                           updated_at = now()
                     WHERE id = %s
                """, (username, pwd_hash, user_id))

            mark_token_used(conn, info["token_id"])
            conn.commit()

            # Log them in
            session.clear()
            session["user_id"] = user_id

            flash("Welcome! Your account is ready.", "success")
            return redirect(url_for("training"))  

    except psycopg2.errors.UniqueViolation:
        # In case someone raced us and took the username between check & update
        flash("That username is taken. Please pick another.", "danger")
        return redirect(url_for("accept_invite", token=token))
    except Exception:
        current_app.logger.exception("Error accepting invite")
        flash("Something went wrong while activating your account.", "danger")
        return redirect(url_for("accept_invite", token=token))


@app.route('/trainer_link', methods=['GET', 'POST'])
def trainer_link_accept():
    token_source = request.form if request.method == 'POST' else request.args
    token = (token_source.get('token') or '').strip()
    if not token:
        flash('Missing trainer invite token.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'GET':
        with get_connection() as conn:
            info = validate_token(conn, token, 'trainer_link')
            if not info:
                flash('This trainer invite link is invalid or has expired.', 'danger')
                return redirect(url_for('login'))
            invite = _get_trainer_link_invite(conn, info['token_id'])
            if not invite or invite.get('client_id') != info['user_id']:
                flash('This trainer invite link is invalid.', 'danger')
                return redirect(url_for('login'))
            if invite.get('accepted_at'):
                flash('This trainer invite link has already been used.', 'warning')
                return redirect(url_for('login'))

        trainer_stub = {
            'name': invite.get('trainer_name'),
            'last_name': invite.get('trainer_last_name'),
            'username': invite.get('trainer_username'),
        }
        return render_template(
            'trainer_link_accept.html',
            token=token,
            trainer_display_name=_trainer_display_name(trainer_stub),
            sessions_summary=_format_sessions_note(invite.get('sessions_remaining')),
        )

    try:
        with get_connection() as conn:
            conn.autocommit = False
            info = validate_token(conn, token, 'trainer_link')
            if not info:
                conn.rollback()
                flash('This trainer invite link is invalid or has expired.', 'danger')
                return redirect(url_for('login'))
            invite = _get_trainer_link_invite(conn, info['token_id'])
            if not invite or invite.get('client_id') != info['user_id']:
                conn.rollback()
                flash('This trainer invite link is invalid.', 'danger')
                return redirect(url_for('login'))
            if invite.get('accepted_at'):
                conn.rollback()
                flash('This trainer invite has already been accepted.', 'warning')
                return redirect(url_for('login'))

            trainer_stub = {
                'name': invite.get('trainer_name'),
                'last_name': invite.get('trainer_last_name'),
                'username': invite.get('trainer_username'),
            }
            client_stub = {
                'name': invite.get('client_name'),
                'last_name': invite.get('client_last_name'),
                'username': invite.get('client_username'),
            }
            trainer_display = _trainer_display_name(trainer_stub)
            sessions_note = _format_sessions_note(invite.get('sessions_remaining'))
            client_display = _client_display_name(client_stub)

            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute(
                    "SELECT trainer_id FROM users WHERE id = %s FOR UPDATE",
                    (invite['client_id'],)
                )
                client_row = cursor.fetchone()
                if not client_row:
                    conn.rollback()
                    flash('We could not find that account anymore.', 'danger')
                    return redirect(url_for('login'))
                existing_trainer = client_row.get('trainer_id')
                if existing_trainer and existing_trainer != invite['trainer_id']:
                    conn.rollback()
                    flash('Your account is already connected to another trainer.', 'danger')
                    return redirect(url_for('login'))

                set_clauses = ['trainer_id = %s', 'updated_at = now()']
                params = [invite['trainer_id']]
                if invite.get('sessions_remaining') is not None:
                    set_clauses.insert(1, 'sessions_remaining = %s')
                    params.append(invite['sessions_remaining'])
                params.append(invite['client_id'])
                cursor.execute(
                    f"UPDATE users SET {', '.join(set_clauses)} WHERE id = %s",
                    params,
                )
                cursor.execute(
                    "UPDATE trainer_link_invites SET accepted_at = now() WHERE id = %s",
                    (invite['id'],),
                )

            mark_token_used(conn, info['token_id'])
            conn.commit()

    except Exception:
        current_app.logger.exception('Failed processing trainer link invite')
        flash('We could not complete that request. Please ask your trainer to resend the invite.', 'danger')
        return redirect(url_for('login'))

    if invite.get('trainer_email'):
        try:
            send_trainer_link_connected_email(
                to_email=invite['trainer_email'],
                trainer_display_name=trainer_display,
                client_display_name=client_display,
            )
        except Exception:
            current_app.logger.exception('Failed sending trainer link confirmation email')

    success_message = f"You're now connected with {trainer_display}."
    if sessions_note:
        success_message += f" {sessions_note}"
    flash(success_message, 'success')
    if session.get('user_id') == invite['client_id']:
        return redirect(url_for('home'))
    return redirect(url_for('login'))


@app.post('/admin/user/<int:user_id>/resend-invite')
@login_required
def admin_resend_invite(user_id):
    if not is_admin(session['user_id']):
        return "Access denied", 403

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT id, email, name, status FROM users WHERE id=%s", (user_id,))
            user = cur.fetchone()
            if not user:
                flash("User not found.", "danger")
                return redirect(url_for('admin_users'))
            if user['status'] not in ('invited','pending'):
                flash("Resend Invite is only available for invited or pending users.", "warning")
                return redirect(url_for('admin_user_profile', user_id=user_id))
            if not user['email']:
                flash("This user has no email on file.", "danger")
                return redirect(url_for('admin_user_profile', user_id=user_id))

        # Issue token (also invalidates any unused previous ones)
        try:
            raw, exp, _token_id = issue_single_use_token(conn, user_id, 'invite', INVITE_TTL_HOURS)
            invite_url = url_for('accept_invite', token=raw, _external=True)
            invite_expires_in = fmt_utc(exp)
            conn.commit()
        except Exception:
            current_app.logger.exception("Failed to create invite token")
            flash("Could not create a fresh invite link.", "danger")
            return redirect(url_for('admin_user_profile', user_id=user_id))

    try:
        send_invite_email(to_email=user['email'], first_name=user['name'] or "there",
                          invite_url=invite_url, admin_note=None)
        flash("Invite email sent.", "success")
        return redirect(url_for('admin_user_profile', user_id=user_id))
    except Exception:
        current_app.logger.exception("Failed to send invite email")
        flash("Invite created, but email failed to send. Copy the link below and share it manually.", "warning")
        # Redirect back with the link visible on the page
        return redirect(url_for('admin_user_profile', user_id=user_id,
                                invite_url=invite_url,
                                invite_expires_in=invite_expires_in))


@app.post('/admin/user/<int:user_id>/copy-invite')
@login_required
def admin_copy_invite(user_id):
    if not is_admin(session['user_id']):
        return "Access denied", 403

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT id, status FROM users WHERE id=%s", (user_id,))
            user = cur.fetchone()
            if not user:
                flash("User not found.", "danger")
                return redirect(url_for('admin_users'))
            if user['status'] not in ('invited', 'pending'):
                flash("Copy Invite Link is only available for invited or pending users.", "warning")
                return redirect(url_for('admin_user_profile', user_id=user_id))

        try:
            raw, exp, _token_id = issue_single_use_token(conn, user_id, 'invite', INVITE_TTL_HOURS)
            invite_url = url_for('accept_invite', token=raw, _external=True)
            invite_expires_in = fmt_utc(exp)
            conn.commit()
        except Exception:
            current_app.logger.exception("Failed to create invite token")
            flash("Could not create a fresh invite link.", "danger")
            return redirect(url_for('admin_user_profile', user_id=user_id))

    flash("Invite link created.", "success")
    return redirect(url_for('admin_user_profile', user_id=user_id,
                            invite_url=invite_url,
                            invite_expires_in=invite_expires_in))


@app.post('/admin/user/<int:user_id>/disable')
@login_required
def admin_disable_user(user_id):
    if not is_admin(session['user_id']):
        return "Access denied", 403

    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("UPDATE users SET status='disabled', session_version=session_version+1 WHERE id=%s", (user_id,))
        conn.commit()

    flash("User disabled and signed out of active sessions.", "success")
    return redirect(url_for('admin_user_profile', user_id=user_id))


@app.post('/admin/user/<int:user_id>/reactivate')
@login_required
def admin_reactivate_user(user_id):
    if not is_admin(session['user_id']):
        return "Access denied", 403

    # Safety: only reactivate if the user has a password set
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT hash, email_verified FROM users WHERE id=%s", (user_id,))
            row = cur.fetchone()
            if not row:
                flash("User not found.", "danger")
                return redirect(url_for('admin_users'))

            if not row['hash']:
                flash("Cannot reactivate: user has no password set. Send an invite instead.", "warning")
                return redirect(url_for('admin_user_profile', user_id=user_id))

        with conn.cursor() as cur:
            cur.execute("UPDATE users SET status='active' WHERE id=%s", (user_id,))
            conn.commit()

    flash("User reactivated.", "success")
    return redirect(url_for('admin_user_profile', user_id=user_id))


@app.post('/admin/user/<int:user_id>/delete')
@login_required
def admin_delete_user(user_id):
    if not is_admin(session['user_id']):
        return "Access denied", 403

    if session['user_id'] == user_id:
        flash("You cannot delete your own account.", "warning")
        return redirect(url_for('admin_user_profile', user_id=user_id))

    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM users WHERE id=%s", (user_id,))
        if cur.rowcount == 0:
            flash("User not found.", "warning")
            conn.commit()
            return redirect(url_for('admin_users'))
        conn.commit()

    flash("User account deleted.", "success")
    return redirect(url_for('admin_users'))


@app.context_processor
def inject_global_context():
    current_year = datetime.now().year
    current_date = date.today()
    user = None

    if 'user_id' in session:
        with get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("SELECT * FROM users WHERE id = %s", (session['user_id'],))
                user = cursor.fetchone()

    return {
        "current_year": current_year,
        "current_date": current_date,
        "user": user,
        "user_has_schedule_access": _user_has_schedule_access(user),
    }


@app.route("/terms")
def terms():
    return render_template("terms.html")


@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


@app.route("/plans")
def plan_options():
    is_logged_in = 'user_id' in session
    premium_cta = url_for('upgrade', plan='premium') if is_logged_in else url_for('register')
    pro_cta = url_for('upgrade', plan='pro') if is_logged_in else url_for('trainer_register')
    return render_template(
        "plan_options.html",
        is_logged_in=is_logged_in,
        premium_cta=premium_cta,
        pro_cta=pro_cta
    )


@app.route('/upgrade')
@login_required
def upgrade():
    user_id = session["user_id"]
    plan = (request.args.get("plan") or "premium").strip().lower()
    if plan not in PLAN_PRICE_LOOKUP:
        flash("Invalid plan selection.", "danger")
        return redirect(url_for('settings'))

    target_price_id = PLAN_PRICE_LOOKUP.get(plan)
    if not target_price_id:
        flash("Selected plan is not available right now. Please contact support.", "danger")
        return redirect(url_for('settings'))

    # Initialize defaults 
    user_email = None
    full_name = None
    stripe_customer_id = None

    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT email, name, last_name, stripe_customer_id 
                FROM users 
                WHERE id = %s
            """, (user_id,))
            result = cursor.fetchone()
            if result:
                user_email = result[0]
                full_name = f"{result[1]} {result[2]}"
                stripe_customer_id = result[3]

    if not user_email:
        flash("A valid email is required to upgrade.", "danger")
        return redirect(url_for('settings'))
    
    try:
        # Create Stripe customer (only if they don't already have a customer ID)
        if not stripe_customer_id:
            customer = stripe.Customer.create(
                email=user_email,
                name=full_name,
                metadata={"user_id": user_id}
            )
            stripe_customer_id = customer.id

            # Save stripe_customer_id to DB
            with get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        UPDATE users SET stripe_customer_id = %s WHERE id = %s
                    """, (stripe_customer_id, user_id))
                    conn.commit()

        # Create a Stripe Checkout Session
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            customer=stripe_customer_id,
            line_items=[{
                'price': target_price_id,
                'quantity': 1,
            }],
            mode='subscription',
            success_url=url_for('upgrade_success', _external=True),
            cancel_url=url_for('settings', _external=True),
            metadata={'user_id': user_id, 'plan': plan}
        )

        return redirect(checkout_session.url)
    
    except Exception as e:
        flash(f"Error creating Stripe checkout: {e}", "danger")
        return redirect(url_for('settings'))


@app.route("/stripe/webhook", methods=["POST"])
def stripe_webhook():
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get("Stripe-Signature")

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, webhook_secret
        )
    except ValueError:
        return "Invalid payload", 400
    except stripe.error.SignatureVerificationError:
        return "Invalid signature", 400

    print(f"📩 Webhook received: {event['type']}")

    # Handle successful checkout
    if event['type'] == 'checkout.session.completed':
        session_data = event['data']['object']
        print("✅ Handling checkout.session.completed")

        user_id = session_data.get('metadata', {}).get('user_id')
        plan = session_data.get('metadata', {}).get('plan', 'premium')
        if plan not in PLAN_PRICE_LOOKUP:
            plan = 'premium'
        stripe_customer_id = session_data.get('customer')

        if user_id and stripe_customer_id:
            with get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        UPDATE users
                        SET subscription_type = %s,
                            role = CASE 
                                WHEN %s = 'pro' AND role != 'admin' THEN 'trainer'
                                WHEN %s != 'pro' AND role != 'admin' THEN 'user'
                                ELSE role 
                            END,
                            trial_end_date = NULL,
                            subscription_cancel_at = NULL,
                            session_version = COALESCE(session_version, 0) + 1
                        WHERE id = %s
                    """, (plan, plan, plan, user_id))
                    conn.commit()

    elif event['type'] == 'customer.subscription.updated':
        sub_data = event['data']['object']
        stripe_customer_id = sub_data.get('customer')
        cancel_at = sub_data.get('cancel_at')  # Will be None if user resumed
        cancel_at_period_end = sub_data.get('cancel_at_period_end', False)
        price_id = None
        items = (sub_data.get('items') or {}).get('data') or []
        for item in items:
            price_obj = item.get('price')
            if isinstance(price_obj, dict):
                price_id = price_obj.get('id')
            else:
                price_id = price_obj
            if price_id:
                break

        plan_from_price = PRICE_PLAN_LOOKUP.get(price_id)
        if plan_from_price and stripe_customer_id:
            with get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        UPDATE users
                        SET subscription_type = %s,
                            role = CASE 
                                WHEN %s = 'pro' AND role != 'admin' THEN 'trainer'
                                WHEN %s != 'pro' AND role != 'admin' THEN 'user'
                                ELSE role
                            END,
                            session_version = COALESCE(session_version, 0) + 1
                        WHERE stripe_customer_id = %s
                    """, (plan_from_price, plan_from_price, plan_from_price, stripe_customer_id))
                    conn.commit()

        if cancel_at_period_end:
            print("⚠️ Subscription set to cancel at period end")
            print("🗓️ Will cancel at:", datetime.fromtimestamp(cancel_at, tz=timezone.utc))

            with get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        UPDATE users
                        SET subscription_cancel_at = to_timestamp(%s)
                        WHERE stripe_customer_id = %s
                    """, (cancel_at, stripe_customer_id))
                    conn.commit()
                    print("📆 subscription_cancel_at saved to DB")

        else:
            # Subscription was resumed (cancelation undone)
            print("✅ Subscription resume detected — clearing cancel_at")
            with get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        UPDATE users
                        SET subscription_cancel_at = NULL
                        WHERE stripe_customer_id = %s
                    """, (stripe_customer_id,))
                    conn.commit()
                    print("🧼 subscription_cancel_at cleared in DB")
    
    elif event['type'] == 'customer.subscription.deleted':
        stripe_customer_id = event['data']['object'].get('customer')
        print("❌ Subscription fully canceled")

        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE users
                    SET subscription_type = 'free',
                        role = CASE 
                            WHEN role != 'admin' THEN 'user'
                            ELSE role
                        END,
                        trial_end_date = NULL,
                        subscription_cancel_at = NULL,
                        session_version = COALESCE(session_version, 0) + 1
                    WHERE stripe_customer_id = %s
                """, (stripe_customer_id,))
                conn.commit()
                print("🔻 Downgraded user to free tier in DB")

    return jsonify({'status': 'success'}), 200


@app.route('/upgrade-success')
@login_required
def upgrade_success():
    flash("🎉 You've successfully upgraded your account!", "success")
    return redirect(url_for('settings'))


@app.route('/customer-portal')
@login_required
def customer_portal():
    stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
    user_id = session["user_id"]

    # Get Stripe Customer ID from your DB
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT stripe_customer_id FROM users WHERE id = %s", (user_id,))
            result = cursor.fetchone()
            if result and result[0]:
                stripe_customer_id = result[0]
            else:
                flash("Unable to access Stripe customer info.", "danger")
                return redirect(url_for('settings'))

    # Create the session
    session_payload = {
        "customer": stripe_customer_id,
        "return_url": url_for('settings', _external=True),
    }
    if stripe_portal_configuration_id:
        session_payload["configuration"] = stripe_portal_configuration_id

    stripe_portal_session = stripe.billing_portal.Session.create(**session_payload)

    return redirect(stripe_portal_session.url)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5500, debug=True)
