from functools import wraps
from flask import session, redirect, url_for, flash
import os, psycopg2, re, json
import hmac, secrets, hashlib, math
import logging
from psycopg2 import connect
from psycopg2.extras import RealDictCursor, Json
from urllib.parse import urlparse
from dotenv import load_dotenv
from collections import OrderedDict
from decimal import Decimal
from datetime import datetime, timedelta, timezone

load_dotenv()
logger = logging.getLogger(__name__)

def get_connection():
    return psycopg2.connect(os.getenv("DATABASE_URL"))

ADMIN_EMAILS = [e.strip().lower() for e in os.getenv('ADMIN_EMAILS', '').split(',') if e.strip()]
DEFAULT_CATALOG_GYM_LOOKUP = {
    "name": "Western Racquet and Fitness Club",
    "city": "Green Bay",
    "state": "Wisconsin",
    "country": "United States",
}
DEFAULT_CATALOG_GYM_ID = None


# Define the workout structure
WORKOUT_STRUCTURE = {
    1: {  # Beginner
        "Chest and Triceps": {"CHEST": 4, "TRICEPS": 3},
        "Back and Biceps": {"BACK": 4, "BICEPS": 3},
        "Shoulders and Abs": {"SHOULDERS": 4, "ABS": 3},
        "Arms": {"SHOULDERS": 3, "BICEPS": 3, "TRICEPS": 3},
        "Legs": {"LEGS": 6},
        "Upper Body": {"CHEST": 2, "BACK": 2, "SHOULDERS": 2, "BICEPS": 1, "TRICEPS": 1},
        "Full Body": {"LEGS": 2, "CHEST": 2, "BACK": 2, "SHOULDERS": 2, "BICEPS": 1, "TRICEPS": 1, "ABS": 1},
        "Cardio": {"CARDIO": 2},
    },
    2: {  # Intermediate
        "Chest and Triceps": {"CHEST": 4, "TRICEPS": 3},
        "Back and Biceps": {"BACK": 4, "BICEPS": 3},
        "Shoulders and Abs": {"SHOULDERS": 4, "ABS": 3},
        "Arms": {"SHOULDERS": 3, "BICEPS": 3, "TRICEPS": 3},
        "Legs": {"LEGS": 6},
        "Upper Body": {"CHEST": 2, "BACK": 2, "SHOULDERS": 2, "BICEPS": 1, "TRICEPS": 1},
        "Full Body": {"LEGS": 2, "CHEST": 2, "BACK": 2, "SHOULDERS": 2, "BICEPS": 1, "TRICEPS": 1, "ABS": 1},
        "Cardio": {"CARDIO": 2},
    },
    3: {  # Advanced
        "Chest and Triceps": {"CHEST": 5, "TRICEPS": 4},
        "Back and Biceps": {"BACK": 5, "BICEPS": 4},
        "Shoulders and Abs": {"SHOULDERS": 5, "ABS": 4},
        "Arms": {"SHOULDERS": 4, "BICEPS": 4, "TRICEPS": 4},
        "Legs": {"LEGS": 6},
        "Upper Body": {"CHEST": 2, "BACK": 2, "SHOULDERS": 2, "BICEPS": 2, "TRICEPS": 2},
        "Full Body": {"LEGS": 2, "CHEST": 2, "BACK": 2, "SHOULDERS": 2, "BICEPS": 2, "TRICEPS": 2, "ABS": 2},
        "Cardio": {"CARDIO": 3},
    },
}

CUSTOM_WORKOUT_TOKEN = "Custom Gym Workout"
HOME_WORKOUT_TOKEN = "Custom Home Workout"
CUSTOMIZABLE_WORKOUT_TOKENS = {CUSTOM_WORKOUT_TOKEN, HOME_WORKOUT_TOKEN}
CUSTOM_WORKOUT_CATEGORIES = (
    "CHEST",
    "TRICEPS",
    "BACK",
    "BICEPS",
    "SHOULDERS",
    "ABS",
    "LEGS",
    "CARDIO",
)

# Weighted baseline so condensed sessions still hit big movers first.
CUSTOM_WORKOUT_BASE_COUNTS = {
    "LEGS": 6,
    "BACK": 5,
    "CHEST": 5,
    "SHOULDERS": 4,
    "BICEPS": 3,
    "TRICEPS": 3,
    "ABS": 3,
    "CARDIO": 2,
}

CUSTOM_WORKOUT_SELECTION_LIMITS = {
    20: {"min": 1, "max": 3},
    30: {"min": 1, "max": 4},
    45: {"min": 1, "max": 6},
    60: {"min": 1, "max": 8},
}

DURATION_TOTAL_EXERCISES = {
    20: 3,
    30: 5,
    45: 7,
    60: 9,
}
DEFAULT_EXERCISES_PER_HOUR = DURATION_TOTAL_EXERCISES.get(60, 10)
DEFAULT_EXERCISES_PER_MINUTE = max(0.1, DEFAULT_EXERCISES_PER_HOUR / 60.0)

CATEGORY_TOTAL_OVERRIDES = {
    "Cardio": {20: 2, 30: 3, 45: 4, 60: 4},
    "Abs": {20: 3, 30: 4, 45: 5, 60: 6},
}

CUSTOM_CATEGORY_TOTAL_OVERRIDES = {key.upper(): value for key, value in CATEGORY_TOTAL_OVERRIDES.items()}

# Short custom sessions (20–30 min) only yield up to five exercises, so let each
# selected bucket get a stronger foothold before biasing toward larger muscles.
SHORT_CUSTOM_SESSION_EXERCISE_CAP = 5
SHORT_CUSTOM_MIN_PER_CATEGORY = 2

HOME_EQUIPMENT_OPTIONS = [
    {"token": "BODYWEIGHT", "label": "Bodyweight"},
    {"token": "DUMBBELL", "label": "Dumbbells"},
    {"token": "BARBELL", "label": "Barbell"},
    {"token": "STABILITY_BALL", "label": "Stability Ball"},
    {"token": "PULL_UP_BAR", "label": "Pull-Up Bar"},
    {"token": "FREEWEIGHT_FLAT_BENCH", "label": "Flat Bench"},
    {"token": "FREEWEIGHT_ADJUSTABLE_BENCH", "label": "Adjustable Bench"},
]

HOME_EQUIPMENT_FILTERS = {
    "BODYWEIGHT": {
        "include_any": ["bodyweight"],
        "exclude_any": ["pull-up", "chin-up", "stability ball", "hanging", "ab wheel", "life fitness", "freemotion"],
    },
    "DUMBBELL": {
        "include_any": ["dumbbell", "goblet squat"],
        "exclude_any": ["bench", "incline", "preacher curl"],
    },
    "BARBELL": {
        "include_any": ["barbell"],
        "exclude_any": ["bench", "clean", "jerk", "snatch"],
    },
    "STABILITY_BALL": {
        "include_any": ["stability ball"],
    },
    "PULL_UP_BAR": {
        "include_any": ["pull-up", "chin-up", "hanging"],
    },
    "FREEWEIGHT_FLAT_BENCH": {
        "include_any": ["flat bench"],
    },
    "FREEWEIGHT_ADJUSTABLE_BENCH": {
        "include_any": ["flat bench", "incline bench", "seated shoulder press"],
    },
}
HOME_EQUIPMENT_TOKEN_SET = {option["token"] for option in HOME_EQUIPMENT_OPTIONS}
CARDIO_BODYWEIGHT_WORKOUTS = (
    "Treadmill Walking",
    "Treadmill Running",
    "Treadmill Sprinting",
    "Treadmill Jogging",
)
HOME_WORKOUT_EXCLUDED_NAME_TERMS = ("trx",)

# Prefix lookup so both leg press machine families can be identified quickly
LEG_PRESS_MACHINE_PREFIXES = {
    "LIFE_FITNESS": "life fitness leg press machine",
    "HAMMER_STRENGTH": "hammer strength leg press machine",
}
LEG_PRESS_FETCH_BUFFER = 4
RECENT_SUBCATEGORY_LOOKBACK = 2
RECENT_SUBCATEGORY_INACTIVITY_RELAX_DAYS = 30


def get_default_catalog_gym_id() -> int | None:
    global DEFAULT_CATALOG_GYM_ID
    if DEFAULT_CATALOG_GYM_ID:
        return DEFAULT_CATALOG_GYM_ID
    try:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT id
                      FROM gyms
                     WHERE lower(name) = lower(%s)
                       AND lower(COALESCE(city, '')) = lower(%s)
                       AND lower(COALESCE(state, '')) = lower(%s)
                       AND lower(COALESCE(country, '')) = lower(%s)
                     ORDER BY id
                     LIMIT 1
                    """,
                    (
                        DEFAULT_CATALOG_GYM_LOOKUP["name"],
                        DEFAULT_CATALOG_GYM_LOOKUP["city"],
                        DEFAULT_CATALOG_GYM_LOOKUP["state"],
                        DEFAULT_CATALOG_GYM_LOOKUP["country"],
                    ),
                )
                row = cursor.fetchone()
                default_id = row[0] if row else None
                if default_id:
                    DEFAULT_CATALOG_GYM_ID = int(default_id)
                    return DEFAULT_CATALOG_GYM_ID
    except Exception:
        logger.exception("Unable to resolve default catalog gym id")
    return None


def normalize_home_equipment_selection(values) -> list[str]:
    """Normalize a list of raw equipment tokens into uppercase identifiers."""
    seen = set()
    normalized: list[str] = []
    for raw in values or []:
        token = (str(raw) or '').strip().upper()
        if token and token in HOME_EQUIPMENT_TOKEN_SET and token not in seen:
            seen.add(token)
            normalized.append(token)
    return normalized


def build_home_equipment_clause(equipment_tokens: list[str]) -> tuple[str, list[str], bool]:
    """
    Build a SQL clause restricting workouts by name based on selected equipment.
    Returns (clause_sql, params, allow_cardio_bodyweight). Clause is empty when no valid tokens exist.
    """
    clauses: list[str] = []
    params: list[str] = []
    allow_cardio_bodyweight = False
    for token in equipment_tokens or []:
        spec = HOME_EQUIPMENT_FILTERS.get(token)
        if not spec:
            if token == "BODYWEIGHT":
                allow_cardio_bodyweight = True
            continue
        if token == "BODYWEIGHT":
            allow_cardio_bodyweight = True
        include_terms = [term.strip().lower() for term in spec.get("include_any", []) if term.strip()]
        if not include_terms:
            continue
        include_parts = ["LOWER(w.name) LIKE %s" for _ in include_terms]
        clause_params = [f"%{term}%" for term in include_terms]

        exclude_terms = [term.strip().lower() for term in spec.get("exclude_any", []) if term.strip()]
        exclude_parts = ["LOWER(w.name) NOT LIKE %s" for _ in exclude_terms]
        clause_params.extend(f"%{term}%" for term in exclude_terms)

        clause = f"({' OR '.join(include_parts)})"
        if exclude_parts:
            clause = f"{clause} AND {' AND '.join(exclude_parts)}"
        clauses.append(f"({clause})")
        params.extend(clause_params)

    if not clauses:
        return "", [], allow_cardio_bodyweight
    return f"({' OR '.join(clauses)})", params, allow_cardio_bodyweight


def build_name_exclusion_clause(exclude_terms) -> tuple[str, list[str]]:
    """Build a SQL clause excluding workouts whose names contain any excluded term."""
    normalized_terms: list[str] = []
    for raw in exclude_terms or []:
        term = (str(raw) or "").strip().lower()
        if term and term not in normalized_terms:
            normalized_terms.append(term)
    if not normalized_terms:
        return "", []
    clause = " AND ".join(["LOWER(w.name) NOT LIKE %s"] * len(normalized_terms))
    params = [f"%{term}%" for term in normalized_terms]
    return clause, params


def normalize_custom_workout_categories(categories) -> list[str]:
    seen = set()
    normalized: list[str] = []
    for raw in categories or []:
        token = (str(raw) or '').strip().upper()
        if token and token in CUSTOM_WORKOUT_CATEGORIES and token not in seen:
            seen.add(token)
            normalized.append(token)
    return normalized


def base_duration_total(duration_minutes: int) -> int:
    """Return the default exercise count for a given session length."""
    base = DURATION_TOTAL_EXERCISES.get(duration_minutes)
    if base is not None:
        return max(1, int(base))
    minutes = max(1, int(duration_minutes or 60))
    estimated = round(minutes * DEFAULT_EXERCISES_PER_MINUTE)
    return max(3, estimated)


def resolve_duration_total(duration_minutes: int, category_name: str | None = None) -> int:
    """Apply category-specific overrides to the default duration totals."""
    total = base_duration_total(duration_minutes)
    if category_name:
        override = CATEGORY_TOTAL_OVERRIDES.get(category_name)
        if override:
            total = override.get(duration_minutes, total)
    return max(1, total)


def resolve_custom_duration_total(duration_minutes: int, categories: list[str]) -> int:
    """
    Determine the total exercise budget for a custom workout, allowing cardio/abs-only
    sessions to inherit their stricter caps.
    """
    total = base_duration_total(duration_minutes)
    normalized = [token for token in categories or [] if token]
    unique_tokens = {token.upper() for token in normalized}
    if len(unique_tokens) == 1:
        token = next(iter(unique_tokens))
        override = CUSTOM_CATEGORY_TOTAL_OVERRIDES.get(token)
        if override:
            total = override.get(duration_minutes, total)
    return max(len(normalized), total)


def custom_selection_bounds(duration_minutes: int) -> tuple[int, int]:
    limits = CUSTOM_WORKOUT_SELECTION_LIMITS.get(
        duration_minutes,
        {"min": 1, "max": len(CUSTOM_WORKOUT_CATEGORIES)},
    )
    min_req = max(1, int(limits.get("min", 1)))
    max_allowed = max(min_req, int(limits.get("max", len(CUSTOM_WORKOUT_CATEGORIES))))
    return min_req, max_allowed


CARDIO_RESTRICTION_TOKEN = 'cardio'

# Map body regions collected from the training questionnaire to workout categories
# that should be avoided when generating workouts.
INJURY_REGION_CATEGORY_MAP = {
    'neck': {'SHOULDERS', 'BACK', 'CHEST'},
    'shoulders': {'SHOULDERS', 'CHEST', 'BACK'},
    'elbows': {'TRICEPS', 'BICEPS', 'SHOULDERS', 'BACK', 'CHEST'},
    'wrists': {'BICEPS', 'TRICEPS', 'SHOULDERS', 'BACK', 'CHEST'},
    'lower_back': {'BACK'},
    'hips': {'LEGS', 'CARDIO'},
    'knees': {'LEGS', 'CARDIO'},
    'ankles': {'LEGS', 'CARDIO'},
    'upper_back': {'BACK', 'SHOULDERS'},
    'shoulder_left': {'SHOULDERS', 'CHEST', 'BACK'},
    'shoulder_right': {'SHOULDERS', 'CHEST', 'BACK'},
    'elbow_left': {'TRICEPS', 'BICEPS', 'SHOULDERS', 'BACK', 'CHEST'},
    'elbow_right': {'TRICEPS', 'BICEPS', 'SHOULDERS', 'BACK', 'CHEST'},
    'wrist_left': {'BICEPS', 'TRICEPS', 'SHOULDERS', 'BACK', 'CHEST'},
    'wrist_right': {'BICEPS', 'TRICEPS', 'SHOULDERS', 'BACK', 'CHEST'},
    'hip_left': {'LEGS', 'CARDIO'},
    'hip_right': {'LEGS', 'CARDIO'},
    'knee_left': {'LEGS', 'CARDIO'},
    'knee_right': {'LEGS', 'CARDIO'},
    'ankle_left': {'LEGS', 'CARDIO'},
    'ankle_right': {'LEGS', 'CARDIO'},
}


def _normalize_region(value):
    if not value:
        return None
    normalized = re.sub(r"[^a-z0-9]+", "_", str(value).strip().lower())
    normalized = normalized.strip("_")
    return normalized or None


def parse_injury_payload(raw):
    """Return normalized injury regions and cardio flag from a JSON/text payload."""
    if raw is None:
        entries = []
    elif isinstance(raw, (list, tuple)):
        entries = list(raw)
    else:
        text = str(raw).strip()
        if not text:
            entries = []
        else:
            try:
                decoded = json.loads(text)
            except (json.JSONDecodeError, TypeError, ValueError):
                decoded = [part for part in re.split(r",|;|\s", text) if part]
            if isinstance(decoded, dict):
                entries = decoded.get('regions') or decoded.get('injury') or []
            else:
                entries = decoded

    regions = []
    cardio_flag = False

    for entry in entries:
        slug = _normalize_region(entry)
        if not slug:
            continue
        if slug == CARDIO_RESTRICTION_TOKEN:
            cardio_flag = True
            continue
        if slug not in regions:
            regions.append(slug)

    return {
        'regions': regions,
        'cardio': cardio_flag,
    }


def compute_injury_exclusions(regions, cardio_restriction=False):
    """Translate injury regions into category/subcategory exclusions."""
    exclusions = set()

    for region in regions or []:
        mapped = INJURY_REGION_CATEGORY_MAP.get(region)
        if mapped:
            exclusions.update(mapped)
    if cardio_restriction:
        exclusions.add('CARDIO')
    return {entry.upper() for entry in exclusions}


def get_user_injury_profile(user_id):
    """Fetch stored injury preferences for a user."""
    with get_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                "SELECT injury, injury_details, cardio_restriction FROM users WHERE id = %s",
                (user_id,),
            )
            row = cursor.fetchone() or {}

    payload = parse_injury_payload(row.get('injury'))
    cardio_flag = bool(row.get('cardio_restriction')) or payload['cardio']
    return {
        'regions': payload['regions'],
        'cardio_restriction': cardio_flag,
        'injury_details': row.get('injury_details') or '',
    }


def get_user_injury_exclusions(user_id):
    profile = get_user_injury_profile(user_id)
    exclusions = compute_injury_exclusions(profile['regions'], profile['cardio_restriction'])
    return {
        'profile': profile,
        'excluded_categories': exclusions,
    }


# --- Exercise history → numeric level mapping ---
LEVEL_MAP = {
    "No Exercise History": 1,
    "Exercise less than 1 year": 1,
    "Exercise 1-5 years": 2,
    "Exercise 5+ years": 3,
}


def is_admin(user_id):
    """Admin if email is in .env bootstrap list OR role='admin' in DB."""
    if not user_id:
        return False
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT email, role FROM users WHERE id = %s", (user_id,))
            row = cursor.fetchone()
            if not row:
                return False
            email, role = row
            return (email or '').lower() in ADMIN_EMAILS or role == 'admin'
        

def hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def validate_token(conn, raw_token: str, purpose: str):
    """
    Returns {"token_id": int, "user_id": int, "expires_at": datetime} if valid and unexpired; else None.
    """
    digest = hash_token(raw_token)
    with conn.cursor() as cur:
        cur.execute("""
            SELECT ut.id, ut.user_id, ut.expires_at
            FROM user_tokens ut
            WHERE ut.purpose = %s
              AND ut.token_digest = %s
              AND ut.used_at IS NULL
              AND ut.expires_at > now()
            LIMIT 1
        """, (purpose, digest))
        row = cur.fetchone()
        if not row:
            return None
        return {"token_id": row[0], "user_id": row[1], "expires_at": row[2]}


def mark_token_used(conn, token_id: int):
    with conn.cursor() as cur:
        cur.execute("UPDATE user_tokens SET used_at = now() WHERE id = %s", (token_id,))


def username_available(conn, username: str) -> bool:
    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM users WHERE lower(username) = lower(%s) LIMIT 1", (username,))
        return cur.fetchone() is None
    

def normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def issue_single_use_token(conn, user_id: int, purpose: str, ttl_hours: int):
    raw_token = secrets.token_urlsafe(32)
    digest = hash_token(raw_token)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=ttl_hours)
    with conn.cursor() as cur:
        # Invalidate ANY existing unused tokens for this purpose
        cur.execute("""
            UPDATE user_tokens
               SET used_at = now()
             WHERE user_id = %s
               AND purpose = %s
               AND used_at IS NULL
        """, (user_id, purpose))
        cur.execute("""
            INSERT INTO user_tokens (user_id, purpose, token_digest, expires_at)
            VALUES (%s, %s, %s, %s)
            RETURNING id
        """, (user_id, purpose, digest, expires_at))
        token_id = cur.fetchone()[0]
    return raw_token, expires_at, token_id


def issue_remember_token(
    conn,
    *,
    user_id: int,
    session_version: int,
    ttl_days: int,
    max_days: int,
    user_agent: str | None = None,
    ip_address: str | None = None,
):
    raw_token = secrets.token_urlsafe(32)
    digest = hash_token(raw_token)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=ttl_days)
    absolute_expires_at = now + timedelta(days=max_days)
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO remember_tokens (
                user_id,
                token_digest,
                session_version,
                created_at,
                last_used_at,
                expires_at,
                absolute_expires_at,
                user_agent,
                ip_address
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                user_id,
                digest,
                session_version,
                now,
                now,
                expires_at,
                absolute_expires_at,
                user_agent,
                ip_address,
            ),
        )
        token_id = cur.fetchone()[0]
    return raw_token, expires_at, absolute_expires_at, token_id


def get_valid_remember_token(conn, raw_token: str):
    digest = hash_token(raw_token)
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
            SELECT rt.id,
                   rt.user_id,
                   rt.session_version AS token_session_version,
                   rt.expires_at,
                   rt.absolute_expires_at,
                   u.role,
                   u.status,
                   u.session_version AS user_session_version
              FROM remember_tokens rt
              JOIN users u ON u.id = rt.user_id
             WHERE rt.token_digest = %s
               AND rt.revoked_at IS NULL
               AND rt.expires_at > now()
               AND rt.absolute_expires_at > now()
             LIMIT 1
            """,
            (digest,),
        )
        return cur.fetchone()


def rotate_remember_token(
    conn,
    *,
    token_id: int,
    ttl_days: int,
    absolute_expires_at: datetime,
    user_agent: str | None = None,
    ip_address: str | None = None,
):
    raw_token = secrets.token_urlsafe(32)
    digest = hash_token(raw_token)
    now = datetime.now(timezone.utc)
    candidate_expires = now + timedelta(days=ttl_days)
    expires_at = min(candidate_expires, absolute_expires_at)
    if expires_at <= now:
        return None, None
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE remember_tokens
               SET token_digest = %s,
                   last_used_at = %s,
                   expires_at = %s,
                   user_agent = COALESCE(%s, user_agent),
                   ip_address = COALESCE(%s, ip_address)
             WHERE id = %s
               AND revoked_at IS NULL
            """,
            (digest, now, expires_at, user_agent, ip_address, token_id),
        )
        updated = cur.rowcount
    if updated != 1:
        return None, None
    return raw_token, expires_at


def revoke_remember_token(conn, raw_token: str):
    digest = hash_token(raw_token)
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE remember_tokens
               SET revoked_at = now()
             WHERE token_digest = %s
               AND revoked_at IS NULL
            """,
            (digest,),
        )


def revoke_remember_token_by_id(conn, token_id: int):
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE remember_tokens
               SET revoked_at = now()
             WHERE id = %s
               AND revoked_at IS NULL
            """,
            (token_id,),
        )



def upsert_invited_user(conn, *, email, first, last, role, subscription, invited_by, trainer_id=None, sessions_remaining=None) -> int:
    now = datetime.now(timezone.utc)
    with conn.cursor() as cur:
        cur.execute("SELECT id, status FROM users WHERE lower(email) = %s", (email.lower(),))
        row = cur.fetchone()

        if row:
            user_id, status = row
            if status == "active":
                raise ValueError("An active account already exists with this email.")
            cur.execute("""
                UPDATE users
                   SET name=%s, last_name=%s, role=%s, subscription_type=%s,
                       status='invited', email_verified=false,
                       invited_by=%s, invited_at=%s,
                       accepted_at=NULL, username=NULL, hash=NULL,
                       trainer_id=%s,
                       sessions_remaining=%s,
                       sessions_booked=COALESCE(sessions_booked, 0),
                       updated_at=%s
                 WHERE id=%s
            """, (first or None, last or None, role, subscription,
                  invited_by, now, trainer_id, sessions_remaining, now, user_id))
            return user_id

        cur.execute("""
            INSERT INTO users
                (email, name, last_name, role, subscription_type,
                 status, email_verified, invited_by, invited_at,
                 username, hash, trainer_id, sessions_remaining, sessions_booked, created_at, updated_at)
            VALUES
                (%s, %s, %s, %s, %s,
                 'invited', false, %s, %s,
                 NULL, NULL, %s, %s, 0, %s, %s)
            RETURNING id
        """, (email, first or None, last or None, role, subscription,
              invited_by, now, trainer_id, sessions_remaining, now, now))
        return cur.fetchone()[0]


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            print("User not logged in, redirecting to login")
            return redirect(url_for('login'))
        print("User is logged in")
        return f(*args, **kwargs)
    return decorated_function


def convert_decimals(obj):
    if isinstance(obj, list):
        return [convert_decimals(i) for i in obj]
    elif isinstance(obj, dict):
        return {k: convert_decimals(v) for k, v in obj.items()}
    elif isinstance(obj, tuple):
        return tuple(convert_decimals(i) for i in obj)
    elif isinstance(obj, Decimal):
        return float(obj)
    else:
        return obj


def get_active_workout(user_id: int) -> dict | None:
    with get_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT category, workout_data, created_at FROM active_workouts WHERE user_id = %s",
                (user_id,),
            )
            return cur.fetchone()


def set_active_workout(user_id: int, category: str, workout_data) -> None:
    payload = convert_decimals(workout_data)
    if isinstance(payload, dict):
        plan = payload.get('plan')
        normalized = []
        if isinstance(plan, dict):
            normalized = [
                {'subcategory': subcat, 'exercises': exercises}
                for subcat, exercises in plan.items()
            ]
        elif isinstance(plan, list):
            for entry in plan:
                if isinstance(entry, dict) and 'subcategory' in entry:
                    normalized.append(entry)
                elif isinstance(entry, (list, tuple)) and len(entry) >= 2:
                    normalized.append({'subcategory': entry[0], 'exercises': entry[1]})
        if normalized:
            payload['plan'] = normalized

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO active_workouts (user_id, category, workout_data)
                VALUES (%s, %s, %s)
                ON CONFLICT (user_id)
                DO UPDATE SET
                    category = EXCLUDED.category,
                    workout_data = EXCLUDED.workout_data,
                    created_at = now()
                """,
                (user_id, category, Json(payload)),
            )
            conn.commit()


def clear_active_workout(user_id: int) -> None:
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM active_workouts WHERE user_id = %s", (user_id,))
            conn.commit()


def calculate_target_heart_rate(age):
    """
    Calculate target heart rate zone and maximum heart rate based on age.
    :param age: Age of the user
    :return: Dictionary containing labeled heart rate data
    """
    max_heart_rate = 220 - age  # General formula for max HR
    lower_bound = int(max_heart_rate * 0.50)
    upper_bound = int(max_heart_rate * 0.85)
    return {
        'lower_bound': lower_bound,
        'upper_bound': upper_bound,
        'max_heart_rate': max_heart_rate
    }


def allocate_counts(subcategories: dict, scale: float, selected_category: str, total_override: int | None = None) -> dict:
    """
    Allocate a total exercise budget across subcategories with priority emphasis.
    When ``total_override`` is provided, it is used as the exact number of exercises
    to distribute across the selected subcategories.
    """
    # ---- 1) Define priority per category ----
    PRIORITY_MAP = {
        # Full Body: emphasize compounds / large muscle groups first
        "Full Body": ["LEGS", "BACK", "CHEST", "SHOULDERS", "BICEPS", "TRICEPS", "ABS"],
        # Upper Body day: prioritize multi-joint / larger movers
        "Upper Body": ["BACK", "CHEST", "SHOULDERS", "BICEPS", "TRICEPS"],
        # Legs is single bucket
        "Legs": ["LEGS"],
        # Push/Pull splits
        "Chest and Triceps": ["CHEST", "TRICEPS"],
        "Back and Biceps": ["BACK", "BICEPS"],
        "Shoulders and Abs": ["SHOULDERS", "ABS"],
        "Arms": ["SHOULDERS", "BICEPS", "TRICEPS"],
        "Cardio": ["CARDIO"],
        CUSTOM_WORKOUT_TOKEN: ["LEGS", "BACK", "CHEST", "SHOULDERS", "BICEPS", "TRICEPS", "ABS", "CARDIO"],
        HOME_WORKOUT_TOKEN: ["LEGS", "BACK", "CHEST", "SHOULDERS", "BICEPS", "TRICEPS", "ABS", "CARDIO"],
    }
    priority = PRIORITY_MAP.get(selected_category, [])

    # ---- 2) Budget math ----
    base_total = sum(subcategories.values())
    if total_override is not None:
        target_total = max(1, int(total_override))
    else:
        target_total = max(1, math.floor(base_total * scale))

    # Edge cases
    if base_total == 0 or not subcategories:
        return {k: 0 for k in subcategories}

    # Build ordered keys: priority first, then any remaining in original order
    # Preserve original order input by using OrderedDict
    ordered_keys = [k for k in priority if k in subcategories] + \
                   [k for k in subcategories.keys() if k not in priority]

    # Fast lookup for tie-breaking: lower rank = higher priority
    prio_rank = {k: i for i, k in enumerate(ordered_keys)}

    # ---- 3) Start everyone at 0 ----
    counts = {k: 0 for k in subcategories}

    # Custom sessions with very small budgets (20–30 min → <=5 exercises)
    # should guarantee a higher floor so secondary groups aren't starved.
    minimum_floor = 1
    if (
        selected_category in CUSTOMIZABLE_WORKOUT_TOKENS
        and target_total <= SHORT_CUSTOM_SESSION_EXERCISE_CAP
        and subcategories
    ):
        bucket_count = max(1, len(subcategories))
        desired_floor = SHORT_CUSTOM_MIN_PER_CATEGORY
        max_supported_floor = max(1, target_total // bucket_count)
        minimum_floor = max(1, min(desired_floor, max_supported_floor))

    # ---- 4) Ensure representation in priority order ----
    for floor_level in range(minimum_floor):
        for key in ordered_keys:
            if sum(counts.values()) >= target_total:
                break
            if counts[key] < (floor_level + 1):
                counts[key] += 1
        else:
            continue
        break

    # ---- 5) Distribute remaining based on "desire" (how far from base pattern),
    #         tie-breaking by priority rank ----
    while sum(counts.values()) < target_total:
        best_key = max(
            subcategories.keys(),
            key=lambda k: (
                subcategories[k] - counts[k],  # bigger gap to base gets more
                (subcategories[k] / base_total) if base_total else 0.0,  # slight bias to bigger base_n
                -prio_rank.get(k, 999)  # then priority (lower rank preferred)
            )  
        )
        counts[best_key] += 1

    return counts



def get_category_groups() -> dict[str, list[str]]:
    """
    Returns a mapping of Category -> [Subcategory,...] derived from WORKOUT_STRUCTURE,
    ensuring a single source of truth for UI or grouped queries.
    """
    groups: dict[str, list[str]] = {}
    for level_map in WORKOUT_STRUCTURE.values():
        for category, subs in level_map.items():
            # preserve insertion order & remove dups across levels
            if category not in groups:
                groups[category] = list(subs.keys())
            else:
                for k in subs.keys():
                    if k not in groups[category]:
                        groups[category].append(k)
    return groups


def get_user_level(exercise_history: str | None) -> int:
    """Map user's exercise history string to a program level (1–3)."""
    if not exercise_history:
        return 1
    return LEVEL_MAP.get(exercise_history, 1)


def identify_leg_press_machine(name: str | None) -> str | None:
    """Return the normalized machine key for any leg press variation."""
    if not name:
        return None
    normalized = name.strip().lower()
    for key, prefix in LEG_PRESS_MACHINE_PREFIXES.items():
        if normalized.startswith(prefix):
            return key
    return None


def filter_leg_press_rows(rows, forced_machine: str | None = None):
    """
    Remove rows that belong to both machine families, keeping only the requested
    machine (or the first encountered machine when not forced).
    """
    machine_key = forced_machine
    filtered = []
    for row in rows or []:
        machine = identify_leg_press_machine(row[1] if len(row) > 1 else None)
        if not machine:
            filtered.append(row)
            continue
        if machine_key and machine != machine_key:
            continue
        if not machine_key:
            machine_key = machine
        filtered.append(row)
    return filtered, machine_key


def group_leg_press_rows(rows, forced_machine: str | None = None):
    """Ensure all selected leg press exercises remain contiguous."""
    machine_key = forced_machine
    machine_rows = []
    non_machine_rows = []
    insertion_idx = None

    for row in rows or []:
        machine = identify_leg_press_machine(row[1] if len(row) > 1 else None)
        if machine:
            if machine_key and machine != machine_key:
                continue
            if not machine_key:
                machine_key = machine
            if machine == machine_key:
                if insertion_idx is None:
                    insertion_idx = len(non_machine_rows)
                machine_rows.append(row)
            continue
        non_machine_rows.append(row)

    if not machine_rows:
        if len(non_machine_rows) == len(rows):
            return rows, machine_key
        return non_machine_rows, machine_key

    if insertion_idx is None:
        insertion_idx = len(non_machine_rows)

    grouped = non_machine_rows[:]
    grouped[insertion_idx:insertion_idx] = machine_rows
    return grouped, machine_key


def prioritize_movement_types(rows):
    """Return exercises ordered Compound → Accessory → Other."""
    compounds = []
    accessories = []
    others = []
    for row in rows or []:
        movement_type = (row[-1] or '').lower()
        if movement_type == 'compound':
            compounds.append(row)
        elif movement_type == 'accessory':
            accessories.append(row)
        else:
            others.append(row)
    ordered = compounds + accessories + others
    return ordered, bool(compounds)


def _normalize_subcategory_key(value) -> str:
    return (str(value or "")).strip().upper()


def _normalize_plan_blocks(plan) -> list[tuple[str | None, list]]:
    if isinstance(plan, list):
        normalized = []
        for entry in plan:
            if isinstance(entry, dict) and 'subcategory' in entry:
                normalized.append((entry.get('subcategory'), entry.get('exercises') or []))
            elif isinstance(entry, (list, tuple)) and len(entry) >= 2:
                normalized.append((entry[0], entry[1]))
        return normalized
    if isinstance(plan, dict):
        return [(key, value) for key, value in plan.items() if key != '_meta']
    return []


def _extract_workout_id(entry) -> int | None:
    raw_value = None
    if isinstance(entry, dict):
        raw_value = entry.get('workout_id')
    elif isinstance(entry, (list, tuple)) and entry:
        raw_value = entry[0]
    try:
        return int(raw_value) if raw_value is not None else None
    except (TypeError, ValueError):
        return None


def _build_recent_exercise_context(user_id: int, subcategory_names) -> dict[str, dict[str, list | set]]:
    subcategory_keys: list[str] = []
    seen = set()
    for name in subcategory_names or []:
        key = _normalize_subcategory_key(name)
        if key and key not in seen:
            seen.add(key)
            subcategory_keys.append(key)

    context = {
        key: {
            'active': set(),
            'assigned_sessions': set(),
            'recent_sessions': [],
        }
        for key in subcategory_keys
    }
    if not context:
        return context

    try:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT workout_data
                      FROM active_workouts
                     WHERE user_id = %s
                    """,
                    (user_id,),
                )
                active_row = cursor.fetchone()
                active_payload = active_row[0] if active_row else None
                if isinstance(active_payload, str):
                    try:
                        active_payload = json.loads(active_payload)
                    except (TypeError, ValueError, json.JSONDecodeError):
                        active_payload = None
                if isinstance(active_payload, dict):
                    for subcategory, exercises in _normalize_plan_blocks(active_payload.get('plan')):
                        subcategory_key = _normalize_subcategory_key(subcategory)
                        if subcategory_key not in context:
                            continue
                        for entry in exercises or []:
                            workout_id = _extract_workout_id(entry)
                            if workout_id is not None:
                                context[subcategory_key]['active'].add(workout_id)

                cursor.execute(
                    """
                    SELECT session_payload
                      FROM trainer_schedule
                     WHERE client_id = %s
                       AND status = %s
                       AND session_payload IS NOT NULL
                    """,
                    (user_id, 'booked'),
                )
                for row in cursor.fetchall() or []:
                    session_payload = row[0] if row else None
                    if isinstance(session_payload, str):
                        try:
                            session_payload = json.loads(session_payload)
                        except (TypeError, ValueError, json.JSONDecodeError):
                            session_payload = None
                    if not isinstance(session_payload, dict):
                        continue
                    for subcategory, exercises in _normalize_plan_blocks(session_payload.get('plan')):
                        subcategory_key = _normalize_subcategory_key(subcategory)
                        if subcategory_key not in context:
                            continue
                        for entry in exercises or []:
                            workout_id = _extract_workout_id(entry)
                            if workout_id is not None:
                                context[subcategory_key]['assigned_sessions'].add(workout_id)

                lookback = RECENT_SUBCATEGORY_LOOKBACK
                cursor.execute(
                    """
                    SELECT MAX(recorded_at)
                      FROM user_exercise_history
                     WHERE user_id = %s
                       AND source = %s
                    """,
                    (user_id, 'session_complete'),
                )
                last_completed_row = cursor.fetchone()
                last_completed_at = last_completed_row[0] if last_completed_row else None
                if last_completed_at:
                    if last_completed_at.tzinfo is None:
                        last_completed_at = last_completed_at.replace(tzinfo=timezone.utc)
                    inactivity_limit = timedelta(days=RECENT_SUBCATEGORY_INACTIVITY_RELAX_DAYS)
                    if datetime.now(timezone.utc) - last_completed_at > inactivity_limit:
                        lookback = 1

                if lookback <= 0:
                    return context

                cursor.execute(
                    """
                    SELECT
                        UPPER(COALESCE(subcategory, '')) AS subcategory_key,
                        session_id,
                        MAX(recorded_at) AS completed_at,
                        ARRAY_AGG(DISTINCT workout_id) FILTER (WHERE workout_id IS NOT NULL) AS workout_ids
                    FROM user_exercise_history
                    WHERE user_id = %s
                      AND source = %s
                      AND session_id IS NOT NULL
                      AND UPPER(COALESCE(subcategory, '')) = ANY(%s)
                    GROUP BY UPPER(COALESCE(subcategory, '')), session_id
                    ORDER BY completed_at DESC
                    """,
                    (user_id, 'session_complete', subcategory_keys),
                )
                for row in cursor.fetchall() or []:
                    subcategory_key = _normalize_subcategory_key(row[0])
                    if subcategory_key not in context:
                        continue
                    sessions = context[subcategory_key]['recent_sessions']
                    if len(sessions) >= lookback:
                        continue
                    workout_ids = {
                        int(workout_id)
                        for workout_id in (row[3] or [])
                        if workout_id is not None
                    }
                    if workout_ids:
                        sessions.append(workout_ids)
    except psycopg2.errors.UndefinedTable:
        logger.warning("Workout history tables missing; recent exercise exclusions skipped for user_id=%s", user_id)
    except Exception:
        logger.exception("Failed to build recent exercise context for user_id=%s", user_id)

    return context


def _partition_candidate_rows(
    rows,
    active_ids: set[int],
    assigned_session_ids: set[int],
    recent_sessions: list[set[int]],
) -> list[list]:
    fresh_rows = []
    older_recent_rows = []
    most_recent_rows = []
    assigned_session_rows = []
    active_rows = []

    most_recent_ids = recent_sessions[0] if recent_sessions else set()
    older_recent_ids = set().union(*recent_sessions[1:]) if len(recent_sessions) > 1 else set()

    for row in rows or []:
        try:
            workout_id = int(row[0])
        except (TypeError, ValueError, IndexError):
            continue
        if workout_id in assigned_session_ids:
            assigned_session_rows.append(row)
        elif workout_id in active_ids:
            active_rows.append(row)
        elif workout_id in older_recent_ids:
            older_recent_rows.append(row)
        elif workout_id in most_recent_ids:
            most_recent_rows.append(row)
        else:
            fresh_rows.append(row)

    return [fresh_rows, older_recent_rows, most_recent_rows, assigned_session_rows, active_rows]


def _select_ranked_rows(candidate_groups: list[list], n: int, subcategory_key: str) -> list:
    selected_rows = []
    selected_ids = set()
    chosen_machine = None

    for group in candidate_groups:
        for row in group or []:
            try:
                workout_id = int(row[0])
            except (TypeError, ValueError, IndexError):
                continue
            if workout_id in selected_ids:
                continue
            if subcategory_key == 'LEGS':
                machine = identify_leg_press_machine(row[1] if len(row) > 1 else None)
                if machine:
                    if chosen_machine and machine != chosen_machine:
                        continue
                    if not chosen_machine:
                        chosen_machine = machine
            selected_rows.append(row)
            selected_ids.add(workout_id)
            if len(selected_rows) >= n:
                return selected_rows

    return selected_rows


def generate_workout(
    selected_category,
    user_level,
    user_id,
    duration_minutes=60,
    custom_categories=None,
    equipment_filters=None,
    catalog_mode=None,
    catalog_gym_id=None,
):
    """
    Generate a workout based on the selected category, user level, and preferred duration.
    Respects user injury restrictions by omitting excluded categories.
    Returns the workout plan and a metadata dictionary describing skipped content.
    """
    try:
        duration_minutes = int(duration_minutes or 60)
    except (TypeError, ValueError):
        duration_minutes = 60

    BASE_MINUTES = 60
    scale = max(0.33, min(1.0, duration_minutes / BASE_MINUTES))

    category_key = (selected_category or "").strip()
    is_custom = category_key in CUSTOMIZABLE_WORKOUT_TOKENS
    is_home = category_key == HOME_WORKOUT_TOKEN
    equipment_tokens: list[str] = []
    equipment_clause = ""
    equipment_params: list[str] = []
    allow_cardio_bodyweight = False

    total_target = None

    if is_custom:
        normalized = normalize_custom_workout_categories(custom_categories)
        min_required, max_allowed = custom_selection_bounds(duration_minutes)
        count = len(normalized)
        if count < min_required or count > max_allowed:
            raise ValueError(
                f"Select between {min_required} and {max_allowed} categories for a {duration_minutes}-minute workout."
            )
        if not normalized:
            raise ValueError("Choose at least one workout category.")
        subcategories = OrderedDict(
            (cat, CUSTOM_WORKOUT_BASE_COUNTS.get(cat, 2))
            for cat in normalized
        )
        total_target = resolve_custom_duration_total(duration_minutes, normalized)
        equipment_tokens = normalize_home_equipment_selection(equipment_filters) if is_home else []
        if is_home:
            if not equipment_tokens:
                raise ValueError("Select at least one piece of equipment for a Custom Home Workout.")
            equipment_clause, equipment_params, allow_cardio_bodyweight = build_home_equipment_clause(equipment_tokens)
            home_name_exclusion_clause, home_name_exclusion_params = build_name_exclusion_clause(
                HOME_WORKOUT_EXCLUDED_NAME_TERMS
            )
            if home_name_exclusion_clause:
                if equipment_clause:
                    equipment_clause = f"({equipment_clause}) AND {home_name_exclusion_clause}"
                else:
                    equipment_clause = home_name_exclusion_clause
                equipment_params.extend(home_name_exclusion_params)
    else:
        structure = WORKOUT_STRUCTURE.get(user_level, {})
        subcategories = structure.get(category_key, {})
        if not subcategories:
            raise ValueError("Invalid workout category selected.")
        subcategories = OrderedDict(subcategories.items())
        total_target = resolve_duration_total(duration_minutes, category_key)

    restrict_barbell = bool(equipment_tokens) and "BARBELL" not in equipment_tokens
    restrict_dumbbell = bool(equipment_tokens) and "DUMBBELL" not in equipment_tokens
    mode_value = (str(catalog_mode).strip().lower() if catalog_mode is not None else "default")
    if mode_value not in {"default", "gym"}:
        mode_value = "default"
    try:
        gym_id_value = int(catalog_gym_id) if catalog_gym_id not in (None, "") else None
    except (TypeError, ValueError):
        gym_id_value = None
    if mode_value != "gym" or gym_id_value is None or gym_id_value <= 0:
        mode_value = "default"
        gym_id_value = None
    default_catalog_gym_id = get_default_catalog_gym_id()

    workout_plan = OrderedDict()

    profile = get_user_injury_profile(user_id)
    excluded_categories = compute_injury_exclusions(profile['regions'], profile['cardio_restriction'])

    priority_key = CUSTOM_WORKOUT_TOKEN if is_custom else category_key
    counts = allocate_counts(
        subcategories,
        scale,
        priority_key,
        total_override=total_target,
    )

    skipped = {
        'regions': list(profile['regions']),
        'cardio_restriction': profile['cardio_restriction'],
        'categories': set(),
        'subcategories': set(),
    }
    recent_exercise_context = _build_recent_exercise_context(user_id, counts.keys())

    with get_connection() as conn:
        with conn.cursor() as cursor:
            for subcategory, n in counts.items():
                if n <= 0:
                    continue
                normalized_subcategory = _normalize_region(subcategory)
                subcategory_key = (subcategory or '').strip().upper()
                if normalized_subcategory and normalized_subcategory in INJURY_REGION_CATEGORY_MAP:
                    mapped = INJURY_REGION_CATEGORY_MAP[normalized_subcategory]
                    if mapped & excluded_categories:
                        skipped['subcategories'].add(subcategory_key)
                        skipped['categories'].update(mapped)
                        continue
                if subcategory_key in excluded_categories:
                    skipped['subcategories'].add(subcategory_key)
                    continue

                use_cardio_bodyweight_override = (
                    is_home and allow_cardio_bodyweight and subcategory_key == "CARDIO"
                )

                query = """
                    SELECT
                        w.id AS workout_id,
                        w.name,
                        w.description,
                        w.youtube_id,
                        w.image_exercise_start,
                        w.image_exercise_end,
                        uep.max_weight,
                        uep.max_reps,
                        uep.notes,
                        w.movement_type
                    FROM workouts w
                    LEFT JOIN user_exercise_progress uep
                        ON w.id = uep.workout_id AND uep.user_id = %s
                    WHERE w.category = %s AND w.level <= %s
                """
                params = [user_id, subcategory, user_level]
                if mode_value == "gym" and gym_id_value:
                    if default_catalog_gym_id and gym_id_value == default_catalog_gym_id:
                        query += " AND (w.gym_id = %s OR w.gym_id IS NULL)"
                        params.append(gym_id_value)
                    else:
                        query += " AND w.gym_id = %s"
                        params.append(gym_id_value)
                elif default_catalog_gym_id:
                    query += " AND (w.gym_id = %s OR w.gym_id IS NULL)"
                    params.append(default_catalog_gym_id)
                else:
                    query += " AND w.gym_id IS NULL"
                if equipment_clause:
                    if use_cardio_bodyweight_override:
                        placeholders = ",".join(["%s"] * len(CARDIO_BODYWEIGHT_WORKOUTS))
                        query += f" AND (({equipment_clause}) OR w.name IN ({placeholders}))"
                        params.extend(equipment_params)
                        params.extend(CARDIO_BODYWEIGHT_WORKOUTS)
                    else:
                        query += f" AND {equipment_clause}"
                        params.extend(equipment_params)
                elif use_cardio_bodyweight_override:
                    placeholders = ",".join(["%s"] * len(CARDIO_BODYWEIGHT_WORKOUTS))
                    query += f" AND w.name IN ({placeholders})"
                    params.extend(CARDIO_BODYWEIGHT_WORKOUTS)
                if restrict_barbell:
                    query += " AND LOWER(w.name) NOT LIKE %s"
                    params.append("%barbell%")
                if restrict_dumbbell:
                    query += " AND LOWER(w.name) NOT LIKE %s"
                    params.append("%dumbbell%")
                query += """
                    ORDER BY RANDOM()
                """
                cursor.execute(query, params)
                results = cursor.fetchall()
                subcategory_context = recent_exercise_context.get(subcategory_key, {})
                candidate_groups = _partition_candidate_rows(
                    results,
                    subcategory_context.get('active') or set(),
                    subcategory_context.get('assigned_sessions') or set(),
                    subcategory_context.get('recent_sessions') or [],
                )
                selected_rows = _select_ranked_rows(candidate_groups, n, subcategory_key)
                ordered_results, has_compound = prioritize_movement_types(selected_rows)
                if subcategory_key == 'LEGS':
                    ordered_results, _ = group_leg_press_rows(ordered_results)
                if ordered_results and has_compound:
                    first_type = (ordered_results[0][-1] or '').lower()
                    if first_type != 'compound':
                        logger.warning(
                            "Compound ordering sanity check failed for %s (first=%s)",
                            subcategory_key or subcategory,
                            first_type or 'unknown',
                        )
                exercises = [row[:-1] for row in ordered_results]
                if not exercises and subcategory_key in excluded_categories:
                    skipped['subcategories'].add(subcategory_key)
                    continue
                workout_plan[subcategory] = exercises

    skipped['categories'].update(excluded_categories)
    skipped['categories'] = sorted({cat.upper() for cat in skipped['categories']})
    skipped['subcategories'] = sorted({sub.upper() for sub in skipped['subcategories']})

    return workout_plan, skipped


def parse_range(value):
    """Extract numbers from a string like '8-12' or '30-60 seconds'."""
    minutes = 'minute' in value
    numbers = list(map(int, re.findall(r'\d+', value)))
    return [n * 60 if minutes else n for n in numbers]

def format_range(values, is_rest=False):
    if not values:
        return "N/A"
    min_val = min(values)
    max_val = max(values)

    # Special formatting for Rest values
    if is_rest:
        if max_val < 90:
            # Show both as seconds
            return f"{min_val}–{max_val} seconds" if min_val != max_val else f"{min_val} seconds"
        elif min_val >= 120:
            # Show both in minutes
            min_min = min_val // 60
            max_min = max_val // 60
            return f"{min_min}–{max_min} minutes" if min_min != max_min else f"{min_min} minutes"
        else:
            # Mixed case: seconds to minutes
            max_min = max_val // 60
            return f"{min_val} seconds – {max_min} minutes"
    else:
        # For Sets and Reps
        return f"{min_val}–{max_val}" if min_val != max_val else f"{min_val}"


def get_guidelines(exercise_history, fitness_goals):
    # Define guidelines based on exercise history and fitness goals
    level = LEVEL_MAP.get(exercise_history, 1)  # Default to Beginner (Level 1)

    if isinstance(fitness_goals, str):
        fitness_goals = [g.strip().title() for g in fitness_goals.split(",")]
    else:
        fitness_goals = [g.title() for g in fitness_goals]

    guidelines = {
        1: {  # Beginner
            "Lose Weight": {"Sets": "2-3", "Reps": "10-15", "Rest": "30-60 seconds"},
            "Gain Muscle": {"Sets": "3", "Reps": "8-12", "Rest": "60-90 seconds"},
            "Tone Muscle": {"Sets": "3", "Reps": "8-12", "Rest": "45-60 seconds"},
            "Abs": {"Sets": "2-3", "Reps": "12-20", "Rest": "30-45 seconds"},
            "Increase Strength": {"Sets": "3", "Reps": "5-8", "Rest": "90-120 seconds"},
            "Increase Endurance": {"Sets": "2-3", "Reps": "15-20", "Rest": "30-45 seconds"},
            "Feel Better": {"Sets": "2-3", "Reps": "10-15", "Rest": "30-60 seconds"}
        },
        2: {  # Intermediate
            "Lose Weight": {"Sets": "3-4", "Reps": "10-12", "Rest": "30-45 seconds"},
            "Gain Muscle": {"Sets": "4", "Reps": "6-12", "Rest": "60 seconds"},
            "Tone Muscle": {"Sets": "4", "Reps": "8-12", "Rest": "30-45 seconds"},
            "Abs": {"Sets": "3-4", "Reps": "15-20", "Rest": "30-45 seconds"},
            "Increase Strength": {"Sets": "4", "Reps": "4-6", "Rest": "2-3 minutes"},
            "Increase Endurance": {"Sets": "3-4", "Reps": "15-25", "Rest": "30 seconds"},
            "Feel Better": {"Sets": "3-4", "Reps": "10-15", "Rest": "30-45 seconds"}
        },
        3: {  # Advanced
            "Lose Weight": {"Sets": "3-5", "Reps": "8-12", "Rest": "15-30 seconds"},
            "Gain Muscle": {"Sets": "3-5", "Reps": "6-10", "Rest": "30-60 seconds"},
            "Tone Muscle": {"Sets": "3-5", "Reps": "8-10", "Rest": "30 seconds"},
            "Abs": {"Sets": "3-5", "Reps": "15-25", "Rest": "30 seconds"},
            "Increase Strength": {"Sets": "3-5", "Reps": "3-5", "Rest": "2-3 minutes"},
            "Increase Endurance": {"Sets": "3-5", "Reps": "20-30", "Rest": "15-30 seconds"},
            "Feel Better": {"Sets": "3-4", "Reps": "12-15", "Rest": "30 seconds"}
        }
    }

    goals = [g for g in fitness_goals if g in guidelines[level]]
    if not goals:
        return {}

    sets = []
    reps = []
    rest = []

    for goal in goals:
        g = guidelines[level][goal]
        sets += parse_range(g["Sets"])
        reps += parse_range(g["Reps"])
        rest += parse_range(g["Rest"])

    return {
        "Sets": format_range(sets),
        "Reps": format_range(reps),
        "Rest": format_range(rest, is_rest=True)
    }


def fmt_utc(dt):
    """Render an aware datetime in a friendly UTC string."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def int_or_none(v):
    try: return int(str(v).strip())
    except (TypeError, ValueError): return None


def inches_0_11_or_none(v):
    try: return max(0, min(11, int(float(str(v).strip()))))
    except (TypeError, ValueError): return None


def float_or_none(v):
    try:
        return float(str(v).strip())
    except (TypeError, ValueError):
        return None
    

def check_and_downgrade_trial(user_id):
    print("🔎Running check_and_downgrade_trial for user:", user_id)
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT role, subscription_type, trial_end_date
                FROM users
                WHERE id = %s
            """, (user_id,))
            result = cur.fetchone()
            if not result:
                return

            role, subscription_type, trial_end_date = result
            role = (role or '').strip().lower()
            subscription_type = (subscription_type or '').strip().lower()
            today = datetime.today().date()

            if not trial_end_date:
                return
            if today < trial_end_date:
                return

            new_role = 'user' if role == 'trainer' else role
            new_subscription = 'free' if subscription_type in {'premium', 'pro'} else subscription_type
            if new_role != role or new_subscription != subscription_type:
                cur.execute(
                    """
                    UPDATE users
                       SET role = %s,
                           subscription_type = %s,
                           session_version = COALESCE(session_version, 0) + 1,
                           updated_at = CURRENT_TIMESTAMP
                     WHERE id = %s
                     RETURNING session_version
                    """,
                    (new_role, new_subscription, user_id),
                )
                row = cur.fetchone()
                conn.commit()
                print("🔻User's trial expired. Downgraded account privileges.")

                if session.get('user_id') == user_id:
                    session['role'] = new_role
                    session['is_admin'] = False
                    if row and row[0] is not None:
                        session['session_version'] = row[0]


def check_subscription_expiry(user_id):
    print("🔎 Running check_subscription_expiry for user:", user_id)
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT subscription_type, subscription_cancel_at
                FROM users
                WHERE id = %s
            """, (user_id,))
            result = cursor.fetchone()

            if not result:
                return  # User not found

            subscription_type, cancel_at = result

            if subscription_type in ('premium', 'pro') and cancel_at:
                # Compare current time with cancel_at
                if cancel_at.tzinfo is None:
                    cancel_at = cancel_at.replace(tzinfo=timezone.utc)

                now = datetime.now(timezone.utc)

                print(f"Now: {now} (tz: {now.tzinfo}), Cancel At: {cancel_at} (tz: {cancel_at.tzinfo})")

                if now > cancel_at:
                    # Downgrade the user
                    cursor.execute("""
                        UPDATE users
                        SET subscription_type = 'free',
                            subscription_cancel_at = NULL,
                            role = CASE WHEN role = 'trainer' THEN 'user' ELSE role END,
                            session_version = COALESCE(session_version, 0) + 1
                        WHERE id = %s
                        RETURNING session_version
                    """, (user_id,))
                    row = cursor.fetchone()
                    conn.commit()

                    print("🔻User's Subscription Canceled and Ended. Downgraded to free.")

                    if session.get('user_id') == user_id and row and row[0] is not None:
                        session['session_version'] = row[0]
