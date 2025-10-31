from functools import wraps
from flask import session, redirect, url_for, flash
import os, psycopg2, re, json
import hmac, secrets, hashlib, math
from psycopg2 import connect
from psycopg2.extras import RealDictCursor, Json
from urllib.parse import urlparse
from dotenv import load_dotenv
from collections import OrderedDict
from decimal import Decimal
from datetime import datetime, timedelta, timezone

load_dotenv()

def get_connection():
    return psycopg2.connect(os.getenv("DATABASE_URL"))

ADMIN_EMAILS = [e.strip().lower() for e in os.getenv('ADMIN_EMAILS', '').split(',') if e.strip()]


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

CUSTOM_WORKOUT_TOKEN = "Custom Workout"
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
    "LEGS": 8,
    "BACK": 6,
    "CHEST": 6,
    "SHOULDERS": 5,
    "BICEPS": 4,
    "TRICEPS": 4,
    "ABS": 4,
    "CARDIO": 3,
}

CUSTOM_WORKOUT_SELECTION_LIMITS = {
    20: {"min": 1, "max": 3},
    30: {"min": 1, "max": 4},
    45: {"min": 1, "max": 6},
    60: {"min": 1, "max": 8},
}

CUSTOM_WORKOUT_TOTAL_EXERCISES = {
    20: 3,
    30: 4,
    45: 7,
    60: 10,
}

def normalize_custom_workout_categories(categories) -> list[str]:
    seen = set()
    normalized: list[str] = []
    for raw in categories or []:
        token = (str(raw) or '').strip().upper()
        if token and token in CUSTOM_WORKOUT_CATEGORIES and token not in seen:
            seen.add(token)
            normalized.append(token)
    return normalized


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
        """, (user_id, purpose, digest, expires_at))
    return raw_token, expires_at



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

    # ---- 4) Ensure representation in priority order ----
    i = 0
    while i < len(ordered_keys) and sum(counts.values()) < target_total:
        counts[ordered_keys[i]] += 1
        i += 1

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


def generate_workout(selected_category, user_level, user_id, duration_minutes=60, custom_categories=None):
    """
    Generate a workout based on the selected category, user level, and preferred duration.
    Respects user injury restrictions by omitting excluded categories.
    Returns the workout plan and a metadata dictionary describing skipped content.
    """
    try:
        duration_minutes = int(duration_minutes or 60)
    except (TypeError, ValueError):
        duration_minutes = 60

    BASE_MINUTES = 60  # new baseline
    scale = duration_minutes / BASE_MINUTES

    # Clamp scale to avoid crazy extremes
    scale = max(0.33, min(1.0, scale))
    # → 20 mins = ~0.33x, 30 = 0.5x, 45 = 0.75x, 60 = 1.0x

    category_key = (selected_category or "").strip()
    is_custom = category_key == CUSTOM_WORKOUT_TOKEN

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
        total_target = CUSTOM_WORKOUT_TOTAL_EXERCISES.get(duration_minutes)
        if total_target is None:
            # Default to a proportional scale similar to main program (roughly 10 exercises per hour)
            proportional = max(3, round((duration_minutes or 60) * (10 / 60)))
            total_target = proportional
        total_target = max(len(normalized), total_target)
    else:
        structure = WORKOUT_STRUCTURE.get(user_level, {})
        subcategories = structure.get(category_key, {})
        if not subcategories:
            raise ValueError("Invalid workout category selected.")
        subcategories = OrderedDict(subcategories.items())

    workout_plan = OrderedDict()

    profile = get_user_injury_profile(user_id)
    excluded_categories = compute_injury_exclusions(profile['regions'], profile['cardio_restriction'])

    priority_key = CUSTOM_WORKOUT_TOKEN if is_custom else category_key
    counts = allocate_counts(
        subcategories,
        scale,
        priority_key,
        total_override=total_target if is_custom else None,
    )

    skipped = {
        'regions': list(profile['regions']),
        'cardio_restriction': profile['cardio_restriction'],
        'categories': set(),
        'subcategories': set(),
    }

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
                        uep.notes
                    FROM workouts w
                    LEFT JOIN user_exercise_progress uep
                        ON w.id = uep.workout_id AND uep.user_id = %s
                    WHERE w.category = %s AND w.level <= %s
                    ORDER BY RANDOM()
                    LIMIT %s
                """
                cursor.execute(query, (user_id, subcategory, user_level, n))
                exercises = cursor.fetchall()
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
            "Lose Weight": {"Sets": "4-5", "Reps": "8-12", "Rest": "15-30 seconds"},
            "Gain Muscle": {"Sets": "5", "Reps": "6-10", "Rest": "30-60 seconds"},
            "Tone Muscle": {"Sets": "4-5", "Reps": "8-10", "Rest": "30 seconds"},
            "Abs": {"Sets": "4-5", "Reps": "15-25", "Rest": "30 seconds"},
            "Increase Strength": {"Sets": "5", "Reps": "3-5", "Rest": "2-3minutes"},
            "Increase Endurance": {"Sets": "4-5", "Reps": "20-30", "Rest": "15-30 seconds"},
            "Feel Better": {"Sets": "4", "Reps": "12-15", "Rest": "30 seconds"}
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
                SELECT subscription_type, trial_end_date
                FROM users
                WHERE id = %s
            """, (user_id,))
            result = cur.fetchone()

            if not result:
                return

            subscription_type, trial_end_date = result
            today = datetime.today().date()

            if not trial_end_date:
                return
            
            if subscription_type == 'premium' and trial_end_date and today >= trial_end_date:
                # Trial expired → downgrade to 'free'
                cur.execute("""
                    UPDATE users
                    SET subscription_type = 'free'
                    WHERE id = %s
                """, (user_id,))
                conn.commit()

                print("🔻User's trial expired. Downgraded to free.")


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

            if subscription_type == 'premium' and cancel_at:
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
                            subscription_cancel_at = NULL
                        WHERE id = %s
                    """, (user_id,))
                    conn.commit()

                    print("🔻User's Subscription Canceled and Ended. Downgraded to free.")

                    
