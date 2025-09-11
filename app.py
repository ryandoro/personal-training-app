import os, re, logging, json, psycopg2, psycopg2.extras, psycopg2.errors, stripe
from flask import Flask, flash, redirect, render_template, request, session, jsonify, url_for, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from helpers import login_required, convert_decimals, calculate_target_heart_rate, generate_workout, get_guidelines, get_connection, is_admin, normalize_email, upsert_invited_user, issue_single_use_token, validate_token, mark_token_used, username_available, fmt_utc, int_or_none, inches_0_11_or_none, float_or_none, hash_token, get_category_groups, get_user_level, LEVEL_MAP, check_and_downgrade_trial, check_subscription_expiry  
from collections import OrderedDict
from dotenv import load_dotenv
from datetime import datetime, date, timedelta, timezone
from mail import send_email, send_password_reset_email, send_invite_email, send_verification_email
from urllib.parse import urlencode 

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
price_id = os.getenv("STRIPE_PREMIUM_PRICE_ID")
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

@app.route('/')
@login_required
def home():
    """Show user's stats and progress."""
    # Get the user ID from the session
    user_id = session['user_id']        

    # Connect to the database to fetch the username
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT name, fitness_goals, workouts_completed, last_workout_completed, form_completed 
                FROM users 
                WHERE id = %s
            """, (user_id,))
            user = cursor.fetchone()
        
    # Ensure the user exists
    if user is None:
        flash("User not found.", "danger")
        return redirect('/logout')

    # Extract the name from the result
    name = user[0]
    fitness_goals = user[1] if user[1] else "Not set yet" # Default message if no goals yet
    workouts_completed = user[2] if user[2] is not None else 0  # Default to 0 if no value
    last_workout_completed = user[3] if user[3] else "No workouts completed yet"
    form_completed = user[4]

    return render_template(
        'index.html', 
        name=name if form_completed else None, 
        fitness_goals=fitness_goals, 
        workouts_completed=workouts_completed,
        last_workout_completed=last_workout_completed,
        form_completed=form_completed
    )



@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect('/')

    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        raw_email = (request.form.get('email') or '').strip()
        email = raw_email.lower() or None
        password = request.form.get('password') or ''
        confirmation = request.form.get('confirmation') or ''

        if not username:
            flash("Username is required", "danger"); return render_template('register.html')
        if not raw_email:
            flash("Email is required", "danger"); return render_template('register.html')
        if not re.match(r"^[^@]+@[^@]+\.[^@]+$", raw_email):
            flash("Please enter a valid email address.", "danger"); return render_template('register.html')
        if not password or not confirmation:
            flash("Password and confirmation are required", "danger"); return render_template('register.html')
        if len(username) > 50 or len(username) < 3:
            flash("Username must be 3–50 characters", "danger"); return render_template('register.html')
        if len(password) < 8:
            flash("Password must be at least 8 characters", "danger"); return render_template('register.html')
        if not any(c.isupper() for c in password):
            flash("Password must include at least one uppercase letter", "danger"); return render_template('register.html')
        if not any(c in "!@#$%^&*()-_+=<>?/{}~" for c in password):
            flash("Password must include at least one special character", "danger"); return render_template('register.html')
        if password != confirmation:
            flash("Passwords do not match", "danger"); return render_template('register.html')

        with get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                # Check username exists (case-insensitive, to match login behavior)
                cur.execute("SELECT 1 FROM users WHERE lower(username)=lower(%s) LIMIT 1", (username,))
                if cur.fetchone():
                    flash("Username already exists", "danger")
                    return render_template('register.html')

                # Optional: pre-check email if provided
                if email:
                    cur.execute("SELECT 1 FROM users WHERE lower(email)=lower(%s) LIMIT 1", (email,))
                    if cur.fetchone():
                        flash("An account with that email already exists", "danger")
                        return render_template('register.html')

                hashed_password = generate_password_hash(password)

                try:
                    cur.execute("""
                        INSERT INTO users (username, hash, email, email_verified)
                        VALUES (%s, %s, %s, %s)
                        RETURNING id
                    """, (username, hashed_password, email, False))
                    user_row = cur.fetchone()
                    user_id = user_row['id']

                    # Issue verification token 
                    raw_token, expires_at = issue_single_use_token(conn, user_id, "verify_email", VERIFY_TTL_HOURS)  
                    verify_url = url_for("verify_email", token=raw_token, _external=True)
                    resend_url  = url_for("resend_verify_confirm", token=raw_token, _external=True)

                    conn.commit()

                except psycopg2.Error as e:
                    if isinstance(e, psycopg2.errors.UniqueViolation):
                        flash("That username or email is already in use", "danger")
                    else:
                        flash("Error creating account", "danger")
                    conn.rollback()
                    return render_template('register.html')

        # Send welcome + verify email
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

    return render_template('register.html')


@app.route('/verify_email')
def verify_email():
    token = request.args.get('token', '').strip()
    if not token:
        flash("Invalid verification link.", "danger")
        return redirect(url_for('login'))

    try:
        with get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                # Validate and consume token using your existing helper
                token_row = validate_token(conn, token, "verify_email")  # should raise/return None if invalid/expired
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
    raw = (request.args.get("token") or "").strip()
    token_digest = hash_token(raw) if raw else ""
    # Always show the confirm page (no enumeration)
    return render_template("resend_verify_confirm.html", token_digest=token_digest)



@app.post("/verify/resend")
def resend_verify_do():
    """POST: actually issue a new token and email."""
    generic_msg = "If an account exists and isn’t verified, we’ve sent a new verification link."
    digest = (request.form.get("token_digest") or "").strip()

    if not digest:
        flash(generic_msg, "info")
        return redirect(url_for("login"))

    try:
        with get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT u.id AS user_id, u.email, u.username, u.email_verified
                      FROM user_tokens ut
                      JOIN users u ON u.id = ut.user_id
                     WHERE ut.purpose = %s
                       AND ut.token_digest = %s
                     LIMIT 1
                """, (VERIFY_PURPOSE, digest))
                row = cur.fetchone()

                if not row:
                    flash("That link is invalid or no longer available. If you still need access, try again from your latest email.", "info")
                    return redirect(url_for("login"))

                if row["email_verified"]:
                    flash("Your email is already verified. Please log in.", "success")
                    return redirect(url_for("login"))

                # Rate limit based on last token creation
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
                    last_ts = last["created_at"]  # already aware
                    # if your DB ever returns naive (unlikely), guard it:
                    if last_ts.tzinfo is None:
                        last_ts = last_ts.replace(tzinfo=timezone.utc)

                    delta = now - last_ts
                    if (delta) < timedelta(seconds=RESEND_COOLDOWN_SECONDS):
                        remaining = max(1, RESEND_COOLDOWN_SECONDS - int((delta.total_seconds())))
                        flash(f"A verification email was just sent. Please verify or try again in ~{remaining}s.", "warning")
                        return redirect(url_for("login"))
                
                # Invalidate prior unused verify tokens (optional but recommended)
                cur.execute("""
                    UPDATE user_tokens
                        SET used_at = %s
                     WHERE user_id = %s 
                        AND purpose = %s 
                        AND used_at IS NULL
                """, (now, row["user_id"], VERIFY_PURPOSE))

                # Issue new token
                new_raw, _expires_at = issue_single_use_token(conn, row["user_id"], VERIFY_PURPOSE, VERIFY_TTL_HOURS)
                new_verify_url = url_for("verify_email", token=new_raw, _external=True)
                new_resend_url  = url_for("resend_verify_confirm", token=new_raw, _external=True)
                conn.commit()

        # Send email outside transaction
        send_verification_email(
            to_email=row["email"],
            first_name=row["username"],
            verify_url=new_verify_url,
            ttl_hours=VERIFY_TTL_HOURS,
            resend_url=new_resend_url
        )
        flash("We've sent you a new verification link.", "success")
        return redirect(url_for("login"))

    except Exception:
        current_app.logger.exception("Resend via token failed")
        flash(generic_msg, "info")
        return redirect(url_for("login"))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('home'))  # or '/'

    if request.method == 'POST':
        session.clear()

        identifier = (request.form.get('username') or '').strip()  # username OR email
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
        session['role'] = user.get('role')
        session['is_admin'] = (user.get('role') == 'admin')

        # Stamp last login
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE users SET last_login_at = now() WHERE id = %s", (user['id'],))
                conn.commit()

        flash("Login successful!", "success")
        return redirect(url_for('home'))  # or wherever

    return render_template('login.html')


@app.before_request
def check_trial_status_and_subscription():
    print("Before request endpoint:", request.endpoint)
    if 'user_id' not in session:
        return

    # Skip checks for static files and public routes
    if request.endpoint in ['static', 'login', 'register', 'logout', None]:
        return

    # Only run the checks once per day per user session
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



@app.route('/training', methods=['GET', 'POST'])
@login_required
def training():
    """Handle personal training form and display workout options."""
    user_id = session['user_id']
        # 🔒 Always enforce downgrade check before premium content
    check_and_downgrade_trial(user_id)
    check_subscription_expiry(user_id)
    form_completed = False  # Default flag to determine what to show

    try:
        # Check if the form has already been completed
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT form_completed, exercise_history, fitness_goals, workout_duration FROM users WHERE id = %s", (user_id,))
                result = cursor.fetchone()
                form_completed = bool(result[0])  # Retrieve form_completed status
                exercise_history = result[1]  # Fetch exercise history
                fitness_goals = result[2]  # Fetch fitness goals
                workout_duration = result[3]
    except Exception as e:
        flash(f"An error occurred: {e}", "danger")
        return render_template('training.html', form_completed=False)

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
        injury = request.form.get('injury')
        injury_details = request.form.get('injury_details')
        workout_duration_raw = request.form.get('workout_duration')
        commitment = request.form.get('commitment')
        additional_notes = request.form.get('additional_notes')

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

        # Checkboxes (1–2 goals)
        if len(fitness_goals) < 1 or len(fitness_goals) > 2:
            errors['fitness_goals'] = "Please select 1–2 fitness goals."

        # Injury details (only if 'Yes')
        if injury == "Yes" and not (injury_details or "").strip():
            errors['injury_details'] = "Please describe your injury/illness."

        allowed_durations = {"20", "30", "45", "60"}
        if workout_duration_raw not in allowed_durations:
            errors['workout_duration'] = "Please select a valid workout duration."
            
        if errors:
            flash("Please fix the highlighted fields.", "danger")
            # Re-render with what the user typed + which fields failed
            return render_template(
                'training.html',
                form_completed=False,
                form_data=request.form,
                errors=errors
            ), 400
        
        workout_duration = int(workout_duration_raw)

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
                            injury = %s, injury_details = %s, commitment = %s, additional_notes = %s, 
                            name = %s, last_name = %s, form_completed = TRUE, workout_duration = %s,
                            subscription_type = 'premium',
                            trial_end_date = %s
                        WHERE id = %s
                    """, (
                        age, weight, height_feet, height_inches, gender, 
                        exercise_history, fitness_goals_str, injury, injury_details, 
                        commitment, additional_notes, name, last_name, workout_duration, 
                        trial_end_date, user_id
                    ))
                    conn.commit()

                    flash("✅ Your 14-day free Premium trial has started! You now have full access to the personalized workout generator and tracking.", "success")

            form_completed = True  # Mark the form as completed
            flash("Your information has been successfully updated!", "success")
        except Exception as e:
            flash(f"An error occurred: {e}", "danger")
            return render_template('training.html', form_completed=False)
        
    # Fetch and organize workouts into groupings
   # categories = {
     #   "Chest and Triceps": ["CHEST", "TRICEPS"],
      #  "Back and Biceps": ["BACK", "BICEPS"],
       # "Shoulders and Abs": ["SHOULDERS", "ABS"],
        #"Arms": ["BICEPS", "TRICEPS", "SHOULDERS"],
       # "Legs": ["LEGS"],
       # "Upper Body": ["BACK", "CHEST", "SHOULDERS", "BICEPS", "TRICEPS"],
        #"Full Body": ["BACK", "CHEST", "SHOULDERS", "BICEPS", "TRICEPS", "LEGS", "ABS"],
        #"Cardio": ["CARDIO"],
    #}

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
                    query = f"SELECT name, description FROM workouts WHERE category IN ({placeholders})"
                    cursor.execute(query, group)
                    grouped_workouts[category] = cursor.fetchall()

                # Fetch the user's exercise history and age
                cursor.execute("SELECT exercise_history, age, fitness_goals FROM users WHERE id = %s", (user_id,))
                user_data = cursor.fetchone()

                if user_data:
                    exercise_history = user_data[0]
                    age = int(user_data[1]) if user_data[1] else None
                    fitness_goals = user_data[2] if user_data[2] else "Not set yet"

                    # Mapping exercise history to numeric levels
            #        level_map = {
             #           "No Exercise History": 1,
              #          "Exercise less than 1 year": 1,
               #         "Exercise 1-5 years": 2,
                #        "Exercise 5+ years": 3
                 #   }
                   #user_level = level_map.get(exercise_history, 1)  # Default to 1 if not found

                    user_level = get_user_level(exercise_history)

                    # Calculate target heart rate zone
                    if age:
                        target_heart_rate_zone = calculate_target_heart_rate(age)

                    # Fetch workouts matching the user's level
                    cursor.execute("SELECT name, description FROM workouts WHERE level <= %s", (user_level,))
                    workouts = cursor.fetchall()

                    # Fetch guidelines based on user's level and fitness goals
                    if exercise_history and fitness_goals:
                        guidelines = get_guidelines(exercise_history, fitness_goals)

                else:
                    flash("User information not found. Please update your profile.", "warning")

            except Exception as e:
                flash(f"An error occurred: {e}", "danger")

    # Fetch full user row (including subscription_type, trial_end_date, etc.)
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            user = cursor.fetchone()

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
        current_date=date.today()
    )


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
    selected_category = request.args.get('category')
    if not selected_category:
        return jsonify({'success': False, 'error': 'No category selected'})

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
                if selected_category != 'Shoulders and Abs':
                    return jsonify({'success': False, 'error': 'Upgrade to Premium to access this category.'})

            user_level = get_user_level(exercise_history)

    # Generate the workout
    workout_plan = generate_workout(selected_category, user_level, user_id, duration_minutes)

    # Save the exact workout and category to the session
    session['generated_workout'] = {
        'category': selected_category,
        'duration_minutes': duration_minutes,
        'workout': json.dumps(convert_decimals(workout_plan))  # Save the randomly generated workout structure
    }

    # Format the workout for the response
    formatted_workout = [
        {
            'subcategory': subcategory,
            'exercises': [
                {
                    'workout_id': exercise[0],
                    'name': exercise[1],
                    'description': exercise[2],
                    'youtube_id': exercise[3],
                    'image_exercise_start': exercise[4],
                    'image_exercise_end': exercise[5],
                    'max_weight': exercise[6],
                    'max_reps': exercise[7],
                    'category': selected_category
                }
                for exercise in exercises
            ]
        }
        for subcategory, exercises in workout_plan.items()
    ]

    return jsonify({'success': True, 'workout': formatted_workout})



@app.route('/complete_workout', methods=['POST'])
@login_required
def complete_workout():
    user_id = session['user_id']

    # Ensure a workout was generated and saved in the session
    if 'generated_workout' not in session:
        return jsonify({'success': False, 'error': 'No workout generated'}), 400

    # Retrieve the generated workout from the session
    generated_workout = session.pop('generated_workout', None)
    if not generated_workout:
        return jsonify({'success': False, 'error': 'No workout data available'}), 400

    # Extract category and workout details
    workout_category = generated_workout['category']
    # Get fresh max values for all exercises in the generated workout
    refreshed_workout = OrderedDict()

    with get_connection() as conn:
        with conn.cursor() as cursor:
            workout_data = json.loads(generated_workout['workout'], object_pairs_hook=OrderedDict)
            for subcat, exercises in workout_data.items():
            #for subcat, exercises in generated_workout['workout'].items():
                refreshed_workout[subcat] = []
                for ex in exercises:
                    workout_id = ex[0]  # assuming (id, name, desc) structure
                    cursor.execute("""
                        SELECT w.name, w.description, uep.max_weight, uep.max_reps
                        FROM workouts w
                        LEFT JOIN user_exercise_progress uep
                            ON w.id = uep.workout_id AND uep.user_id = %s
                        WHERE w.id = %s
                    """, (user_id, workout_id))
                    result = cursor.fetchone()
                    if result:
                        name, description, max_weight, max_reps = result
                        refreshed_workout[subcat].append({
                            "name": name,
                            "description": description,
                            "max_weight": float(max_weight) if max_weight is not None else None,
                            "max_reps": max_reps
                        })
            # Store the workout details and increment the workout counter
            # Save refreshed workout details
            cursor.execute("""
                UPDATE users
                SET workouts_completed = COALESCE(workouts_completed, 0) + 1,
                    last_workout_completed = %s,
                    last_workout_details = %s
                WHERE id = %s
            """, (workout_category, json.dumps(refreshed_workout), user_id))
            conn.commit()

    return jsonify({'success': True})



@app.route('/workout_details/<category>', methods=['GET'])
@login_required
def workout_details(category):
    user_id = session['user_id']

    with get_connection() as conn:
        with conn.cursor() as cursor:

            # Fetch the last workout details for the given category
            cursor.execute("""
                SELECT last_workout_details
                FROM users
                WHERE id = %s AND last_workout_completed = %s
            """, (user_id, category))
            result = cursor.fetchone()

    if not result or not result[0]:
        return render_template('workout_details.html', category=category, workouts=None)

    # Parse the stored JSON workout details
    #raw_workouts = json.loads(result[0])

    # Reformat the data for the template
    #workouts = {
    #    subcategory: [
    #        {
    #            "name": exercise["name"],
    #            "description": exercise["description"],
    #            "max_weight": exercise["max_weight"],
    #            "max_reps": exercise["max_reps"]
    #        }
    #        for exercise in exercises
    #    ]
    #    for subcategory, exercises in raw_workouts.items()
    #}
    # Load and preserve subcategory order
    workouts = json.loads(result[0], object_pairs_hook=OrderedDict)

    return render_template('workout_details.html', category=category, workouts=workouts)



@app.route('/update_pr', methods=['POST'])
@login_required
def update_pr():
    data = request.get_json()
    user_id = session['user_id']
    workout_id = data['workout_id']
    max_weight = data['max_weight']
    max_reps = data['max_reps']

    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO user_exercise_progress (user_id, workout_id, max_weight, max_reps)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (user_id, workout_id) DO UPDATE
                SET max_weight = EXCLUDED.max_weight,
                    max_reps = EXCLUDED.max_reps,
                    updated_at = CURRENT_TIMESTAMP
            """, (user_id, workout_id, max_weight, max_reps))
            conn.commit()

    return jsonify({'success': True})


@app.route("/search")
@login_required
def search():
    query = request.args.get("q", "").strip()

    if not query:
        flash("Please enter a search term.", "warning")
        return redirect("/training")

    db = get_connection()
    cursor = db.cursor()
    cursor.execute("""
        SELECT w.id, w.name, w.description, w.category, uep.max_weight, uep.max_reps
        FROM workouts w
        LEFT JOIN user_exercise_progress uep
        ON w.id = uep.workout_id AND uep.user_id = %s
        WHERE LOWER(w.name) LIKE LOWER(%s)
    """, (session["user_id"], f"%{query}%"))
    results = cursor.fetchall()

    return render_template("search_results.html", query=query, results=results)


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

        # Uniform message to avoid account enumeration
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
                raw_token, expires_at = issue_single_use_token(conn, user_id, "reset_password", RESET_TTL_HOURS)
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
                       gender, exercise_history, fitness_goals, injury, injury_details,
                       commitment, additional_notes, form_completed, workout_duration,
                        subscription_type, trial_end_date
                FROM users
                WHERE id = %s
            """, (user_id,))
            row = cursor.fetchone()
    columns = ['username', 'name', 'last_name', 'email', 'age', 'weight', 'height_feet', 'height_inches',
                'gender', 'exercise_history', 'fitness_goals', 'injury', 'injury_details',
                'commitment', 'additional_notes', 'form_completed', 'workout_duration',
                'subscription_type', 'trial_end_date']

    user = dict(zip(columns, row)) if row else {k: "" for k in columns}
    for k in columns:
        if user.get(k) is None:
            user[k] = ""

    form_completed = bool(user.get('form_completed'))

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
                return render_template('settings.html', user=user, form_completed=form_completed)
            if len(password) < 8:
                flash("Password must be at least 8 characters long.", "danger")
                return render_template('settings.html', user=user, form_completed=form_completed)
            if not any(char.isupper() for char in password):
                flash("Password must include at least one uppercase letter.", "danger")
                return render_template('settings.html', user=user, form_completed=form_completed)
            if not any(char in "!@#$%^&*()-_+=<>?/{}~" for char in password):
                flash("Password must include at least one special character.", "danger")
                return render_template('settings.html', user=user, form_completed=form_completed)

            hashed_password = generate_password_hash(password)
            with get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("UPDATE users SET hash = %s, session_version=session_version+1 WHERE id = %s", (hashed_password, user_id))
                    conn.commit()

            flash("Password updated successfully!", "success")
            return render_template('settings.html', user=user, form_completed=form_completed)
    
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
        injury = request.form.get('injury')
        injury_details = request.form.get('injury_details')
        commitment = request.form.get('commitment')
        additional_notes = request.form.get('additional_notes')

        workout_duration_raw = request.form.get('workout_duration')
        allowed_durations = {"20", "30", "45", "60"}
        if workout_duration_raw not in allowed_durations:
            flash("Please select a valid workout duration.", "danger")
            return render_template('settings.html', user=user, form_completed=form_completed)
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
            request.form.get('injury'),
            request.form.get('injury_details'),
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
                            gender, exercise_history, fitness_goals, injury, injury_details,
                            commitment, additional_notes, form_completed, workout_duration
                        FROM users
                        WHERE id = %s
                    """, (user_id,))
                    row = cursor.fetchone()

            user = dict(zip(columns, row)) if row else {k: "" for k in columns}
            for k in columns:
                if user.get(k) is None:
                    user[k] = ""
            form_completed = bool(user.get('form_completed'))

            return render_template('settings.html', user=user, form_completed=form_completed)

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
            return render_template('settings.html', user=user, form_completed=form_completed)

        if not (1 <= len(fitness_goals) <= 2):
            flash("Please select 1 or 2 fitness goals.", "danger")
            return render_template('settings.html', user=user, form_completed=form_completed)

        # Validate password if provided
        hashed_password = None
        if password:
            if password != confirm_password:
                flash("Passwords do not match.", "danger")
                return render_template('settings.html', user=user, form_completed=form_completed)
            if len(password) < 8:
                flash("Password must be at least 8 characters long.", "danger")
                return render_template('settings.html', user=user, form_completed=form_completed)
            if not any(char.isupper() for char in password):
                flash("Password must include at least one uppercase letter.", "danger")
                return render_template('settings.html', user=user, form_completed=form_completed)
            if not any(char in "!@#$%^&*()-_+=<>?/{}~" for char in password):
                flash("Password must include at least one special character.", "danger")
                return render_template('settings.html', user=user, form_completed=form_completed)

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
                    return render_template('settings.html', user=user, form_completed=form_completed)

                if email:
                    cursor.execute(
                        "SELECT id FROM users WHERE lower(email) = lower(%s) AND id != %s",
                        (email, user_id)
                    )
                    if cursor.fetchone():
                        flash("That email is already in use.", "danger")
                        return render_template('settings.html', user=user, form_completed=form_completed)
                    
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
                        injury = %s, injury_details = %s, commitment = %s,
                        additional_notes = %s, form_completed = %s, workout_duration = %s
                    WHERE id = %s
                """, (
                    username, name, last_name, email, age, weight, height_feet,
                    height_inches, gender, exercise_history, fitness_goals_cleaned,
                    injury, injury_details, commitment, additional_notes, new_form_completed, 
                    workout_duration, 
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
                        gender, exercise_history, fitness_goals, injury, injury_details,
                        commitment, additional_notes, form_completed, workout_duration
                    FROM users
                    WHERE id = %s
                """, (user_id,))
                row = cursor.fetchone()
        user = dict(zip(columns, row)) if row else {k: "" for k in columns}
        for k in columns:
            if user.get(k) is None:
                user[k] = ""
        form_completed = new_form_completed

    return render_template('settings.html', user=user, form_completed=form_completed, current_date=date.today())


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

    return render_template('admin_dashboard.html', users=users, search_term=search_term)


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
            'injury': request.form.get('injury'),
            'injury_details': request.form.get('injury_details'),
            'commitment': request.form.get('commitment'),
            'additional_notes': request.form.get('additional_notes'),
            'workouts_completed': request.form.get('workouts_completed') or 0
        }

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
                        commitment = %s,
                        additional_notes = %s,
                        workouts_completed = %s
                    WHERE id = %s
                """
                try:
                    cursor.execute(update_query, (
                        username_clean, data['name'], data['last_name'], email_clean,
                        data['role'], data['subscription_type'], data['email_verified'],
                        data['form_completed'], data['age'], data['weight'],
                        data['height_feet'], data['height_inches'], data['gender'],
                        data['exercise_history'], fitness_goals_str, data['injury'],
                        data['injury_details'], data['commitment'], data['additional_notes'],
                        data['workouts_completed'], user_id
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

    invite_url = request.args.get('invite_url')
    invite_expires_in = request.args.get('invite_expires_in')
    return render_template('admin_user_profile.html', user=user, invite_url=invite_url, invite_expires_in=invite_expires_in)


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
    # reuse your existing admin check
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

    # validations → use your global toast categories (message first, category second)
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

            raw_token, expires_at = issue_single_use_token(conn, user_id, "invite", INVITE_TTL_HOURS)
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

        # Optional: show the invited email on the page
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
            return redirect(url_for("training"))  # or your onboarding/home

    except psycopg2.errors.UniqueViolation:
        # In case someone raced us and took the username between check & update
        flash("That username is taken. Please pick another.", "danger")
        return redirect(url_for("accept_invite", token=token))
    except Exception:
        current_app.logger.exception("Error accepting invite")
        flash("Something went wrong while activating your account.", "danger")
        return redirect(url_for("accept_invite", token=token))


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
            raw, exp = issue_single_use_token(conn, user_id, 'invite', INVITE_TTL_HOURS)
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
            raw, exp = issue_single_use_token(conn, user_id, 'invite', INVITE_TTL_HOURS)
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
        "user": user
    }


@app.route('/upgrade')
@login_required
def upgrade():
    user_id = session["user_id"]

    # Optional: Lookup user info from your DB if needed (e.g., name or email)
    user_email = None
    full_name = None
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT email, name, last_name FROM users WHERE id = %s", (user_id,))
            result = cursor.fetchone()
            if result:
                user_email = result[0]
                full_name = f"{result[1]} {result[2]}"

    try:
        # Create Stripe customer (only if you want to store customer ID)
        customer = stripe.Customer.create(
            email=user_email,
            name=full_name,
            metadata={"user_id": user_id}
        )

        # Save stripe_customer_id to your DB
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE users SET stripe_customer_id = %s WHERE id = %s
                """, (customer.id, user_id))
                conn.commit()

        # Create a Stripe Checkout Session
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            customer=customer.id,
            line_items=[{
                'price': price_id,  
                'quantity': 1,
            }],
            mode='subscription',
            success_url=url_for('upgrade_success', _external=True),
            cancel_url=url_for('training', _external=True),
            metadata={'user_id': user_id}
        )

        return redirect(checkout_session.url)
    
    except Exception as e:
        flash(f"Error creating Stripe checkout: {e}", "danger")
        return redirect(url_for('training'))


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
        stripe_customer_id = session_data.get('customer')

        if user_id and stripe_customer_id:
            with get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        UPDATE users
                        SET subscription_type = 'premium', 
                            trial_end_date = NULL,
                            stripe_customer_id = %s,
                            subscription_cancel_at = NULL
                        WHERE id = %s
                    """, (stripe_customer_id, user_id,))
                    conn.commit()

    elif event['type'] == 'customer.subscription.updated':
        sub_data = event['data']['object']
        stripe_customer_id = sub_data.get('customer')
        cancel_at = sub_data.get('cancel_at')  # Will be None if user resumed
        cancel_at_period_end = sub_data.get('cancel_at_period_end', False)

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
                        subscription_cancel_at = NULL
                    WHERE stripe_customer_id = %s
                """, (stripe_customer_id,))
                conn.commit()
                print("🔻 Downgraded user to free tier in DB")

    return jsonify({'status': 'success'}), 200


@app.route('/upgrade-success')
@login_required
def upgrade_success():
    flash("🎉 You've successfully upgraded to Premium!", "success")
    return redirect(url_for('training'))


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
                return redirect(url_for('training'))

    # Create the session
    stripe_portal_session = stripe.billing_portal.Session.create(
        customer=stripe_customer_id,
        return_url=url_for('training', _external=True),
    )

    return redirect(stripe_portal_session.url)


if __name__ == '__main__':
    app.run(debug=True)
