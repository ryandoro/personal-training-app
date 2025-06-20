import os, logging, json
# from dotenv import load_dotenv
from flask import Flask, flash, redirect, render_template, request, session, jsonify, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from helpers import login_required, convert_decimals, calculate_target_heart_rate, generate_workout, get_guidelines, get_connection
from collections import OrderedDict

# Utilized ChatGPT to help complete this web application 
# Set up basic logging configuration
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
app.secret_key = os.urandom(24) # Required for flash messages

# Define database path based on environment
## Not using - DATABASE_PATH = os.getenv('DATABASE_URL', 'instance/health.db')


@app.route('/')
@login_required
def home():
    """Show user's stats and progress."""
    # Get the user ID from the session
    user_id = session['user_id']

    # Connect to the database to fetch the username
    ## Not using - with sqlite3.connect(DATABASE_PATH) as conn:
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
        username = request.form.get('username')
        email = request.form.get('email') or None
        password = request.form.get('password')
        confirmation = request.form.get('confirmation')

        # Check if all fields are filled
        if not username:
            flash("Username is required", "danger")
            return render_template('register.html')
        if not password:
            flash("Password is required", "danger")
            return render_template('register.html')
        if not confirmation:
            flash("Password confirmation is required", "danger")
            return render_template('register.html')
        
        # Check username and password length
        if len(username) > 50:
            flash("Username must be 50 characters or less", "danger")
            return render_template('register.html')
        if len(username) < 3:
            flash("Username must be at least 3 characters long", "danger")
            return render_template('register.html')
        if len(password) < 8:
            flash("Password must be at least 8 characters long", "danger")
            return render_template('register.html')

        # Check password complexity
        if not any(char.isupper() for char in password):
            flash("Password must include at least one uppercase letter", "danger")
            return render_template('register.html')
        if not any(char in "!@#$%^&*()-_+=<>?/{}~" for char in password):
            flash("Password must include at least one special character", "danger")
            return render_template('register.html')

        # Check if passwords match
        if password != confirmation:
            flash("Passwords do not match", "danger")
            return render_template('register.html')

        # Connect to the database
        ## Not using - with sqlite3.connect(DATABASE_PATH) as conn:
        with get_connection() as conn:
            with conn.cursor() as cursor:

                # Check if username already exists
                cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
                existing_user = cursor.fetchone()

                if existing_user:
                    flash("Username already exists", "danger")
                    return render_template('register.html')

                # Hash the password and insert the new user
                hashed_password = generate_password_hash(password)
                cursor.execute("INSERT INTO users (username, hash, email) VALUES (%s, %s, %s)", (username, hashed_password, email))
                conn.commit()

        flash("Registration successful! Please log in.", "success")
        return redirect('/login')

    return render_template('register.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    """Log user in"""
    if 'user_id' in session:
        return redirect('/')

    if request.method == 'POST':
        # Clear the session when someone tries to log in
        session.clear()

        username = request.form.get('username')
        password = request.form.get('password')

        # Check if username and password were submitted
        if not username or not password:
            flash("Must provide username and password", "danger")
            return render_template('login.html')

        # Connect to the database
        ## Not using - with sqlite3.connect(DATABASE_PATH) as conn:
        with get_connection() as conn:
            with conn.cursor() as cursor:

                # Query for the user
                cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
                user = cursor.fetchone()

                # Validate the username and password
                if user is None or not check_password_hash(user[2], password):
                    flash("Invalid username and/or password", "danger")
                    return render_template('login.html')

                # Remember the user's session
                session['user_id'] = user[0]  # Store the user's ID in the session
                print(f"User {user[0]} logged in successfully")
        flash("Login successful!", "success")
        return redirect('/')

    return render_template('login.html')



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
    form_completed = False  # Default flag to determine what to show

    try:
        # Check if the form has already been completed
        ## Not using - with sqlite3.connect(DATABASE_PATH) as conn:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT form_completed, exercise_history, fitness_goals FROM users WHERE id = %s", (user_id,))
                result = cursor.fetchone()
                form_completed = bool(result[0])  # Retrieve form_completed status
                exercise_history = result[1]  # Fetch exercise history
                fitness_goals = result[2]  # Fetch fitness goals
    except Exception as e:
        flash(f"An error occurred: {e}", "danger")
        return render_template('training.html', form_completed=False)

    # If the user submits the form and it hasn't been completed yet
    if request.method == 'POST' and not form_completed:
        # Get form data
        name = request.form.get('name')
        last_name = request.form.get('last_name')
        age = request.form.get('age')
        weight = request.form.get('weight')
        height_feet = request.form.get('height_feet')
        height_inches = request.form.get('height_inches')
        gender = request.form.get('gender')
        exercise_history = request.form.get('exercise_history')
        fitness_goals = request.form.getlist('fitness_goals')  # List of selected goals
        injury = request.form.get('injury')
        injury_details = request.form.get('injury_details')
        commitment = request.form.get('commitment')
        additional_notes = request.form.get('additional_notes')

        # Combine fitness goals into a single string
        fitness_goals_str = ", ".join(fitness_goals)

        # Validate required fields
        if not all([name, last_name, age, weight, height_feet, height_inches, gender, exercise_history, commitment]):
            flash("Please fill out all required fields.", "danger")
            return render_template('training.html', form_completed=False)

        # Server-side validation for number of goals
        if len(fitness_goals) < 1:
            flash("Please select at least 1 fitness goal.", "danger")
            return render_template('training.html', form_completed=False)
        
        # Connect to the database and update user information
        try:
            ## Not using - with sqlite3.connect(DATABASE_PATH) as conn:
            with get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        UPDATE users
                        SET 
                            age = %s, weight = %s, height_feet = %s, height_inches = %s, 
                            gender = %s, exercise_history = %s, fitness_goals = %s, 
                            injury = %s, injury_details = %s, commitment = %s, additional_notes = %s, 
                            name = %s, last_name = %s, form_completed = TRUE
                        WHERE id = %s
                    """, (
                        age, weight, height_feet, height_inches, gender, 
                        exercise_history, fitness_goals_str, injury, injury_details, 
                        commitment, additional_notes, name, last_name, user_id
                    ))
                    conn.commit()

            form_completed = True  # Mark the form as completed
            flash("Your information has been successfully updated!", "success")
        except Exception as e:
            flash(f"An error occurred: {e}", "danger")
            return render_template('training.html', form_completed=False)
        
    # Fetch and organize workouts into groupings
    categories = {
        "Chest and Triceps": ["CHEST", "TRICEPS"],
        "Back and Biceps": ["BACK", "BICEPS"],
        "Shoulders and Abs": ["SHOULDERS", "ABS"],
        "Arms": ["BICEPS", "TRICEPS", "SHOULDERS"],
        "Legs": ["LEGS"],
        "Upper Body": ["BACK", "CHEST", "SHOULDERS", "BICEPS", "TRICEPS"],
        "Full Body": ["BACK", "CHEST", "SHOULDERS", "BICEPS", "TRICEPS", "LEGS", "ABS"],
        "Cardio": ["CARDIO"],
    }

    grouped_workouts = {}
    workouts = []
    target_heart_rate_zone = None
    guidelines = {}

    # Single connection block for fetching grouped workouts and user data
    ## Not using - with sqlite3.connect(DATABASE_PATH) as conn:
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
                    level_map = {
                        "No Exercise History": 1,
                        "Exercise less than 1 year": 1,
                        "Exercise 1-5 years": 2,
                        "Exercise 5+ years": 3
                    }
                    user_level = level_map.get(exercise_history, 1)  # Default to 1 if not found

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

    return render_template(
        'training.html', 
        form_completed=form_completed, 
        workouts=workouts, 
        target_heart_rate_zone=target_heart_rate_zone, 
        grouped_workouts=grouped_workouts, 
        guidelines=guidelines,
        fitness_goals=fitness_goals
    )



@app.route('/generate_workout')
@login_required
def generate_workout_route():
    selected_category = request.args.get('category')
    if not selected_category:
        return jsonify({'success': False, 'error': 'No category selected'})

    user_id = session['user_id']

    # Fetch the user's level
    ## Not using - with sqlite3.connect(DATABASE_PATH) as conn:
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT exercise_history FROM users WHERE id = %s", (user_id,))
            exercise_history = cursor.fetchone()[0]
            level_map = {"No Exercise History": 1, "Exercise less than 1 year": 1, "Exercise 1-5 years": 2, "Exercise 5+ years": 3}
            user_level = level_map.get(exercise_history, 1)

    # Generate the workout
    workout_plan = generate_workout(selected_category, user_level, user_id)

    # Save the exact workout and category to the session
    session['generated_workout'] = {
        'category': selected_category,
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
                    'video_demo': exercise[3],
                    'image_exercise_start': exercise[4],
                    'image_exercise_end': exercise[5],
                    'max_weight': exercise[6],
                    'max_reps': exercise[7]
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
            ## Not using - with sqlite3.connect(DATABASE_PATH) as conn:
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

    ## Not using - with sqlite3.connect(DATABASE_PATH) as conn:
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
        SELECT w.id, w.name, w.description, uep.max_weight, uep.max_reps
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
        username = request.form['username']

        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
                user = cursor.fetchone()

        if user:
            return redirect(url_for('reset_password', username=username))
        else:
            flash("No account found with that username.", "danger")
            return render_template("forgot_password.html")

    return render_template("forgot_password.html")


@app.route('/reset_password/<username>', methods=['GET', 'POST'])
def reset_password(username):
    # Confirm user exists before showing reset form
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()

    if not user:
        flash("No user found with that username.", "danger")
        return redirect('/forgot_password')
    
    if request.method == 'POST':
        password = request.form['password']
        confirmation = request.form['confirmation']

        if password != confirmation:
            flash("Passwords do not match", "danger")
            return render_template("reset_password.html", username=username)

        hashed = generate_password_hash(password)
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("UPDATE users SET hash = %s WHERE username = %s", (hashed, username))
                conn.commit()

        flash("Password successfully updated! Please log in.", "success")
        return redirect('/login')

    return render_template("reset_password.html", username=username)


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    user_id = session['user_id']

    # Fetch user info to pre-fill the form
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT username, name, last_name, email, age, weight, height_feet, height_inches,
                       gender, exercise_history, fitness_goals, injury, injury_details,
                       commitment, additional_notes
                FROM users
                WHERE id = %s
            """, (user_id,))
            user = cursor.fetchone()
    columns = ['username', 'name', 'last_name', 'email', 'age', 'weight', 'height_feet', 'height_inches',
                'gender', 'exercise_history', 'fitness_goals', 'injury', 'injury_details',
                'commitment', 'additional_notes']

    if user:
        user = dict(zip(columns, user))    

    if request.method == 'POST':
        # Collect updated form values
        username = request.form.get('username')
        name = request.form.get('name')
        last_name = request.form.get('last_name')
        email = request.form.get('email') or None
        age = request.form.get('age')
        weight = request.form.get('weight')
        height_feet = request.form.get('height_feet')
        height_inches = request.form.get('height_inches')
        gender = request.form.get('gender')
        exercise_history = request.form.get('exercise_history')
        fitness_goals = request.form.getlist('fitness_goals')
        fitness_goals_cleaned = ", ".join(goal.strip() for goal in fitness_goals if goal.strip())
        injury = request.form.get('injury')
        injury_details = request.form.get('injury_details')
        commitment = request.form.get('commitment')
        additional_notes = request.form.get('additional_notes')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Validate required fields (excluding optional email/password)
        if not all([username, name, last_name, age, weight, height_feet, height_inches, gender, exercise_history, commitment]):
            flash("Please fill out all required fields.", "danger")
            return render_template('settings.html', user=user)

        # Validate fitness goals (must select 1 or 2)
        if not (1 <= len(fitness_goals) <= 2):
            flash("Please select 1 or 2 fitness goals.", "danger")
            return render_template('settings.html', user=user)

        # Validate password if provided
        if password:
            if password != confirm_password:
                flash("Passwords do not match.", "danger")
                return render_template('settings.html', user=user)
            
            if len(password) < 8:
                flash("Password must be at least 8 characters long.", "danger")
                return render_template('settings.html', user=user)

            if not any(char.isupper() for char in password):
                flash("Password must include at least one uppercase letter.", "danger")
                return render_template('settings.html', user=user)

            if not any(char in "!@#$%^&*()-_+=<>?/{}~" for char in password):
                flash("Password must include at least one special character.", "danger")
                return render_template('settings.html', user=user)
    
            hashed_password = generate_password_hash(password)
        else:
            hashed_password = None

        # Check for duplicate username or email
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT id FROM users WHERE username = %s AND id != %s", (username, user_id))
                if cursor.fetchone():
                    flash("That username is already taken.", "danger")
                    return render_template('settings.html', user=user)

                if email:
                    cursor.execute("SELECT id FROM users WHERE email = %s AND id != %s", (email, user_id))
                    if cursor.fetchone():
                        flash("That email is already in use.", "danger")
                        return render_template('settings.html', user=user)

        # Update the user
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE users
                    SET username = %s, name = %s, last_name = %s, email = %s,
                        age = %s, weight = %s, height_feet = %s, height_inches = %s,
                        gender = %s, exercise_history = %s, fitness_goals = %s,
                        injury = %s, injury_details = %s, commitment = %s,
                        additional_notes = %s
                    WHERE id = %s
                """, (
                    username, name, last_name, email, age, weight, height_feet,
                    height_inches, gender, exercise_history, fitness_goals_cleaned,
                    injury, injury_details, commitment, additional_notes, user_id
                ))

                if hashed_password:
                    cursor.execute("UPDATE users SET hash = %s WHERE id = %s", (hashed_password, user_id))

                conn.commit()

        flash("Settings updated successfully!", "success")

        # Refetch updated data
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT username, name, last_name, email, age, weight, height_feet, height_inches,
                           gender, exercise_history, fitness_goals, injury, injury_details,
                           commitment, additional_notes
                    FROM users
                    WHERE id = %s
                """, (user_id,))
                user = cursor.fetchone()
        if user:
            user = dict(zip(columns, user))

    return render_template('settings.html', user=user)


if __name__ == '__main__':
    app.run(debug=True)
