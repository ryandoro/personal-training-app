import os, sqlite3, logging, json
from flask import Flask, flash, redirect, render_template, request, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from helpers import login_required, calculate_target_heart_rate, generate_workout, get_guidelines

# Utilized ChatGPT to help complete this web application 
# Set up basic logging configuration
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
app.secret_key = os.urandom(24) # Required for flash messages


@app.route('/')
@login_required
def home():
    """Show user's stats and progress."""
    # Get the user ID from the session
    user_id = session['user_id']

    # Connect to the database to fetch the username
    with sqlite3.connect('instance/health.db') as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name, fitness_goals, workouts_completed, last_workout_completed FROM users WHERE id = ?", (user_id,))
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

    return render_template(
        'index.html', 
        name=name, 
        fitness_goals=fitness_goals, 
        workouts_completed=workouts_completed,
        last_workout_completed=last_workout_completed
    )



@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect('/')
    
    if request.method == 'POST':
        username = request.form.get('username')
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
        with sqlite3.connect('instance/health.db') as conn:
            cursor = conn.cursor()

            # Check if username already exists
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            existing_user = cursor.fetchone()

            if existing_user:
                flash("Username already exists", "danger")
                return render_template('register.html')

            # Hash the password and insert the new user
            hashed_password = generate_password_hash(password)
            cursor.execute("INSERT INTO users (username, hash) VALUES (?, ?)", (username, hashed_password))
            conn.commit()

        flash("Registration successful! Please log in.", "success")
        return redirect('/login')

    return render_template('register.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    """Log user in"""
    if 'user_id' in session:
        return redirect('/')

    # Forget any user_id
    session.clear()

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Check if username and password were submitted
        if not username or not password:
            flash("Must provide username and password", "danger")
            return render_template('login.html')

        # Connect to the database
        with sqlite3.connect('instance/health.db') as conn:
            cursor = conn.cursor()

            # Query for the user
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
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
        with sqlite3.connect('instance/health.db') as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT form_completed, exercise_history, fitness_goals FROM users WHERE id = ?", (user_id,))
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
        if not all([name, age, weight, height_feet, height_inches, gender, exercise_history, commitment]):
            flash("Please fill out all required fields.", "danger")
            return render_template('training.html', form_completed=False)

        # Connect to the database and update user information
        try:
            with sqlite3.connect('instance/health.db') as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE users
                    SET 
                        age = ?, weight = ?, height_feet = ?, height_inches = ?, 
                        gender = ?, exercise_history = ?, fitness_goals = ?, 
                        injury = ?, injury_details = ?, commitment = ?, additional_notes = ?, 
                        name = ?, form_completed = 1
                    WHERE id = ?
                """, (
                    age, weight, height_feet, height_inches, gender, 
                    exercise_history, fitness_goals_str, injury, injury_details, 
                    commitment, additional_notes, name, user_id
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
    with sqlite3.connect('instance/health.db') as conn:
        cursor = conn.cursor()
        try:
            # Fetch grouped workouts
            for category, group in categories.items():
                placeholders = ",".join("?" for _ in group)
                query = f"SELECT name, description FROM workouts WHERE category IN ({placeholders})"
                cursor.execute(query, group)
                grouped_workouts[category] = cursor.fetchall()

            # Fetch the user's exercise history and age
            cursor.execute("SELECT exercise_history, age, fitness_goals FROM users WHERE id = ?", (user_id,))
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
                cursor.execute("SELECT name, description FROM workouts WHERE level <= ?", (user_level,))
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
    with sqlite3.connect('instance/health.db') as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT exercise_history FROM users WHERE id = ?", (user_id,))
        exercise_history = cursor.fetchone()[0]
        level_map = {"No Exercise History": 1, "Exercise less than 1 year": 1, "Exercise 1-5 years": 2, "Exercise 5+ years": 3}
        user_level = level_map.get(exercise_history, 1)

    # Generate the workout
    workout_plan = generate_workout(selected_category, user_level)

    # Save the exact workout and category to the session
    session['generated_workout'] = {
        'category': selected_category,
        'workout': workout_plan  # Save the raw workout structure
    }

    # Format the workout for the response
    formatted_workout = [
        {
            'subcategory': subcategory,
            'exercises': [{'name': exercise[0], 'description': exercise[1]} for exercise in exercises]
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
    workout_details = generated_workout['workout']  # Raw workout details

    # Store the workout details and increment the workout counter
    with sqlite3.connect('instance/health.db') as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE users
            SET workouts_completed = COALESCE(workouts_completed, 0) + 1,
                last_workout_completed = ?,
                last_workout_details = ?
            WHERE id = ?
        """, (workout_category, json.dumps(workout_details), user_id))
        conn.commit()

    return jsonify({'success': True})



@app.route('/workout_details/<category>', methods=['GET'])
@login_required
def workout_details(category):
    user_id = session['user_id']

    with sqlite3.connect('instance/health.db') as conn:
        cursor = conn.cursor()

        # Fetch the last workout details for the given category
        cursor.execute("""
            SELECT last_workout_details
            FROM users
            WHERE id = ? AND last_workout_completed = ?
        """, (user_id, category))
        result = cursor.fetchone()

    if not result or not result[0]:
        return render_template('workout_details.html', category=category, workouts=None)

    # Parse the stored JSON workout details
    raw_workouts = json.loads(result[0])

    # Reformat the data for the template
    workouts = {
        subcategory: [{"name": exercise[0], "description": exercise[1]} for exercise in exercises]
        for subcategory, exercises in raw_workouts.items()
    }

    return render_template('workout_details.html', category=category, workouts=workouts)



if __name__ == '__main__':
    app.run(debug=True)