from functools import wraps
from flask import session, redirect, url_for, flash
import os, psycopg2
from psycopg2 import connect
from urllib.parse import urlparse
from dotenv import load_dotenv
from collections import OrderedDict
from decimal import Decimal

load_dotenv()
## Not using - DATABASE_PATH = os.getenv('DATABASE_URL', 'instance/health.db')

def get_connection():
    return psycopg2.connect(os.getenv("DATABASE_URL"))


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            print("User not logged in, redirecting to login")
            flash("You must log in to access this page.", "danger")
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


def generate_workout(selected_category, user_level, user_id):
    """
    Generate a workout based on the selected category and user level.
    :param selected_category: The category selected by the user (e.g., 'Chest and Triceps')
    :param user_level: The user's fitness level (1 = Beginner, 2 = Intermediate, 3 = Advanced)
    :return: A list of exercises grouped by subcategory.
    """
    # Define the workout structure
    workout_structure = {
        1: {  # Beginner
            "Chest and Triceps": {"CHEST": 3, "TRICEPS": 2},
            "Back and Biceps": {"BACK": 3, "BICEPS": 2},
            "Shoulders and Abs": {"SHOULDERS": 3, "ABS": 2},
            "Arms": {"BICEPS": 2, "TRICEPS": 2, "SHOULDERS": 2},
            "Legs": {"LEGS": 3},
            "Upper Body": {"BACK": 1, "CHEST": 1, "SHOULDERS": 1, "BICEPS": 1, "TRICEPS": 1},
            "Full Body": {"BACK": 1, "CHEST": 1, "SHOULDERS": 1, "BICEPS": 1, "TRICEPS": 1, "LEGS": 1, "ABS": 1},
            "Cardio": {"CARDIO": 1},
        },
        2: {  # Intermediate
            "Chest and Triceps": {"CHEST": 4, "TRICEPS": 3},
            "Back and Biceps": {"BACK": 4, "BICEPS": 3},
            "Shoulders and Abs": {"SHOULDERS": 4, "ABS": 3},
            "Arms": {"BICEPS": 3, "TRICEPS": 3, "SHOULDERS": 3},
            "Legs": {"LEGS": 4},
            "Upper Body": {"BACK": 1, "CHEST": 1, "SHOULDERS": 1, "BICEPS": 2, "TRICEPS": 2},
            "Full Body": {"BACK": 2, "CHEST": 2, "SHOULDERS": 1, "BICEPS": 1, "TRICEPS": 1, "LEGS": 1, "ABS": 1},
            "Cardio": {"CARDIO": 2},
        },
        3: {  # Advanced
            "Chest and Triceps": {"CHEST": 5, "TRICEPS": 4},
            "Back and Biceps": {"BACK": 5, "BICEPS": 4},
            "Shoulders and Abs": {"SHOULDERS": 5, "ABS": 4},
            "Arms": {"BICEPS": 4, "TRICEPS": 4, "SHOULDERS": 4},
            "Legs": {"LEGS": 6},
            "Upper Body": {"BACK": 2, "CHEST": 2, "SHOULDERS": 2, "BICEPS": 2, "TRICEPS": 2},
            "Full Body": {"BACK": 2, "CHEST": 2, "SHOULDERS": 2, "BICEPS": 2, "TRICEPS": 2, "LEGS": 2, "ABS": 2},
            "Cardio": {"CARDIO": 3},
        },
    }

    # Fetch the workout structure for the selected category and user level
    subcategories = workout_structure.get(user_level, {}).get(selected_category, {})
    workout_plan = OrderedDict()

    ## Not using - with sqlite3.connect(DATABASE_PATH) as conn:
    with get_connection() as conn:
        with conn.cursor() as cursor:
            for subcategory, num_exercises in subcategories.items():
                query = """
                    SELECT
                        w.id AS workout_id,
                        w.name,
                        w.description,
                        w.video_demo,
                        w.image_exercise_start,
                        w.image_exercise_end,
                        uep.max_weight,
                        uep.max_reps
                    FROM workouts w
                    LEFT JOIN user_exercise_progress uep
                        ON w.id = uep.workout_id AND uep.user_id = %s
                    WHERE w.category = %s AND w.level <= %s
                    ORDER BY RANDOM()
                    LIMIT %s
                """
                cursor.execute(query, (user_id, subcategory, user_level, num_exercises))
                exercises = cursor.fetchall()
                workout_plan[subcategory] = exercises

    return workout_plan


def get_guidelines(exercise_history, fitness_goals):
    # Define guidelines based on exercise history and fitness goals
    level_map = {
        "No Exercise History": 1,
        "Exercise less than 1 year": 1,
        "Exercise 1-5 years": 2,
        "Exercise 5+ years": 3
    }
    level = level_map.get(exercise_history, 1)  # Default to Beginner (Level 1)

    guidelines = {
        1: {  # Beginner
            "Lose Weight": {"Sets": "2-3", "Reps": "8-12", "Rest": "60-90 seconds"},
            "Gain Muscle": {"Sets": "3", "Reps": "8-12", "Rest": "30-90 seconds"},
            "Tone Muscle": {"Sets": "3", "Reps": "8-12", "Rest": "30-60 seconds"},
            "Abs": {"Sets": "3", "Reps": "10-15", "Rest": "30-60 seconds"},
            "Increase Strength": {"Sets": "3", "Reps": "4-8", "Rest": "2-3 minutes"},
            "Increase Endurance": {"Sets": "2-3", "Reps": "12-20", "Rest": "30-60 seconds"},
            "Feel Better": {"Sets": "3", "Reps": "10-15", "Rest": "30-60 seconds"}
        },
        2: {  # Intermediate
            "Lose Weight": {"Sets": "3-4", "Reps": "8-12", "Rest": "60 seconds"},
            "Gain Muscle": {"Sets": "4", "Reps": "8-12", "Rest": "60 seconds"},
            "Tone Muscle": {"Sets": "4", "Reps": "8-12", "Rest": "30-60 seconds"},
            "Abs": {"Sets": "4", "Reps": "10-15", "Rest": "60 seconds"},
            "Increase Strength": {"Sets": "4", "Reps": "4-8", "Rest": "2-3 minutes"},
            "Increase Endurance": {"Sets": "3-4", "Reps": "12-20", "Rest": "60 seconds"},
            "Feel Better": {"Sets": "3-4", "Reps": "10-15", "Rest": "60 seconds"}
        },
        3: {  # Advanced
            "Lose Weight": {"Sets": "4-5", "Reps": "8-12", "Rest": "30-60 seconds"},
            "Gain Muscle": {"Sets": "4-5", "Reps": "8-12", "Rest": "30-60 seconds"},
            "Tone Muscle": {"Sets": "4-5", "Reps": "8-12", "Rest": "30-60 seconds"},
            "Abs": {"Sets": "4-5", "Reps": "10-15", "Rest": "30-60 seconds"},
            "Increase Strength": {"Sets": "4-5", "Reps": "4-8", "Rest": "2-4 minutes"},
            "Increase Endurance": {"Sets": "4-5", "Reps": "12-20", "Rest": "30-60 seconds"},
            "Feel Better": {"Sets": "4-5", "Reps": "10-15", "Rest": "30-60 seconds"}
        }
    }

    return guidelines[level].get(fitness_goals, {})
