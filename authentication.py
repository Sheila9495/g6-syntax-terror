import bcrypt
from database import get_db_cursor
import re

# hashes the password using bcrypt
def hash_pw(raw_pw: str) -> str:
    hashed_pw = bcrypt.hashpw(raw_pw.encode('utf-8'), bcrypt.gensalt())
    return hashed_pw.decode('utf-8')

# checks if the password meets the minimum requirements (length) and is not empty
def is_pw_ok(password :str) -> tuple[bool, str]:
    if not password:
        return False, "Password Required. Please enter a password."
    if len(password) < 8:
        return False, "Your password is too short. Passwords must be at least 8 characters long."
    return True, ""

# checks if the password input matches the saved hash in the database
def is_pw_valid(pw_input: str, saved_hash : str) -> bool:
    return bcrypt.checkpw(pw_input.encode('utf-8'), saved_hash.encode('utf-8'))

# checks if the email is in a valid format using a regular expression
def is_email_valid (email: str) -> bool:
    email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return bool(re.match(email_regex, email or ""))

# registers a new user by validating the email, using password hashing, and inserting the user's data into the database
def register_user(username: str, email: str, password: str) -> bool:
    if not is_email_valid(email):
        raise ValueError("Invalid email format. Please enter a valid email address.")
    ok, message = is_pw_ok(password)
    if not ok:
        raise ValueError(message)
    
    hashed_password = hash_pw(password)
    
    try:
        with get_db_cursor() as cursor:
            cursor.execute("INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)", (username.strip(), email.strip().lower(), hashed_password),)
    except Exception as e:
        raise ValueError("Oh no! That username or email is taken. Try another one.") from e
    
    return True
    
# logs in a user by checking the provided email and password against the credentials stored in the database
def login_user (email: str, password: str):
    if not password or not email:
        raise ValueError("Email and Password Required. Please Try again.")
    
    with get_db_cursor() as cursor:
        cursor.execute("SELECT id, username,email, password_hash FROM users WHERE email = %s", (email.strip().lower(),))
        user_result = cursor.fetchone()
    if not user_result:
        raise ValueError("Invalid email or password.")
    if not is_pw_valid(password, user_result["password_hash"]):
        raise ValueError("Invalid email or password.")
    return {"id": user_result["id"], "username": user_result["username"] ,"email":user_result["email"],}


def get_user_by_name(username: str):
    with get_db_cursor() as cursor:
        cursor.execute("SELECT id, username, email FROM users WHERE username = %s", (username.strip(),),)
        return cursor.fetchone()
   