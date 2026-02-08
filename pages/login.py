import streamlit as st
import bcrypt
from database import get_db_cursor


def get_user_by_username(username: str):
    sql = """
        SELECT id, username, email, password_hash, failed_attempts, is_locked
        FROM users
        WHERE username = %s
        LIMIT 1
    """
    with get_db_cursor() as cursor:
        cursor.execute(sql, (username.strip(),))
        return cursor.fetchone()


def reset_failed_attempts(user_id: int):
    with get_db_cursor() as cursor:
        cursor.execute("UPDATE users SET failed_attempts = 0 WHERE id = %s", (user_id,))


def record_successful_login(user_id: int):
    with get_db_cursor() as cursor:
        cursor.execute("UPDATE users SET last_login = NOW() WHERE id = %s", (user_id,))


def increment_failed_attempts(user_id: int, lock_after: int = 3):
    with get_db_cursor() as cursor:
        cursor.execute(
            "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = %s",
            (user_id,),
        )
        cursor.execute("SELECT failed_attempts FROM users WHERE id = %s", (user_id,))
        row = cursor.fetchone()
        attempts = int(row["failed_attempts"]) if row and row.get("failed_attempts") is not None else 0

        if attempts >= lock_after:
            cursor.execute("UPDATE users SET is_locked = 1 WHERE id = %s", (user_id,))
            return attempts, True

    return attempts, False


st.set_page_config(page_title="Log on")
st.title("Log on")

username = st.text_input("Username")
password = st.text_input("Password", type="password")

col1, col2 = st.columns([1, 1])

with col1:
    if st.button("Log on"):
        u = username.strip()

        if not u or not password:
            st.error("Please enter both username and password.")
            st.stop()

        user = get_user_by_username(u)

        if not user:
            st.error("Username or password does not exist.")
            st.stop()

        if user.get("is_locked") == 1:
            st.error("Your account is locked due to too many failed login attempts.")
            st.stop()

        stored_hash = user["password_hash"].encode("utf-8")
        if bcrypt.checkpw(password.encode("utf-8"), stored_hash):
            reset_failed_attempts(user["id"])
            record_successful_login(user["id"])

            st.session_state["session_id"] = f"user_{user['id']}"
            st.session_state["user_id"] = user["id"]
            st.session_state["username"] = user["username"]
            st.session_state["email"] = user["email"]

            st.switch_page("app.py")
        else:
            attempts, locked = increment_failed_attempts(user["id"], lock_after=3)
            if locked:
                st.error("Username or password does not exist. Account is locked after 3 attempts.")
            else:
                st.error("Username or password does not exist.")
                st.caption(f"Attempt {attempts}/3")

with col2:
    st.write("")
    st.write("")
    if st.button("New user? Register"):
        st.switch_page("pages/register.py")
