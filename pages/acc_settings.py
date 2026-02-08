import json
import streamlit as st
from database import get_db_cursor

st.title("Account Settings")

if not st.session_state.get("session_id"):
    st.warning("Please log in to view your account settings.")
    st.stop()

user_id = st.session_state.get("user_id")
st.subheader("Account Summary")
st.write("Your saved music preferences:")

try:
    with get_db_cursor() as cursor:
        cursor.execute(
            "SELECT latest_quiz FROM user_sessions WHERE user_id = %s",
            (user_id,),
        )
        row = cursor.fetchone()
    if row and row.get("latest_quiz"):
        try:
            prefs = json.loads(row["latest_quiz"])
        except (json.JSONDecodeError, TypeError):
            prefs = {}
        genres = prefs.get("genres", [])
        if genres:
            st.write(", ".join(genres))
        else:
            st.write("No preferences saved yet.")
    else:
        st.write("No preferences saved yet.")
except Exception:
    st.error("Could not load preferences.")
