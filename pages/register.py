import json
import streamlit as st
from authentication import register_user, is_pw_ok, is_email_valid
from quiz_options import GENRES, MIN_PREFERENCES

st.title("Register with Diggable")

username = st.text_input("Username")
email = st.text_input("Email")
password = st.text_input("Password", type="password")
st.caption("Password must be at least 8 characters. Please use a strong password!")

st.subheader("Music Preferences")
st.caption("Pick at least 3 genres to personalize your recommendations.")
selected_genres = st.multiselect(
    "Select your favorite genres",
    options=GENRES,
    default=st.session_state.get("quiz_selections", []),
)

if st.button("Get To Digging!"):
    has_err = False

    if not username.strip():
        st.error("A Username is required to register.")
        has_err = True

    if not email.strip():
        st.error("An Email is required to register.")
        has_err = True

    elif not is_email_valid(email):
        st.error("Uh oh! Please enter a valid email address and Try again.")
        has_err = True
    if not password:
        st.error("A Password is required to register.")
        has_err = True
    else:
        ok, msg = is_pw_ok(password)
        if not ok:
            st.error(msg)
            has_err = True

    if len(selected_genres) < MIN_PREFERENCES:
        st.error(f"Please select at least {MIN_PREFERENCES} music preferences to complete sign up.")
        has_err = True
    elif len(selected_genres) >= MIN_PREFERENCES:
        st.session_state["quiz_selections"] = selected_genres

    if not has_err:
        try:
            quiz_json = json.dumps({"genres": selected_genres})
            register_user(username, email, password, quiz_json)
            st.success("Registration successful! Go to the Login page to sign in.")
        except Exception as e:
            st.error(str(e))

st.info("Already have an account? Go to the Login page to sign in!")
