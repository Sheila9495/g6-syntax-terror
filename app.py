import streamlit as st

# Show logout only if logged in
if st.session_state.get("session_id"):

    if st.button("Log Off"):

        # Clear all login session data
        for key in ["session_id", "user_id", "username", "email"]:
            st.session_state.pop(key, None)

        st.switch_page("pages/login.py")
