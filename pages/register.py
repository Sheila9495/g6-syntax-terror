import streamlit as st
from authentication import register_user, is_pw_ok, is_email_valid

st.title("Register with Diggable") 

username = st.text_input("Username")
email = st.text_input("Email")
password = st.text_input("Password", type="password")
st.caption("Password must be at least 8 characters. Please use a strong password!")

# This handles the registration process when the user clicks the "Get To Digging!" button.
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
    if not has_err:
        try:
            register_user(username, email, password)
            st.success("Registration successful! Go to the Login page to sign in.")
        except Exception as e:
            st.error(str(e))    

st.info("Already have an account? Go to the Login page to sign in!")
