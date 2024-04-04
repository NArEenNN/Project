import streamlit as st
from streamlit import session_state
from pymongo import MongoClient
import streamlit as st
import base64
import hashlib
import qrcode
import os
import pyaes
import numpy as np
import dotenv
import random
import string
from zipfile import ZipFile
import io

dotenv.load_dotenv()


@st.cache_resource
def init_connection():
    MONGO_URI = os.getenv("MONGO_URI")
    return MongoClient(MONGO_URI)

client = init_connection()
db = client["encrypted_data"]
users_collection = db["user_data"]

session_state = st.session_state
if "user_index" not in st.session_state:
    st.session_state["user_index"] = 0
    

def image_to_string(image_path):
    with open("QR_Images//"+image_path, "rb") as image_file:
        encoded_string = base64.b64encode(image_file.read()).decode("utf-8")
    return encoded_string


def string_to_image(encoded_string, new_name):
    decoded_bytes = base64.b64decode(encoded_string)
    if not os.path.exists("QR_Images"):
        os.makedirs("QR_Images")
    with open("QR_Images//"+new_name, "wb") as image_file:
        image_file.write(decoded_bytes)
        
def generate_qr_code(data, name):
    qr = qrcode.QRCode(version=1, box_size=12)
    qr.add_data(data)
    qr.make(fit=True)
    qr_image = qr.make_image(fill_color="black", back_color="white")
    name = "QR_Images//" + name
    if not os.path.exists("QR_Images"):
        os.makedirs("QR_Images")
    qr_image.save(name)
    
def generateKey(user_key, admin_auth, token_auth):
    key = hashlib.sha256(
        user_key.encode("utf-8")
        + admin_auth.encode("utf-8")
        + token_auth.encode("utf-8")
    ).digest()[:16]
    return key    

def signup():
    st.title("Signup Page")
    with st.form("signup_form"):
        st.write("Fill in the details below to create an account:")
        name = st.text_input("Name:")
        email = st.text_input("Email:")
        age = st.number_input("Age:", min_value=0, max_value=120)
        sex = st.radio("Sex:", ("Male", "Female", "Other"))
        password = st.text_input("Password:", type="password")
        confirm_password = st.text_input("Confirm Password:", type="password")

        if st.form_submit_button("Signup"):
            if password == confirm_password:
                user = create_account(name, email, age, sex, password)
                session_state["logged_in"] = True
                session_state["user_info"] = user
            else:
                st.error("Passwords do not match. Please try again.")


def check_login(username, password):
    user = users_collection.find_one({"email": username, "password": password})
    if user:
        session_state["logged_in"] = True
        session_state["user_info"] = user
        st.success("Login successful!")
        return user
    else:
        st.error("Invalid credentials. Please try again.")
        return None


def initialize_database():
    try:
        if "users" not in db.list_collection_names():
            db.create_collection("users")
    except Exception as e:
        print(f"Error initializing database: {e}")


def create_account(name, email, age, sex, password):
    try:
        user_info = {
            "name": name,
            "email": email,
            "age": age,
            "sex": sex,
            "password": password,
            "files": None,
        }
        result = users_collection.insert_one(user_info)
        user_info["_id"] = result.inserted_id
        st.success("Account created successfully! You can now login.")
        return user_info
    except Exception as e:
        st.error(f"Error creating account: {e}")
        return None

def login():
    st.title("Login Page")
    username = st.text_input("Username:")
    password = st.text_input("Password:", type="password")

    login_button = st.button("Login")

    if login_button:
        user = check_login(username, password)
        if user is not None:
            session_state["logged_in"] = True
            session_state["user_info"] = user
        else:
            st.error("Invalid credentials. Please try again.")


def render_dashboard(user_info):
    try:
        st.title(f"Welcome to the Dashboard, {user_info['name']}!")
        st.subheader("User Information:")
        st.write(f"Name: {user_info['name']}")
        st.write(f"Sex: {user_info['sex']}")
        st.write(f"Age: {user_info['age']}")
        st.image("image.jpg", use_column_width=True)

    except Exception as e:
        st.error(f"Error rendering dashboard: {e}")

        

def main():
    st.title("Secure Multi-Party File Storage System")
    page = st.sidebar.radio(
        "Go to",
        ("Signup/Login", "Dashboard", "File Upload", "File Download"),
        key="Pages",
    )

    if page == "Signup/Login":
        st.title("Signup/Login Page")
        login_or_signup = st.radio(
            "Select an option", ("Login", "Signup"), key="login_signup"
        )
        if login_or_signup == "Login":
            login()
        else:
            signup()

    elif page == "Dashboard":
        if session_state.get("logged_in"):
            render_dashboard(session_state["user_info"])
        else:
            st.warning("Please login/signup to view the dashboard.")

    

    elif page == "File Upload":
        if session_state.get("logged_in"):
            st.title("Image Upload")
            uploaded_file = st.file_uploader(
                "Upload a File", type=["png", "jpg", "jpeg", "pdf", "docx", "txt"]
            )
            if uploaded_file is not None:
                st.write("Name: %s" % uploaded_file.name)
                st.write("Type: %s" % uploaded_file.type)
                st.write("Size: %s" % uploaded_file.size)
                user_auth =''.join(random.choices(string.ascii_letters + string.digits, k=16))
                admin_auth = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
                token_auth = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
                
                if st.button("Encrypt and Save"):
                    user_auth = hashlib.sha256(user_auth.encode("utf-8")).hexdigest()[:16]
                    admin_auth = hashlib.sha256(admin_auth.encode("utf-8")).hexdigest()[:16]
                    token_auth = hashlib.sha256(token_auth.encode("utf-8")).hexdigest()[:16]
                    dummy_text1 = "This is user's QR code"
                    dummy_text2 = "This is admin's QR code"
                    dummy_text3 = "This is token's QR code"
                    generate_qr_code(dummy_text1, "UserQR.png")
                    generate_qr_code(dummy_text2, "AdminQR.png")
                    generate_qr_code(dummy_text3, "TokenQR.png")
                    user_string = image_to_string("UserQR.png")
                    admin_string = image_to_string("AdminQR.png")
                    token_string = image_to_string("TokenQR.png")
                    if os.path.exists("QR_Images//UserQR.png"):
                        os.remove("QR_Images//UserQR.png")
                    if os.path.exists("QR_Images//AdminQR.png"):
                        os.remove("QR_Images//AdminQR.png")
                    if os.path.exists("QR_Images//TokenQR.png"):
                        os.remove("QR_Images//TokenQR.png")
                    
                    user_string = user_string[:-32] + user_auth + user_string[-32:]
                    admin_string = admin_string[:-32] + admin_auth + admin_string[-32:]
                    token_string = token_string[:-32] + token_auth + token_string[-32:]
                    
                    string_to_image(user_string, "UserQR.png")
                    string_to_image(admin_string, "AdminQR.png")
                    string_to_image(token_string, "TokenQR.png")
                    key = generateKey(user_auth, admin_auth, token_auth)
                    aes = pyaes.AESModeOfOperationCTR(key)
                    cipher_text = aes.encrypt(base64.b64encode(uploaded_file.read()).decode(
                            "utf-8"
                        ))
                    cipher_text = base64.b64encode(cipher_text).decode("utf-8")
                    file_data = cipher_text
                    user_info = session_state["user_info"]
                    current_time = str(np.datetime64("now"))
                    if user_info["files"] is None:
                        user_info["files"] = []
                    user_info["files"].append(
                        {
                            "file": uploaded_file.name,
                            "data": cipher_text,
                            "time": current_time,
                        }
                    )
                    # update user info
                    session_state["user_info"] = user_info
                    # update database
                    users_collection.update_one(
                        {"email": user_info["email"]},
                        {"$set": {"files": user_info["files"]}},
                    )   
                    st.success("Image uploaded successfully!")
                
                    buf = io.BytesIO()

                    with ZipFile(buf, "x") as zip:
                        zip.writestr("UserQR.png", base64.b64decode(user_string))
                        zip.writestr("AdminQR.png", base64.b64decode(admin_string))
                        zip.writestr("TokenQR.png", base64.b64decode(token_string))
                    if st.download_button(
                        label="Download QR codes",
                        data=buf.getvalue(),
                        file_name="QR_Codes.zip",
                        mime="application/zip",
                    ):
                        st.success("QR codes downloaded successfully!")

        else:
            st.warning("Please login/signup to access this page.")

    elif page == "File Download":
        if session_state.get("logged_in"):
            st.title("File Download")
            i = 1
            user_info = session_state["user_info"]
            if len(session_state["user_info"]["files"]) == 0:
                st.warning("No files uploaded yet.")
                return
            
            # for Image in session_state["user_info"]["files"]:
            for i, file in enumerate(reversed(user_info["files"])):
                files = []
                files_data = {}
                files_data["S.No"] = i+1
                files_data["File Name"] = file["file"]
                files_data["Upload Time"] = file["time"]
                files.append(files_data)
                i += 1
                st.table(files)
                file_data = None
                
                try:
                    with st.form("credentials" + str(i)):
                        st.write("Enter the credentials to decrypt the File:")
                        user_qr = st.file_uploader("Upload User QR code", type=["png"])
                        admin_qr = st.file_uploader("Upload Admin QR code", type=["png"])
                        token_qr = st.file_uploader("Upload Token QR code", type=["png"])
                        if st.form_submit_button("Decrypt and Download Image " + str(i)):
                            user_auth = image_to_string(user_qr.name)[-48:-32]
                            admin_auth = image_to_string(admin_qr.name)[-48:-32]
                            token_auth = image_to_string(token_qr.name)[-48:-32]
                            key = generateKey(user_auth, admin_auth, token_auth)
                            aes = pyaes.AESModeOfOperationCTR(key)
                            data = base64.b64decode(file["data"])
                            decrypted_text = aes.decrypt(data).decode("utf-8")
                            data = base64.b64decode(decrypted_text)
                            file_data = data
                            with open(file["file"], "wb") as f:
                                f.write(data)
                            st.success("file decrypted successfully!")
                    if file_data is not None:
                        if st.download_button(
                                label="Download decrypted file",
                                data=data,
                                file_name=file["file"],
                                mime="text/plain",
                            ):
                                st.success("File downloaded successfully!")
                                
                except Exception as e:
                    st.error(f"Wrong credentials entered")
        else:
            st.warning("Please login/signup to access this page.")

if __name__ == "__main__":
    initialize_database()
    main()
