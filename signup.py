from tkinter import *
from tkinter import messagebox
import re
import hashlib
import subprocess

def clear_default_text(event):
    event.widget.delete(0, END)

def validate_email(email):
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'

    if re.match(email_regex, email):
        return True
    else:
        messagebox.showerror("Error", "Invalid Email Address.")
        return False

def validate_password():
    password = password_entry.get()
    confirm_password = confirmation_entry.get()

    if password != confirm_password:
        messagebox.showerror("Error", "Passwords do not match.")
        return False

    if not re.match(r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$", password):
        messagebox.showerror("Error",
                             "Password must be at least 8 characters long and contain both letters and numbers.")
        return False

    return True

def is_username_unique(username):
    try:
        with open("user_data.txt", "r") as file:
            for line in file:
                if f"Username: {username}" in line:
                    return False
    except FileNotFoundError:
        return True

    return True

def is_email_unique(email):
    try:
        with open("user_data.txt", "r") as file:
            for line in file:
                if f"Email: {email}" in line:
                    return False
    except FileNotFoundError:
        return True

    return True

def validate_unique_fields(username, email):
    if not is_username_unique(username):
        messagebox.showerror("Error", "Username already exists.")
        return False

    if not is_email_unique(email):
        messagebox.showerror("Error", "Email already exists.")
        return False

    return True

def save_user_data():
    first_name = first_name_label.get()
    last_name = last_name_label.get()
    email = email_label.get()
    username = username_entry.get()
    password = password_entry.get()

    if not validate_unique_fields(username, email):
        return

    hashed_password = hash_password(password)

    with open("user_data.txt", "a") as file:
        file.write(f"First Name: {first_name}, Last Name: {last_name}, Email: {email}, Username: {username}, Password: {hashed_password}\n")

    messagebox.showinfo("Success", "User data saved successfully!")

def hash_password(password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return hashed_password

def signup():
    email = email_label.get()

    if not validate_email(email):
        return

    if not validate_password():
        return

    save_user_data()

def open_login_page():
    subprocess.run(["python", "login.py"])

root = Tk()
root.title("Sign up")
root.geometry("925x500+300+200")
root.configure(bg="#fff")
root.resizable(False, False)

try:
    img = PhotoImage(file="signup.png")
    Label(root, image=img, bg='white').place(x=50, y=50)
except TclError:
    messagebox.showerror("Error", "Image file not found.")

frame = Frame(root, width=500, height=600, bg="#fff")
frame.place(x=480, y=70)

heading = Label(frame, text='Registration', fg='#57a1f8', bg='white', font=('Microsoft YaHei UI Light', 23, 'bold'))
heading.place(x=100, y=5)

first_name_label = Entry(frame, width=25, fg="black", border=0, bg="white", font=('Microsoft YaHei UI Light', 11))
first_name_label.place(x=30, y=80)
first_name_label.insert(0, 'First Name')
Frame(frame, width=295, height=2, bg='black').place(x=25, y=107)
first_name_label.bind("<FocusIn>", clear_default_text)

last_name_label = Entry(frame, width=25, fg="black", border=0, bg="white", font=('Microsoft YaHei UI Light', 11))
last_name_label.place(x=30, y=120)
last_name_label.insert(0, 'Last Name')
Frame(frame, width=295, height=2, bg='black').place(x=25, y=147)
last_name_label.bind("<FocusIn>", clear_default_text)

email_label = Entry(frame, width=25, fg="black", border=0, bg="white", font=('Microsoft YaHei UI Light', 11))
email_label.place(x=30, y=160)
email_label.insert(0, 'Email')
Frame(frame, width=295, height=2, bg='black').place(x=25, y=187)
email_label.bind("<FocusIn>", clear_default_text)

username_entry = Entry(frame, width=25, fg="black", border=0, bg="white", font=('Microsoft YaHei UI Light', 11))
username_entry.place(x=30, y=200)
username_entry.insert(0, 'Username')
Frame(frame, width=295, height=2, bg='black').place(x=25, y=227)
username_entry.bind("<FocusIn>", clear_default_text)

password_entry = Entry(frame, width=25, fg="black", border=0, bg="white", font=('Microsoft YaHei UI Light', 11),
                       show="*")
password_entry.place(x=30, y=240)
password_entry.insert(0, 'Password')
Frame(frame, width=295, height=2, bg='black').place(x=25, y=267)
password_entry.bind("<FocusIn>", clear_default_text)

confirmation_entry = Entry(frame, width=25, fg="black", border=0, bg="white", font=('Microsoft YaHei UI Light', 11),
                           show="*")
confirmation_entry.place(x=30, y=280)
confirmation_entry.insert(0, 'Confirm Password')
Frame(frame, width=295, height=2, bg='black').place(x=25, y=307)
confirmation_entry.bind("<FocusIn>", clear_default_text)

login_button = Button(frame, width=30, border=0, pady=7, text="Signup", bg="#57a1f8", fg="white", font=('Arial', 12),
                      relief=FLAT, command=signup)
login_button.place(x=30, y=320)

label = Label(frame, width='30', text="Already have an account?", foreground='black', font=('Arial', 9))
label.place(x=30, y=380)

signup_label = Button(frame, width=13, border=0, text="Sign In", fg="black", font=('Arial', 9), relief=FLAT)
signup_label.place(x=215, y=380)
signup_label.bind("<Button-1>", lambda e: open_login_page())
root.mainloop()
