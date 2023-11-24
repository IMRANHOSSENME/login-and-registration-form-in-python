from tkinter import *
from tkinter import messagebox
import hashlib
import subprocess

def hash_password(password):
    # Use a secure hashing algorithm like SHA-256
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return hashed_password

def login():
    username = entry_user.get()
    password = entry_password.get()

    # Hash the entered password for comparison
    hashed_password = hash_password(password)

    if not username or not password:
        messagebox.showerror("Error", "Username and password are required.")
        return

    try:
        with open("user_data.txt", "r") as file:
            for line in file:
                if f"Username: {username}" in line and f"Password: {hashed_password}" in line:
                    messagebox.showinfo("Success", "Login successful!")
                    return

    except FileNotFoundError:
        messagebox.showerror("Error", "User data file not found.")

    messagebox.showerror("Error", "Invalid username or password.")

def open_signup_page():
    subprocess.run(["python", "signup.py"])  # Replace "python" with your Python interpreter if needed

root = Tk()
root.title("Login")
root.geometry("925x500+300+200")
root.configure(bg="#fff")
root.resizable(False, False)

img = PhotoImage(file="login.png")
Label(root, image=img, bg='white').place(x=50, y=50)

frame = Frame(root, width=350, height=350, bg="#fff")
frame.place(x=480, y=70)

heading = Label(frame, text='Sign In', fg='#57a1f8', bg='white', font=('Microsoft YaHei UI Light', 23, 'bold'))
heading.place(x=100, y=5)

entry_user = Entry(frame, width=25, fg="black", border=0, bg="white", font=('Microsoft YaHei UI Light', 11))
entry_user.place(x=30, y=80)
entry_user.insert(0, 'Username')
Frame(frame, width=295, height=2, bg='black').place(x=25, y=107)

entry_password = Entry(frame, width=25, fg="black", border=0, bg="white", font=('Microsoft YaHei UI Light', 11), show='*')
entry_password.place(x=30, y=140)
entry_password.insert(0, 'Password')
Frame(frame, width=295, height=2, bg='black').place(x=25, y=177)

login_button = Button(frame, width=30, border=0, pady=7, text="Login", bg="#57a1f8", fg="white", font=('Arial', 12), relief=FLAT, command=login)
login_button.place(x=30, y=205)

label = Label(frame, width='30', text="Don't have an account?", foreground='black', font=('Arial', 9))
label.place(x=30, y=270)

signup_label = Button(frame, width=13, border=0, text="Sign Up", fg="black", font=('Arial', 9), relief=FLAT)
signup_label.place(x=215, y=270)
signup_label.bind("<Button-1>", lambda e: open_signup_page())  # Use <Button-1> event to trigger the function

root.mainloop()
