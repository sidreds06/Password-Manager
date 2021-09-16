from tkinter import *
import tkinter.messagebox
import uuid
import hashlib
import mysql.connector
from tkinter import ttk


con = mysql.connector.connect(
  host="db4free.net",
  user="sidreds06",
  password="Password_Manager",
  database="password_manager"
)
print("Database Connected")
cr = con.cursor()

def hash_password(password):
    # uuid is used to generate a random number
    salt = uuid.uuid4().hex
    return hashlib.sha256(salt.encode() + password.encode()).hexdigest() + ':' + salt


def check_password(hashed_password, user_password):
    password, salt = hashed_password.split(':')
    return password == hashlib.sha256(salt.encode() + user_password.encode()).hexdigest()

def pwd(pas):
    from cryptography.fernet import Fernet
    key = b'pRmgMa8T0INjEAfksaq2aafzoZXEuwKI7wDe4c1F8AY='
    cipher_suite = Fernet(key)
    ciphered_text = cipher_suite.encrypt(pas.encode())   #required to be bytes
    return ciphered_text
def dpwd(ciphered_text):
    from cryptography.fernet import Fernet
    key = b'pRmgMa8T0INjEAfksaq2aafzoZXEuwKI7wDe4c1F8AY='
    cipher_suite = Fernet(key)
    uncipher_text = (cipher_suite.decrypt(ciphered_text))
    plain_text_encryptedpassword = bytes(uncipher_text).decode("utf-8") #convert to string
    return plain_text_encryptedpassword

def back():
    login_screen.deiconify()
    register_screen.destroy()


def show():
    login_screen.deiconify()
    login_success_screen.destroy()


def register():
    global register_screen
    global frame_2
    register_screen = Toplevel(login_screen)
    frame_2 = LabelFrame(register_screen, padx=200, pady=200)
    frame_2.place(x=583, y=200)
    register_screen.title("Register")
    register_screen.geometry("1920x1080")

    global username
    global password
    global repassword
    global username_entry
    global password_entry
    global repassword_entry
    username = StringVar()
    password = StringVar()
    repassword = StringVar()

    Label(frame_2, text="Password Manager", bg="#1D1033", fg="white",
          font=("Comic Sans MS", 22)).place(x=-120, y=-170)
    Label(frame_2, text="PW", font=("Cooper Black", 50), fg="white", bg="#1D1033").place(x=-50, y=-110)
    Label(frame_2, text=" ", fg="#1D1033", bg="#1D1033").pack()
    username_lable = Label(frame_2, text="Enter Username  :", fg="white", bg="#1D1033")
    username_lable.place(x=-125, y=10)
    username_entry = Entry(frame_2, textvariable=username, bg="#5E35A6", fg="white")
    username_entry.place(x=-10, y=10)
    password_lable = Label(frame_2, text="Enter Password  :", fg="white", bg="#1D1033")
    password_lable.place(x=-125, y=50)
    password_entry = Entry(frame_2, textvariable=password, show='*', bg="#5E35A6", fg="white")
    password_entry.place(x=-10, y=50)
    repassword_lable = Label(frame_2, text="Confirm Password  :", fg="white", bg="#1D1033")
    repassword_lable.place(x=-125, y=90)
    repassword_entry = Entry(frame_2, textvariable=repassword, show='*', bg="#5E35A6", fg="white")
    repassword_entry.place(x=-10, y=90)
    Button(frame_2, text="Register", width=10, height=1,
           command=register_user, bg="#5E35A6", fg="white").place(x=-90, y=140)
    Button(frame_2, text="Back", width=10, height=1,
           command=back, bg="#5E35A6", fg="white").place(x=30, y=140)
    frame_2.configure(bg="#1D1033")
    register_screen.configure(bg="#171717")
    login_screen.withdraw()


# Designing window for login


def register_user():
    username_info = username.get()
    password_info = password.get()
    repassword_info = repassword.get()
    if password_info != repassword_info:
        tkinter.messagebox.showerror("Failed", "Passwords do not match")
    else:
        new_pass = password_info
        hashed_password = hash_password(new_pass)


        cr.execute("CREATE TABLE IF NOT EXISTS users (username text,password text)")

        cr.execute("SELECT * FROM users where username = %s", (username_info,))
        data = cr.fetchall()
        if data:
            tkinter.messagebox.showerror("Error", "User already exists")
        else:
            cr.execute("INSERT INTO users VALUES(%s,%s)", (username_info, hashed_password))
            tkinter.messagebox.showinfo("Success", "Registered Successfully")
            back()
        con.commit()


# Implementing event on login button

def login_verify():
    username1 = username_verify.get()
    password1 = password_verify.get()
    username_login_entry.delete(0, END)
    password_login_entry.delete(0, END)

    cr = con.cursor()
    cr.execute("SELECT * FROM users where username = %s", (username1,))
    data = cr.fetchall()
    if data:
        cr.execute("SELECT password FROM users where username = %s", (username1,))
        pas = cr.fetchall()
        if check_password(pas[0][0],password1):
            login_success(username1)

        else:
            user_not_found()

    else:
        user_not_found()


# Designing popup for login success

def login_success(username1):
    global login_success_screen
    global url_name
    global url_new
    global username_url
    global username_new
    global password_name
    global password_new
    url_new = StringVar()
    username_new = StringVar()
    password_new = StringVar()
    login_success_screen = Toplevel(login_screen)
    frame_3 = LabelFrame(login_success_screen, padx=200, pady=200)
    frame_3.place(x=600, y=200)
    login_success_screen.title("Success")
    login_success_screen.geometry("1920x1080")
    Label(frame_3, text="Password Manager", fg="white", bg="#1D1033",
          font=("Comic Sans MS", 16)).place(x=-100, y=-170)
    Label(frame_3, text="", font=("Cooper Black", 33), fg="#1D1033", bg="#1D1033").pack()
    Label(frame_3, text="Account  :", fg="white", bg="#1D1033").place(x=-140, y=-100)
    url_name = Entry(frame_3, textvariable=url_new, bg="#5E35A6", fg="white").place(x=-50, y=-100)
    Label(frame_3, text="Username  :", fg="white", bg="#1D1033").place(x=-140, y=-60)
    username_url = Entry(frame_3, textvariable=username_new, bg="#5E35A6", fg="white").place(x=-50, y=-60)
    Label(frame_3, text="Password  :", fg="white", bg="#1D1033").place(x=-140, y=-20)
    password_name = Entry(frame_3, textvariable=password_new, bg="#5E35A6", show="*", fg="white").place(x=-50, y=-20)
    Button(frame_3, text="Add", fg="white",bg="#5E35A6",command=lambda :data_entry(username1,list1)).place(x=100, y=-100)
    Button(frame_3, text="Delete", fg="white",bg="#5E35A6",command=lambda :data_del(username1,list1)).place(x=100, y=-60)
    Button(frame_3, text="Update", fg="white",bg="#5E35A6",command=lambda :data_upd(username1,list1)).place(x=100, y=-20)
    Button(frame_3, text="Search", fg="white",bg="#5E35A6",command=lambda :data_view(username1,list1)).place(x=-50, y=20)
    Button(frame_3, text="View All", fg="white",bg="#5E35A6", command=lambda :view_all(username1)).place(x=20, y=20)
    list1 = Listbox(frame_3, height=7, width=57, bg="#000000", fg="white")
    list1.place(x=-167.8, y=63)
    # sb1 = Scrollbar(frame_3, bg="light blue")
    # sb1.place(x=180, y=80)
    #list1.configure(yscrollcommand=sb1.set)
    # sb1.configure(command=list1.yview)
    frame_3.configure(bg="#1D1033")
    Button(frame_3, text="Logout", bg="#5E35A6", fg="white", command=show).place(x=-20, y=200)
    login_success_screen.configure(bg="#171717")
    login_screen.withdraw()



def data_entry(username1,list1):
    ur=username1
    w=url_new.get()
    i=username_new.get()

    p=pwd(password_new.get())
    cr.execute("CREATE TABLE IF NOT EXISTS data (user text,site text, id text, pas varchar(300))")
    cr.execute("SELECT * FROM data where user= %s AND site = %s ", (ur,w))
    data = cr.fetchall()
    if data:
        tkinter.messagebox.showerror("Error", "Data for "+w+" already exists!")
    else:
        cr.execute("INSERT INTO data VALUES(%s,%s,%s,%s)", (ur,w,i,p))
        tkinter.messagebox.showinfo("Success", "Data Added Successfully!")
        con.commit()



def data_del(username1,list1):
    ur = username1
    w = url_new.get()
    cr.execute("SELECT * FROM data where user =%s AND site = %s", (ur,w))
    data = cr.fetchall()
    if data:
        cr.execute("DELETE FROM data where user =%s AND site = %s", (ur, w))
        tkinter.messagebox.showinfo("Success", "Data Deleted Successfully!")
        con.commit()

    else:
        tkinter.messagebox.showerror("Error", "Data for "+w+" doesn't exist!")

def data_upd(username1,list1):
    ur = username1
    w = url_new.get()
    i = username_new.get()
    p = pwd(password_new.get())
    cr.execute("SELECT * FROM data where user= %s AND site = %s ", (ur, w))
    data = cr.fetchall()
    if data:
        cr.execute("UPDATE data SET id=%s, pas=%s WHERE user= %s AND site = %s ",(i,p,ur,w))
        tkinter.messagebox.showinfo("Success", "Data Updated Successfully!")
        con.commit()

    else:
        tkinter.messagebox.showerror("Error", "Data for "+w+" doesn't exist!")


def data_view(username1,list1):
    list1.delete(0,END)
    ur=username1
    w = url_new.get()
    # cr.execute("SELECT site,id,pas FROM data where user= %s", (ur,))
    # data = cr.fetchall()
    cr.execute("SELECT id FROM data where user= %s AND site=%s", (ur, w))
    d2 = cr.fetchall()
    cr.execute("SELECT pas FROM data where user= %s AND site=%s", (ur, w))
    d3 = cr.fetchall()
    j = 0
    if d2:
        for k,l in zip(d2,d3):
            st=dpwd(l[0].encode())
            c = str(st)
            x="Username= "+k[0]+", Password= "+c
            list1.insert(j,x)
            j+=1
    else:
        tkinter.messagebox.showerror("Error", "Data for " + w + " doesn't exist!")


def view_all(username1):
    global viewall
    viewall = Toplevel(login_success_screen)
    tv = ttk.Treeview(viewall, columns=(1, 2, 3), height="20", show="headings")
    tv.tag_configure("Treeview", background="#000000", foreground="white")
    tv.place(x=480, y=190)
    tv.heading(1, text="Account")
    tv.heading(2, text="Username")
    tv.heading(3, text="Password")
    ur=username1
    cr.execute("SELECT site FROM data where user= %s", (ur,))
    d1 = cr.fetchall()
    cr.execute("SELECT id FROM data where user= %s", (ur,))
    d2 = cr.fetchall()
    cr.execute("SELECT pas FROM data where user= %s", (ur,))
    d3 = cr.fetchall()
    j = 0
    for i, k, l in zip(d1, d2, d3):
        st = dpwd(l[0].encode())
        c = str(st)
        x = i[0] + " " + k[0] + " " + c
        tv.insert('','end',values=(i[0],k[0],st))
    viewall.geometry("1920x1080")
    viewall.configure(bg="#171717")
    viewall.mainloop()


def user_not_found():
    global user_not_found_screen
    tkinter.messagebox.showerror("Failed", "Invalid Username or Password")


# Deleting popups

def delete_login_success():
    login_success_screen.destroy()


def delete_user_not_found_screen():
    user_not_found_screen.destroy()


# Designing Main(first) window


def main_account_screen():
    global login_screen
    login_screen = Tk()
    frame = LabelFrame(login_screen, padx=200, pady=175)
    frame.place(x=583, y=200)
    login_screen.geometry("1920x1080")
    login_screen.title("Account Login")
    Label(frame, text="Password Manager", bg="#1D1033", fg="white",
          font=("Comic Sans MS", 22)).place(x=-120, y=-150)
    Label(frame, text="PW", font=("Cooper Black", 50), fg="white", bg="#1D1033").place(x=-50, y=-100)
    Label(frame, text="", fg="#1D1033", bg="#1D1033").pack()

    global username_verify
    global password_verify

    username_verify = StringVar()
    password_verify = StringVar()

    global username_login_entry
    global password_login_entry

    Label(frame, text="Username", fg="white", bg="#1D1033").place(x=-100, y=10)
    username_login_entry = Entry(frame, textvariable=username_verify, bg="#5E35A6", fg="white")
    username_login_entry.place(x=-15, y=10)
    Label(frame, text="Password", fg="white", bg="#1D1033").place(x=-100, y=70)
    password_login_entry = Entry(frame, textvariable=password_verify, show='*', bg="#5E35A6", fg="white")
    password_login_entry.place(x=-15, y=70)
    Button(frame, text="Login", width=10, height=1, command=login_verify, bg="#5E35A6", fg="white").place(x=-80, y=135)
    Button(frame, text="Register", width=10, height=1, command=register, bg="#5E35A6", fg="white").place(x=40, y=135)
    login_screen.configure(bg="#171717")
    frame.configure(bg="#1D1033")
    login_screen.mainloop()


main_account_screen()
