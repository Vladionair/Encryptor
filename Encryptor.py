import base64
from tkinter import *
from tkinter import filedialog
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class Encryptor:

    def __init__(self, master):

        master.title('Encryptor')
        master.geometry('500x500+50+50')
        master['bg'] = 'grey'

        frame_1 = Frame()
        frame_1.place(relx=0.01, rely=0.07, relwidth=0.98, relheight=0.42)

        frame_2 = Frame()
        frame_2.place(relx=0.01, rely=0.56, relwidth=0.98, relheight=0.43)

        scroll_text_1_y = Scrollbar(frame_1)
        scroll_text_1_y.pack(side=RIGHT, fill=Y)

        scroll_text_2_y = Scrollbar(frame_2)
        scroll_text_2_y.pack(side=RIGHT, fill=Y)

        self.text_1 = Text(frame_1, wrap=None, yscrollcommand=scroll_text_1_y.set)
        self.text_1.pack(fill=BOTH)

        self.text_2 = Text(frame_2, wrap=None, yscrollcommand=scroll_text_2_y.set)
        self.text_2.pack(fill=BOTH)

        scroll_text_1_y.config(command=self.text_1.yview)
        scroll_text_2_y.config(command=self.text_2.yview)

        open_file_button = Button(text='Open file', command=self.open_file)
        open_file_button.place(relx=0.01, rely=0.01, relwidth=0.24, relheight=0.05)

        encrypt_button = Button(text='Encrypt', command=self.encrypting)
        encrypt_button.place(relx=0.26, rely=0.01, relwidth=0.24, relheight=0.05)

        decrypt_button = Button(text='Decrypt', command=self.decrypting)
        decrypt_button.place(relx=0.51, rely=0.01, relwidth=0.24, relheight=0.05)

        delete_button = Button(text='Delete', command=self.deleting)
        delete_button.place(relx=0.76, rely=0.01, relwidth=0.23, relheight=0.05)

        save_pass_button = Button(text='Save pass', command=self.pass_saving)
        save_pass_button.place(relx=0.01, rely=0.50, relwidth=0.15, relheight=0.05)

        save_text_button = Button(text='Save file', command=self.text_saving)
        save_text_button.place(relx=0.84, rely=0.50, relwidth=0.15, relheight=0.05)

        self.pass_window = Entry()
        self.pass_window.place(relx=0.17, rely=0.50, relwidth=0.66, relheight=0.05)

        self.menu = Menu(tearoff=0)

        self.menu.add_command(label='Cut', command=lambda: self.menu.focus_get().event_generate('<<Cut>>'))
        self.menu.add_command(label='Copy', command=lambda: self.menu.focus_get().event_generate('<<Copy>>'))
        self.menu.add_command(label='Paste', command=lambda: self.menu.focus_get().event_generate('<<Paste>>'))

        self.text_1.bind('<Button-3>', self.text_selection)
        self.text_2.bind('<Button-3>', self.text_selection)
        self.pass_window.bind('<Button-3>', self.text_selection)

    def open_file(self):

        self.deleting()
        try:
            path = filedialog.askopenfilename()
            with open(path, 'r') as file:
                data = file.read().encode()
                self.text_1.insert(1.0, data)
        except Exception:
            pass

    def encrypting(self):

        if len(self.text_1.get(1.0, END)) > 1:
            self.text_2.delete(1.0, END)
            password = self.pass_window.get().encode()
            salt = password
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
            key = base64.urlsafe_b64encode(kdf.derive(password))
            frn = Fernet(key)
            data = self.text_1.get(1.0, END).encode()
            file = frn.encrypt(data)
            self.text_2.insert(1.0, file)

    def decrypting(self):

        try:
            if len(self.text_1.get(1.0, END)) > 1 and len(self.pass_window.get()) > 1:
                self.text_2.delete(1.0, END)
                password = self.pass_window.get().encode()
                salt = password
                kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
                key = base64.urlsafe_b64encode(kdf.derive(password))
                frn = Fernet(key)
                file = self.text_1.get(1.0, END).encode()
                data = frn.decrypt(file)
                data = data.decode()
                self.text_2.insert(1.0, data)
        except Exception:
            self.deleting()
            self.pass_window.insert(0, 'Data is wrong!')

    def deleting(self):

        self.text_1.delete(1.0, END)
        self.text_2.delete(1.0, END)
        self.pass_window.delete(0, END)

    def pass_saving(self):

        try:
            file = filedialog.asksaveasfile(mode='a')
            file.writelines('\n' + '\n' + self.pass_window.get())
        except Exception:
            pass

    def text_saving(self):

        try:
            file = filedialog.asksaveasfile(mode='a')
            file.write('\n' + '\n' + self.text_2.get(1.0, END))
        except Exception:
            pass

    def text_selection(self, e):

        self.menu.post(e.x_root, e.y_root)

if __name__ == '__main__':

    root = Tk()
    run = Encryptor(root)
    root.mainloop()