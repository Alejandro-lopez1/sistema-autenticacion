import tkinter as tk 
from tkinter import ttk 
import bcrypt 
import sqlite3

class SistemaAutenticacionApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Sistema de Autenticación")

        #conexión con la base de datos SQLite
        self.conn = sqlite3.connect('ususarios.db')
        self.c = self.conn.cursor()

        #creando la tabla de usuarios 
        self.c.execute('''CREATE TABLE IF NOT EXISTS usuarios (
                       id INTEGER PRIMARY KEY,
                       username TEXT NOT NULL UNIQUE, 
                       password_hash TEXT NOT NULL
                    )''')
        self.conn.commit()

        #interfaz gráfica
        self.label_username = ttk.Label(self.master, text="Nombre de usuario:")
        self.label_username.grid(row=0, column=0, padx=5, pady=5)

        self.username_entry = ttk.Entry(self.master, width=30)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)

        self.label_password = ttk.Label(self.master, text="Contraseña:")
        self.label_password.grid(row=1, column=0, padx=5, pady=5)

        self.password_entry = ttk.Entry(self.master, width=30, show="*")
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)

        self.login_button = ttk.Button(self.master, text="Iniciar Sesión", command=self.iniciar_sesion)
        self.login_button.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

        self.register_button = ttk.Button(self.master, text="Registrarse", command=self.registrarse)
        self.register_button.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

    def iniciar_sesion(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        #consulta a la base de datos para el usuario ingresado
        self.c.execute("SELECT password_hash FROM usuarios WHERE username=?", (username,))
        result = self.c.fetchone()

        if result:
            #verificando la contraseña ingresada con el hash almacenado en la base de datos
            if bcrypt.checkpw(password.encode('utf-8'), result[0].encode('utf-8')):
                print("Inicio de Sesión Exitoso")
            else:
                print("Contraseña Incorrecta")
        else:
            print("Usuario no Encontrado")

    def registrarse(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        #generando un hash de la contraseña
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        #insertando el nuevo usuario en la base de datos
        self.c.execute("INSERT INTO usuarios (username, password_hash) VALUES (?, ?)", (username, hashed_password))
        self.conn.commit()
        print("Usuario Registrado Exitosamente")

if __name__ == "__main__":
    root = tk.Tk()
    app = SistemaAutenticacionApp(root)
    root.mainloop()