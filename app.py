import os
import certifi
from flask import Flask, flash, render_template, redirect, request, session, url_for
from flask_pymongo import PyMongo
from pymongo import MongoClient
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash

# Проверяем, существует ли файл env.py и импортируем его, если он есть
if os.path.exists("env.py"):
    import env

# Создаем экземпляр приложения Flask
app = Flask(__name__)

# Настройка параметров приложения
app.config["MONGO_DBNAME"] = os.environ.get("MONGO_DBNAME")
app.config["MONGO_URI"] = os.environ.get("MONGO_URI")
app.secret_key = os.environ.get("SECRET_KEY")

# Выводим отладочную информацию
print("MONGO_DBNAME:", app.config["MONGO_DBNAME"])
print("MONGO_URI:", app.config["MONGO_URI"])
print("SECRET_KEY:", app.secret_key)

# Инициализация PyMongo с использованием certifi для сертификатов
mongo = PyMongo(app, tlsCAFile=certifi.where())

# Проверка подключения к базе данных
@app.route("/check_db_connection")
def check_db_connection():
    try:
        # Проверка инициализации объекта mongo.cx
        if not mongo.cx:
            raise Exception("MongoClient is not initialized")
        # Проверяем подключение к базе данных
        mongo.cx.admin.command("ping")
        return "MongoDB connection successful!"
    except Exception as e:
        return str(e)
    
@app.route("/manual_check_db_connection")
def manual_check_db_connection():
    try:
        mongo_uri = os.environ.get("MONGO_URI")
        client = MongoClient(mongo_uri, tlsCAFile=certifi.where())
        db = client[os.environ.get("MONGO_DBNAME")]
        db.command("ping")
        return "Manual MongoDB connection successful!"
    except Exception as e:
        return str(e)

@app.route("/")
@app.route("/get_tasks")
def get_tasks():
    try:
        if mongo.db is None:
            raise Exception("mongo.db is None")
        print(f"Connected to database: {mongo.db.name}")
        tasks = mongo.db.tasks.find()
        return render_template("tasks.html", tasks=tasks)
    except Exception as e:
        return str(e)
    

@app.route("/register", methods=["GET", "POST"])
def register():
    return render_template("register.html")


if __name__ == "__main__":
    app.run(host=os.environ.get("IP"), port=int(os.environ.get("PORT")), debug=True)