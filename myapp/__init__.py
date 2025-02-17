import os

from dotenv import load_dotenv
from flask import Flask
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_mail import Mail
from flask_sqlalchemy import SQLAlchemy

from flask_wtf.csrf import CSRFProtect

load_dotenv(".env")
app = Flask(__name__)
app.app_context().push()
app.config["SECRET_KEY"] = "\xf8A\xa0\xc2\xd4\xd6V\x93\xb8\xc9\x01{"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///site.db"
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
mail = Mail(app)
csrf = CSRFProtect(app)


from myapp import routes
