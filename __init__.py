from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_session import Session
from datetime import timedelta
import os
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv

# تحميل متغيرات البيئة من .env
load_dotenv()

db = SQLAlchemy()
bcrypt = Bcrypt()
jwt = JWTManager()
oauth = OAuth()

def create_app():
    app = Flask(__name__)

    # إعدادات أساسية
    app.config.from_object("config.Config")

    # تحميل المتغيرات من .env إلى config
    app.config['GITHUB_CLIENT_ID'] = os.getenv('GITHUB_CLIENT_ID')
    app.config['GITHUB_CLIENT_SECRET'] = os.getenv('GITHUB_CLIENT_SECRET')
    app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID')
    app.config['GOOGLE_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET')
    app.config['OKTA_CLIENT_ID'] = os.getenv('OKTA_CLIENT_ID')
    app.config['OKTA_CLIENT_SECRET'] = os.getenv('OKTA_CLIENT_SECRET')
    app.config['OKTA_DOMAIN'] = os.getenv('OKTA_DOMAIN')

    # تهيئة الإضافات
    db.init_app(app)
    bcrypt.init_app(app)
    jwt.init_app(app)
    Session(app)
    oauth.init_app(app)

    # OAuth GitHub
    oauth.register(
        name='github',
        client_id=app.config['GITHUB_CLIENT_ID'],
        client_secret=app.config['GITHUB_CLIENT_SECRET'],
        authorize_url='https://github.com/login/oauth/authorize',
        access_token_url='https://github.com/login/oauth/access_token',
        client_kwargs={'scope': 'user:email'},
        api_base_url='https://api.github.com/',
        userinfo_endpoint='https://api.github.com/user',

    )

    # OAuth Google
    oauth.register(
        name='google',
        client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET'],
        access_token_url='https://oauth2.googleapis.com/token',
        authorize_url='https://accounts.google.com/o/oauth2/auth',
        client_kwargs={'scope': 'openid email profile'},
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    )

    # OAuth Okta
    oauth.register(
        name='okta',
        client_id=app.config['OKTA_CLIENT_ID'],
        client_secret=app.config['OKTA_CLIENT_SECRET'],
        server_metadata_url=f"{app.config['OKTA_DOMAIN']}/.well-known/openid-configuration",
        client_kwargs={'scope': 'openid profile email'}
    )

    # إعداد مجلدات الملفات
    UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploaded_files')
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

    ENCRYPTED_FOLDER = os.path.join(os.getcwd(), 'uploaded_files_encrypted')
    os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)
    app.config['UPLOAD_FOLDER_ENCRYPTED'] = ENCRYPTED_FOLDER

    # تسجيل البلوروت
    from .routes import main
    app.register_blueprint(main)

    from . import models

    return app
