from flask import Blueprint, request, redirect, url_for, session, render_template, jsonify
from flask_bcrypt import Bcrypt
from app.models import User, File
from app.utils import encrypt_file, decrypt_file, sign_file, verify_signature
from flask import current_app, send_file, after_this_request
from werkzeug.utils import secure_filename
from app.models import User, File, AuditLog
import os
from app import db
import pyotp  # لو مش فوق
from urllib.parse import quote, unquote
from app import oauth
main = Blueprint('main', __name__)
bcrypt = Bcrypt()
def log_action(user_id, action):
    ip = request.remote_addr or 'unknown'
    log = AuditLog(user_id=user_id, action=action, ip_address=ip)
    db.session.add(log)
    db.session.commit()
# الصفحة الرئيسية
@main.route('/')
def home():
    return redirect(url_for('main.login_page'))
# تسجيل الدخول
@main.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            email = data.get("email")
            password = data.get("password")

            user = User.query.filter_by(email=email).first()

            if user and user.check_password(password):
                session["user_id"] = user.id
                session["email"] = user.email
                session["role"] = user.role
                session["login_method"] = "manual"

                if user.role == "admin":
                    # Log admin login immediately here (no OTP)
                    log_action(user.id, "Admin logged in")
                    return jsonify({
                        "message": "Admin login successful",
                        "token": "session",
                        "redirect": "/admin/dashboard"
                    }), 200
                else:
                    # 2FA: لا نحفظ user_id حتى يتم التحقق من OTP
                    session["temp_email"] = user.email
                    return jsonify({
                        "message": "Login successful",
                        "token": "session",
                        "redirect": "/verify-otp"
                    }), 200

            else:
                # Log failed attempt only if user exists
                if user:
                    log_action(user.id, "Failed login attempt")
                # Do NOT log if user does not exist (avoid info leak)
                return jsonify({"message": "Invalid credentials"}), 401
        return "Form POST not supported", 400

    return render_template('login.html')

from flask import flash, get_flashed_messages

@main.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")
        role = "user"

        import re
        email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        if not re.match(email_regex, email):
            flash("Invalid email format.", "error")
            return render_template("signup.html")

        pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$'
        if not re.match(pattern, password):
            flash("Password must be at least 8 characters and include uppercase, lowercase, number & special character.", "error")
            return render_template("signup.html")

        if User.query.filter_by(email=email).first():
            flash("Email already exists.", "error")
            return render_template("signup.html")

        new_user = User(name=name, email=email, role=role)
        new_user.set_password(password)
        new_user.otp_secret = pyotp.random_base32()

        db.session.add(new_user)
        db.session.commit()

        # ✅ نفعّل الـ QR فقط للمرة الأولى
        session['temp_email'] = new_user.email
        session['show_qr'] = True
        flash("Signup successful! Please scan QR and verify OTP.", "success")
        return redirect(url_for('main.verify_otp'))

    return render_template('signup.html')

# تسجيل الخروج
@main.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('role', None)
    return redirect(url_for('main.login_page'))

# لوحة تحكم الأدمن
@main.route('/admin/dashboard')
def admin_dashboard():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('main.login_page'))

    all_users = User.query.all()
    all_files = File.query.all()
    return render_template('admin_dashboard.html', users=all_users, files=all_files)

@main.route('/admin/edit-user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if 'role' not in session or session['role'] != 'admin':
        return redirect(url_for('main.login_page'))

    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        user.name = request.form.get('name')
        user.email = request.form.get('email')
        user.role = request.form.get('role')

        password = request.form.get('password')
        if password:
            user.set_password(password)

        db.session.commit()
        return redirect(url_for('main.admin_dashboard'))

    return render_template('edit_user.html', user=user)

@main.route('/admin/delete-user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'role' not in session or session['role'] != 'admin':
        return redirect(url_for('main.login_page'))

    user = User.query.get_or_404(user_id)

    for file in user.files:
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER_ENCRYPTED'], file.filename)
        sig_path = file_path + ".sig"
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
            if os.path.exists(sig_path):
                os.remove(sig_path)
        except Exception as e:
            print(f"Error deleting file: {e}")

    # حذف الملفات من قاعدة البيانات ثم حذف اليوزر
    File.query.filter_by(user_id=user_id).delete()
    db.session.delete(user)
    db.session.commit()

    log_action(session['user_id'], f"Deleted user ID: {user_id}")  # Logging admin user deletion

    # Prevent admin deleting themselves (optional)
    if user.id == session.get('user_id'):
        return "Cannot delete yourself", 400

    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('main.admin_dashboard'))

# لوحة تحكم المستخدم
@main.route('/user/dashboard')
def user_dashboard():
    if not session.get("user_id") or session.get("role") != 'user':
        return redirect(url_for('main.login_page'))

    # ✅ لو لسه ما دخلش OTP
    if session.get("temp_email") and session.get("login_method") == "manual":
        return redirect(url_for('main.verify_otp'))

    user_id = session['user_id']
    user = User.query.get(user_id)
    files = File.query.filter_by(user_id=user_id).all()
    return render_template('user_dashboard.html', user=user, files=files)

@main.route('/upload', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        return redirect(url_for('main.login_page'))

    if 'file' not in request.files:
        return "No file uploaded", 400

    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400

    filename = secure_filename(file.filename)
    user_id = session['user_id']

    upload_folder = current_app.config['UPLOAD_FOLDER']
    raw_path = os.path.join(upload_folder, filename)

    encrypted_folder = current_app.config['UPLOAD_FOLDER_ENCRYPTED']
    encrypted_path = os.path.join(encrypted_folder, filename)

    file.save(raw_path)
    encrypt_file(raw_path, encrypted_path)
    sign_file(encrypted_path)
    os.remove(raw_path)

    new_file = File(filename=filename, user_id=user_id)
    db.session.add(new_file)
    db.session.commit()

    log_action(user_id, f"Uploaded file: {filename}")  # Logging upload action

    if session.get('role') == 'admin':
        return redirect(url_for('main.admin_dashboard'))
    else:
        return redirect(url_for('main.user_dashboard'))

@main.route('/download/<int:file_id>')
def download_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('main.login_page'))

    user_id = session['user_id']
    file_record = File.query.get(file_id)

    if not file_record or file_record.user_id != user_id:
        return "Unauthorized or file not found", 403

    encrypted_path = os.path.join(current_app.config['UPLOAD_FOLDER_ENCRYPTED'], file_record.filename)
    decrypted_path = os.path.join(os.getcwd(), 'decrypted_' + file_record.filename)
    signature_path = encrypted_path + '.sig'  # ✅ صح كده لأنه تم توقيع المشفر

    # ✅ تحقق من التوقيع قبل فك التشفير
    if not os.path.exists(signature_path):
        return "Signature not found", 400

    if not verify_signature(encrypted_path, signature_path):  # ✅ هنا نتحقق من الملف المشفر
        return "Signature verification failed", 400

    # ✅ لو التوقيع سليم، فك التشفير
    decrypt_file(encrypted_path, decrypted_path)

    @after_this_request
    def remove_file(response):
        try:
            os.remove(decrypted_path)
        except Exception as e:
            print("Failed to delete decrypted file:", e)
        return response

    return send_file(decrypted_path, as_attachment=True)

# حذف ملف
@main.route('/delete/<int:file_id>', methods=['POST'])
def delete_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('main.login_page'))

    user_id = session['user_id']
    file_record = File.query.filter_by(id=file_id, user_id=user_id).first()

    if not file_record:
        return "Unauthorized or file not found", 403

    encrypted_path = os.path.join(current_app.config['UPLOAD_FOLDER_ENCRYPTED'], file_record.filename)
    if os.path.exists(encrypted_path):
        os.remove(encrypted_path)

    db.session.delete(file_record)
    db.session.commit()

    log_action(user_id, f"Deleted file ID: {file_id}")  # Logging deletion action

    if session.get('role') == 'admin':
        return redirect(url_for('main.admin_dashboard'))
    else:
        return redirect(url_for('main.user_dashboard'))

@main.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    import pyotp, qrcode
    from io import BytesIO
    import base64

    email = session.get('temp_email')
    if not email:
        return redirect(url_for('main.login_page'))

    user = User.query.filter_by(email=email).first()
    if not user:
        return "User not found", 404
    
    if not user.otp_secret:
        user.otp_secret = pyotp.random_base32()
        db.session.commit()

    if request.method == "POST":
        otp = request.form.get("otp")
        totp = pyotp.TOTP(user.otp_secret)
        if totp.verify(otp):
            log_action(user.id, "User logged in after OTP verification")
            session["user_id"] = user.id
            session["role"] = user.role
            session["email"] = user.email
            session.pop("temp_email", None)
            session.pop("show_qr", None)  # 👈 نشيل الفلاج ده بعد التحقق
            return redirect(url_for('main.user_dashboard') if user.role == 'user' else url_for('main.admin_dashboard'))
        else:
            return render_template("verify.html", error="Invalid OTP")

    # ✅ نعرض QR فقط إذا كانت الجلسة show_qr مفعّلة
    qr_code = None
    if session.get("show_qr"):
        totp = pyotp.TOTP(user.otp_secret)
        otp_uri = totp.provisioning_uri(name=user.email, issuer_name="SecureDocs")
        qr = qrcode.QRCode(box_size=10, border=4)
        qr.add_data(otp_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = BytesIO()
        img.save(buf, format='PNG')
        qr_code = base64.b64encode(buf.getvalue()).decode("utf-8")

    return render_template("verify.html", qr_code=qr_code)

@main.route('/login/okta')
def login_okta():
    redirect_uri = url_for('main.okta_callback', _external=True)
    return oauth.okta.authorize_redirect(redirect_uri)

@main.route('/login/callback')
def okta_callback():
    token = oauth.okta.authorize_access_token()
    user_info = token.get('userinfo') or {}
    email = user_info.get('email')
    name = user_info.get('name', 'User')

    if not email:
        return "Unable to retrieve email from Okta", 400

    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(name=name, email=email, role='user')
        user.set_password("oauth")
        user.otp_secret = pyotp.random_base32()
        db.session.add(user)
        db.session.commit()
    elif not user.role:
        user.role = 'user'
        db.session.commit()

    session['user_id'] = user.id
    session['role'] = user.role
    session['email'] = user.email
    session['login_method'] = 'oauth'

    print(f"LOGIN OKTA: user_id={user.id}, role={user.role}, email={user.email}")

    return redirect('/user/dashboard') if user.role == 'user' else redirect('/admin/dashboard')

@main.route('/github-login')
def github_login():
    redirect_uri = url_for('main.github_callback', _external=True)
    return oauth.github.authorize_redirect(redirect_uri)

@main.route('/github-callback')
def github_callback():
    token = oauth.github.authorize_access_token()
    resp = oauth.github.get('user', token=token)
    profile = resp.json()
    email = profile.get('email') or profile.get('login') + "@github.com"
    name = profile.get('name') or profile.get('login')

    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(name=name, email=email, role='user')
        user.set_password("oauth")
        db.session.add(user)
        db.session.commit()

    session['user_id'] = user.id
    session['role'] = user.role
    session['email'] = user.email
    session['login_method'] = 'oauth'

    return redirect('/user/dashboard') if user.role == 'user' else redirect('/admin/dashboard')


@main.route('/google-login')
def google_login():
    redirect_uri = url_for('main.google_callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@main.route('/google-callback')
def google_callback():
    token = oauth.google.authorize_access_token()
    user_info = token.get('userinfo')
    email = user_info.get('email')
    name = user_info.get('name')

    if not email:
        return "Unable to retrieve email from Google", 400

    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(name=name, email=email, role='user')
        user.set_password("oauth")  # كلمة مرور وهمية
        db.session.add(user)
        db.session.commit()
    elif not user.role:
        user.role = 'user'
        db.session.commit()

    session['user_id'] = user.id
    session['role'] = user.role
    session['email'] = user.email
    session['login_method'] = 'oauth'

    print(f"LOGIN GOOGLE: user_id={user.id}, role={user.role}, email={user.email}")

    return redirect('/user/dashboard') if user.role == 'user' else redirect('/admin/dashboard')


@main.route('/profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        return redirect(url_for('main.login_page'))

    user = User.query.get(session['user_id'])
    if not user:
        flash("User not found.", "error")
        return redirect(url_for('main.login_page'))

    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')

        # Simple validation example (you can add more)
        if not name or not email:
            flash("Name and email cannot be empty.", "error")
            return render_template('profile.html', user=user)

        # Check if email is changed and if it's already taken by someone else
        if email != user.email and User.query.filter_by(email=email).first():
            flash("Email is already in use.", "error")
            return render_template('profile.html', user=user)

        user.name = name
        user.email = email

        if password:
            # You can add password complexity checks here as well
            user.set_password(password)

        db.session.commit()
        log_action(user.id, "Updated profile")  # Logging profile update
        flash("Profile updated successfully.", "success")
        return redirect(url_for('main.edit_profile'))

    return render_template('profile.html', user=user)

@main.route('/integrity-check/<int:file_id>')
def integrity_check(file_id):
    if 'user_id' not in session:
        return redirect(url_for('main.login_page'))

    file_record = File.query.get(file_id)
    if not file_record:
        return "File not found", 404

    encrypted_path = os.path.join(current_app.config['UPLOAD_FOLDER_ENCRYPTED'], file_record.filename)
    signature_path = encrypted_path + '.sig'

    if not os.path.exists(encrypted_path) or not os.path.exists(signature_path):
        return "File or signature missing", 400

    if verify_signature(encrypted_path, signature_path):
        return "✔ Integrity verified successfully"
    else:
        return "✘ Integrity verification failed"

@main.route('/admin/audit-logs')
def audit_logs():
    if 'role' not in session or session['role'] != 'admin':
        return redirect(url_for('main.login_page'))

    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    return render_template('audit_logs.html', logs=logs)
