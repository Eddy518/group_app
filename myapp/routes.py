import secrets
from datetime import datetime
from flask import (
    flash,
    redirect,
    render_template,
    request,
    url_for,
    session,
)
from flask_login import current_user, login_required, logout_user, login_user
from flask_login.login_manager import timedelta
from flask_mail import Message
from threading import Timer

from myapp import (
    app,
    bcrypt,
    db,
    mail,
)
from myapp.form import (
    LoginForm,
    PasswordResetForm,
    RegisterForm,
    RequestResetForm,
    UpdateAccountForm,
    UpdatePasswordForm,
    TwoFactorForm,
    CreateGroupForm,
    EditGroupForm,
)
from myapp.models import User


@app.route("/")
def home():
    return render_template(
        "index.html", current_user=current_user, current_page="home"
    )


@app.route("/groups/create/")
def create_group():
    form = CreateGroupForm()
    return render_template("groups/create_group.html", form=form)


@app.route("/groups/edit")
def edit_group():
    form = EditGroupForm()
    return render_template("groups/edit_group.html", form=form)


@app.route("/group/chat")
def chat_group():
    return render_template("groups/group_chat.html")


@app.route("/group/info")
def group_info():
    return render_template("groups/group_info.html")


def send_token_email(tk):
    verification_code = tk
    print(session)
    email = session["email"]
    print(verification_code)
    print(email)
    msg = Message(
        "2-Step Verification Code",
        sender=app.config["MAIL_USERNAME"],
        recipients=[email],
    )
    msg.body = f""" Use the following code to login {verification_code}. Expires in 2 minutes."""
    mail.send(msg)


@app.route("/account/verify", methods=("GET", "POST"))
def two_factor():
    form = TwoFactorForm()
    user = User.query.filter_by(email=session["email"]).first()
    if request.method == "GET":
        if "verification_code" not in session or request.args.get("resend"):
            verification_code = secrets.token_hex(4)
            session["verification_code"] = verification_code
            session["code_expiry"] = (
                datetime.utcnow() + timedelta(minutes=2)
            ).timestamp()
            print("I am being run")
            print(session["code_expiry"])
            # At this point create a random token and send it to the user then log them in
            send_token_email(verification_code)

    if request.method == "POST":
        if "verification_code" not in session or "code_expiry" not in session:
            flash(
                "Verification code has expired or doesn't exist. Please request a new one.",
                "error",
            )
            return redirect(url_for("two_factor"))

        if datetime.utcnow().timestamp() > session["code_expiry"]:
            session.pop("verification_code", None)
            session.pop("code_expiry", None)
            flash(
                "Verification code has expired. Please request a new one.",
                "error",
            )
            return redirect(url_for("two_factor"))

        if session.get("verification_code") == form.token.data:
            login_user(user, remember=session["remember"])
            session.pop("verification_code", None)
            session.pop("code_expiry", None)
            return redirect(url_for("home"))
        else:
            flash("The code you have entered is invalid or expired", "error")

    return (
        render_template("two_factor_confirmation.html", form=form),
        200,
        {
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


@app.route("/signin/", methods=("GET", "POST"))
@app.route("/SIGNIN/", methods=("GET", "POST"))
@app.route("/LOGIN/", methods=("GET", "POST"))
@app.route("/login/", methods=("GET", "POST"))
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(
            user.password, form.password.data
        ):
            flash(
                "A Verification Code has been sent to your email. Please input the code to proceed",
                "success",
            )
            session["email"] = form.email.data
            session["remember"] = form.remember.data
            return redirect(url_for("two_factor"))
        else:
            flash(
                """Login unsuccessful. Please check if your Email
                    and Password is correct and try again!""",
                "error",
            )
    return render_template(
        "login_user.html", title=login, form=form, current_page="login"
    )


@app.route("/register/", methods=["POST", "GET"])
@app.route("/REGISTER/", methods=["GET", "POST"])
@app.route("/SIGNUP/", methods=["GET", "POST"])
@app.route("/signup/", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    form = RegisterForm()
    if request.method == "POST":
        if form.validate_on_submit():
            username = form.username.data
            email = form.email.data.lower()
            password = form.password.data

            hashed_password = bcrypt.generate_password_hash(password).decode(
                "utf-8"
            )
            user = User(
                username=username,
                email=email,
                password=hashed_password,
            )

            db.session.add(user)
            db.session.commit()
            session["email"] = email

            flash(
                "Account created successfully! Please proceed to login.",
                "success",
            )
            return redirect(url_for("login"))

    return render_template(
        "register_user.html", form=form, current_page="register"
    )


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message(
        "Password Reset Request",
        sender=app.config["MAIL_USERNAME"],
        recipients=[user.email],
    )
    msg.body = f"""To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}

If you did not make this request then simply ignore this email and no changes will be done.
"""
    mail.send(msg)


@app.route("/request_password", methods=["GET", "POST"])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        print(user)
        send_reset_email(user)
        flash(
            f"Hello, {form.email.data} \n. An email has been sent to you with reset instructions",
            "info",
        )
        return redirect(url_for("reset_request"))
        if not user:
            flash("Please check your credentials and try again.", "error")
    return render_template("reset_request.html", form=form)


@app.route("/request_password/<token>", methods=["GET", "POST"])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for("main_page"))
    user = User.verify_reset_token(token)
    if user is None:
        flash(
            "That token is invalid or expired. Please enter your email again.",
            "error",
        )
        return redirect(url_for("reset_request"))
    form = PasswordResetForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        user.password = hashed_password
        db.session.commit()
        flash(
            "Your password has been successfully updated. Log in to proceed.",
            "info",
        )
        return redirect(url_for("login"))
    return render_template("reset_token.html", form=form)


@app.route("/account/", methods=["GET", "POST"])
@app.route("/profile/", methods=["GET", "POST"])
@login_required
def profile():
    account_form = UpdateAccountForm()
    password_form = UpdatePasswordForm()

    if request.method == "GET":
        account_form.username.data = current_user.username
        account_form.email.data = current_user.email

    if account_form.account_submit.data and account_form.validate_on_submit():
        if (
            current_user.email == account_form.email.data
            and current_user.username == account_form.username.data
        ):
            return redirect(url_for("profile"))
        else:
            current_user.username = account_form.username.data
            current_user.email = account_form.email.data.lower()
            db.session.commit()
            flash("Your Account Info has been updated successfully!", "success")
            return redirect(url_for("profile"))

    if (
        password_form.password_submit.data
        and password_form.validate_on_submit()
    ):
        hashed_password = bcrypt.generate_password_hash(
            password_form.new_password.data
        ).decode("utf-8")
        current_user.password = hashed_password
        db.session.commit()
        flash("Your Password has been updated successfully!", "success")
        return redirect(url_for("profile"))

    return render_template(
        "user_profile.html",
        account_form=account_form,
        password_form=password_form,
        current_page="settings",
    )


@app.route("/account/delete", methods=("GET", "POST"))
@app.route("/profile/delete", methods=("GET", "POST"))
@login_required
def delete_account():
    current_user.remove()
    db.session.commit()
    flash("You no longer exist :)", "info")
    return redirect(url_for("home"))
    return render_template("confirm_delete.html")


@app.route("/logout/")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))


@app.errorhandler(404)
def error_404(error):
    return render_template("404.html")


@app.errorhandler(403)
def error_403(error):
    return render_template("403.html")


@app.errorhandler(401)
def error_401(error):
    return render_template("401.html")


@app.errorhandler(500)
def error_500(error):
    return render_template("500.html")
