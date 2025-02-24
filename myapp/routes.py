import secrets
import pytz
from datetime import datetime
from flask import (
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
    session,
    abort,
)
from flask_login import current_user, login_required, logout_user, login_user
from flask_login.login_manager import timedelta
from flask_mail import Message
from myapp import resize_group_image

from myapp import app, bcrypt, db, mail, socketio
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
from myapp.models import User, Group, GroupMessage, GroupMember, GroupPoints

from flask_socketio import emit, join_room, leave_room
from myapp.utils import handle_points, convert_to_local

online_users = {}


@app.route("/")
def home():
    # Get sort parameter
    sort = request.args.get("sort", "")
    tag_filter = request.args.get("tag", "")

    # Base query
    groups_query = Group.query

    # Apply tag filter if specified
    if tag_filter:
        groups_query = groups_query.filter(Group.group_tags.like(f"%{tag_filter}%"))

    # Apply sorting
    if sort == "newest":
        groups_query = groups_query.order_by(Group.created_at.desc())
    elif sort == "oldest":
        groups_query = groups_query.order_by(Group.created_at.asc())
    elif sort == "members":
        groups_query = (
            groups_query.join(GroupMember)
            .group_by(Group.id)
            .order_by(db.func.count(GroupMember.id).desc())
        )
    elif sort == "active":
        groups_query = (
            groups_query.join(GroupMessage)
            .group_by(Group.id)
            .order_by(db.func.count(GroupMessage.id).desc())
        )
    else:
        # Default sorting
        groups_query = groups_query.order_by(Group.created_at.desc())

    # Execute query
    groups = groups_query.all()

    # Get all unique tags
    all_tags = set()
    for group in Group.query.all():
        if group.group_tags:
            # Split tags and strip whitespace
            tags = [tag.strip() for tag in group.group_tags.split(",")]
            all_tags.update(tags)

    # Sort tags alphabetically
    all_tags = sorted(all_tags)

    return render_template(
        "index.html",
        current_user=current_user,
        current_page="home",
        groups=groups,
        all_tags=all_tags,
        selected_sort=sort,
        selected_tag=tag_filter,
    )


@app.template_filter("formatdatetime")
def format_datetime(timestamp):
    """Convert UTC timestamp to local time and format it"""
    if isinstance(timestamp, str):
        try:
            timestamp = datetime.fromisoformat(timestamp)
        except:
            return timestamp

    local_time = convert_to_local(timestamp)
    return local_time.strftime("%I:%M %p")


@app.route("/api/group/<int:group_id>/top-contributors")
@login_required
def get_top_contributors(group_id):
    top_contributors = (
        User.query.join(GroupPoints)
        .filter(GroupPoints.group_id == group_id)
        .order_by(GroupPoints.points.desc())
        .limit(5)
        .all()
    )

    return jsonify(
        [
            {"username": user.username, "points": user.get_points_in_group(group_id)}
            for user in top_contributors
        ]
    )


@app.route("/group/<int:group_id>/chat")
@login_required
def chat_group(group_id):
    group = Group.query.get_or_404(group_id)

    if not group.is_member(current_user):
        group.add_member(current_user)
        try:
            db.session.commit()
            flash("You have joined the group", "success")
        except:
            db.session.rollback()
            flash("Error joining the group", "error")
            return redirect(url_for("home"))

    messages = (
        GroupMessage.query.filter_by(group_id=group_id)
        .order_by(GroupMessage.timestamp.desc())
        .limit(50)
        .all()
    )
    messages.reverse()
    message_dicts = [msg.to_dict() for msg in messages]

    # Get members with their points
    members = []
    for member in group.get_members():
        group_points = GroupPoints.query.filter_by(
            user_id=member.id, group_id=group_id
        ).first()
        members.append(
            {
                "id": member.id,
                "username": member.username,
                "points": group_points.points if group_points else 0,
            }
        )

    # Get top contributors
    top_contributors = (
        db.session.query(User, GroupPoints.points)
        .join(GroupPoints)
        .filter(GroupPoints.group_id == group_id)
        .order_by(GroupPoints.points.desc())
        .limit(5)
        .all()
    )

    top_contributors_list = [
        {"id": user.id, "username": user.username, "points": points}
        for user, points in top_contributors
    ]

    if group_id not in online_users:
        online_users[group_id] = set()

    return render_template(
        "groups/group_chat.html",
        group=group,
        messages=message_dicts,
        current_user=current_user,
        members=members,
        top_contributors=top_contributors_list,
        online_users=online_users[group_id],
        online_count=len(online_users.get(group_id, set())),
    )


@socketio.on("join")
def on_join(data):
    group_id = data["group_id"]
    room = f"group_{group_id}"
    join_room(room)

    if group_id not in online_users:
        online_users[group_id] = set()
    online_users[group_id].add(current_user.username)

    # Get updated member list with points
    group = Group.query.get_or_404(group_id)
    members = []
    for member in group.get_members():
        group_points = GroupPoints.query.filter_by(
            user_id=member.id, group_id=group_id
        ).first()
        members.append(
            {
                "id": member.id,
                "username": member.username,
                "points": group_points.points if group_points else 0,
            }
        )

    # Get updated top contributors
    top_contributors = (
        db.session.query(User, GroupPoints.points)
        .join(GroupPoints)
        .filter(GroupPoints.group_id == group_id)
        .order_by(GroupPoints.points.desc())
        .limit(5)
        .all()
    )

    top_contributors_list = [
        {"id": user.id, "username": user.username, "points": points}
        for user, points in top_contributors
    ]

    emit(
        "status",
        {
            "msg": f"{current_user.username} has joined the chat",
            "type": "join",
            "username": current_user.username,
            "online_count": len(online_users[group_id]),
            "online_users": list(online_users[group_id]),
            "members": members,
            "top_contributors": top_contributors_list,
        },
        room=room,
        broadcast=True,
    )


@socketio.on("leave")
def on_leave(data):
    group_id = data["group_id"]
    room = f"group_{group_id}"
    leave_room(room)

    if group_id in online_users:
        online_users[group_id].discard(current_user.id)
    emit(
        "status",
        {
            "msg": f"{current_user.username} has left the chat",
            "type": "leave",
            "username": current_user.username,
            "online_count": (
                len(online_users[group_id]) if group_id in online_users else 0
            ),
            "online_users": list(online_users[group_id]),
        },
        room=room,
        broadcast=True,
    )


@socketio.on("disconnect")
def on_disconnect():
    # Clean up when user disconnects
    for group_id in list(online_users.keys()):
        if current_user.username in online_users[group_id]:
            online_users[group_id].discard(current_user.username)
            room = f"group_{group_id}"
            emit(
                "status",
                {
                    "msg": f"{current_user.username} has disconnected",
                    "type": "leave",
                    "username": current_user.username,
                    "online_count": len(online_users[group_id]),
                },
                room=room,
                broadcast=True,
            )


@socketio.on("message")
def handle_message(data):
    content = data["message"]
    group_id = data["group_id"]
    room = f"group_{group_id}"

    message = GroupMessage(content=content, user_id=current_user.id, group_id=group_id)
    db.session.add(message)

    recipients = handle_points(content, current_user.id, group_id, User, GroupPoints)

    try:
        db.session.commit()
        emit(
            "message",
            {
                "id": message.id,
                "msg": content,
                "user": current_user.username,
                "timestamp": message.timestamp.isoformat(),
                "points_awarded": recipients,
            },
            room=room,
        )

        if recipients:
            for recipient in recipients:
                emit(
                    "points_awarded",
                    {
                        "recipient": recipient["username"],
                        "awarder": recipient["awarder"],
                        "new_points": recipient["new_points"],
                    },
                    room=room,
                )

            # Send updated top contributors after points are awarded
            top_contributors = (
                db.session.query(User, GroupPoints.points)
                .join(GroupPoints)
                .filter(GroupPoints.group_id == group_id)
                .order_by(GroupPoints.points.desc())
                .limit(5)
                .all()
            )

            top_contributors_list = [
                {"id": user.id, "username": user.username, "points": points}
                for user, points in top_contributors
            ]

            emit(
                "status",
                {
                    "top_contributors": top_contributors_list,
                },
                room=room,
            )

    except:
        db.session.rollback()
        emit("error", {"msg": "Failed to send message"}, room=room)


@socketio.on("request_updates")
def handle_update_request(data):
    group_id = data["group_id"]
    room = f"group_{group_id}"

    group = Group.query.get_or_404(group_id)

    # Get members with their points
    members = []
    for member in group.get_members():
        group_points = GroupPoints.query.filter_by(
            user_id=member.id, group_id=group_id
        ).first()
        members.append(
            {
                "username": member.username,
                "points": group_points.points if group_points else 0,
                "id": member.id,
            }
        )

    # Get top contributors
    top_contributors = (
        db.session.query(User, GroupPoints.points)
        .join(GroupPoints)
        .filter(GroupPoints.group_id == group_id)
        .order_by(GroupPoints.points.desc())
        .limit(5)
        .all()
    )

    top_contributors_list = [
        {"username": user.username, "points": points, "id": user.id}
        for user, points in top_contributors
    ]

    emit(
        "status",
        {
            "members": members,
            "top_contributors": top_contributors_list,
            "online_users": list(online_users.get(group_id, set())),
            "online_count": len(online_users.get(group_id, set())),
        },
        room=room,
    )


@app.route("/award_points")
def award_points():
    pass


@app.route("/api/process-message", methods=["POST"])
@login_required
def process_message():
    data = request.get_json()
    message = data.get("message")

    if not message:
        return jsonify({"error": "No message provided"}), 400


@app.route("/groups/create/", methods=("GET", "POST"))
@login_required
def create_group():
    form = CreateGroupForm()
    if form.validate_on_submit():
        try:
            group_picture_file = "default.jpg"
            if form.group_image.data:
                group_picture_file = resize_group_image.save_picture(
                    form.group_image.data
                )

            # Create the group
            group = Group(
                group_title=form.group_title.data,
                group_description=form.group_description.data,
                group_picture_file=group_picture_file,
                group_tags=form.group_tags.data,
            )

            # Add to database
            db.session.add(group)
            db.session.flush()  # This assigns an ID to the group

            # Add current user as admin member
            group.add_admin(current_user)

            # Create initial group points for creator
            group_points = GroupPoints(
                user_id=current_user.id, group_id=group.id, points=0
            )
            db.session.add(group_points)

            db.session.commit()
            flash("Group has been created successfully!", "success")
            return redirect(url_for("chat_group", group_id=group.id))

        except Exception as e:
            db.session.rollback()
            flash("Error creating group. Please try again.", "error")
            print(f"Error creating group: {e}")

    return render_template("groups/create_group.html", form=form)


@app.route("/groups/edit")
def edit_group():
    form = EditGroupForm()
    return render_template("groups/edit_group.html", form=form)


@app.route("/group/<id>/info")
def group_info(id):
    group = Group.query.filter_by(id=id).first()
    if not group:
        abort(404)
    print(group)
    members = []
    for member in group.get_members():
        group_points = GroupPoints.query.filter_by(
            user_id=member.id, group_id=id
        ).first()
        members.append(
            {
                "id": member.id,
                "username": member.username,
                "points": group_points.points if group_points else 0,
            }
        )
    messages = GroupMessage.query.filter_by(group_id=id).all()
    return render_template(
        "groups/group_info.html",
        group=group,
        members=members,
        messages=messages,
        created_time=convert_to_local(group.created_at),
    )


@app.route("/my-groups")
@login_required
def my_groups():
    # Get all groups the user is a member of
    user_groups = (
        Group.query.join(GroupMember)
        .filter(GroupMember.user_id == current_user.id)
        .order_by(Group.created_at.desc())
        .all()
    )

    return render_template("groups/my_groups.html", groups=user_groups)


@app.route("/group/<int:group_id>/leave")
@login_required
def leave_group(group_id):
    group = Group.query.get_or_404(group_id)

    # Check if user is an admin
    if group.is_admin(current_user):
        # Get all members except current user, ordered by join date
        next_admin = (
            GroupMember.query.filter(
                GroupMember.group_id == group_id, GroupMember.user_id != current_user.id
            )
            .order_by(GroupMember.joined_at)
            .first()
        )

        if next_admin:
            # Transfer admin rights to the oldest member
            next_admin.is_admin = True
            try:
                # Remove current user
                group.remove_member(current_user)
                # Remove user's points for this group
                GroupPoints.query.filter_by(
                    user_id=current_user.id, group_id=group_id
                ).delete()
                db.session.commit()
                flash(
                    f"Admin rights transferred to {next_admin.user.username}. You have left the group.",
                    "success",
                )
                return redirect(url_for("home"))
            except Exception as e:
                db.session.rollback()
                flash("Error leaving group. Please try again.", "error")
                return redirect(url_for("chat_group", group_id=group_id))
        else:
            # No other members, delete the group
            try:
                # Delete all related records
                GroupPoints.query.filter_by(group_id=group_id).delete()
                GroupMessage.query.filter_by(group_id=group_id).delete()
                GroupMember.query.filter_by(group_id=group_id).delete()
                db.session.delete(group)
                db.session.commit()
                flash("You were the last member. The group has been deleted.", "info")
                return redirect(url_for("home"))
            except Exception as e:
                db.session.rollback()
                flash("Error deleting group. Please try again.", "error")
                return redirect(url_for("chat_group", group_id=group_id))

    # Regular member leaving
    try:
        group.remove_member(current_user)
        # Remove user's points for this group
        GroupPoints.query.filter_by(user_id=current_user.id, group_id=group_id).delete()
        db.session.commit()
        flash("You have left the group successfully", "success")
        return redirect(url_for("home"))
    except Exception as e:
        db.session.rollback()
        flash("Error leaving group. Please try again.", "error")
        return redirect(url_for("chat_group", group_id=group_id))


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
        if user and bcrypt.check_password_hash(user.password, form.password.data):
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

            hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
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

    return render_template("register_user.html", form=form, current_page="register")


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

    if password_form.password_submit.data and password_form.validate_on_submit():
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
