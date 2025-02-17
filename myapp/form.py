import re

from flask_login import current_user
from flask_wtf import FlaskForm
from wtforms import (
    BooleanField,
    EmailField,
    PasswordField,
    StringField,
    SubmitField,
    ValidationError,
)
from wtforms.fields import FileField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length

from myapp.models import User


def password_check(form, field):
    """
    Verify that the password meets the following criteria:
    1. 8 characters or more
    2. At least one uppercase letter
    3. At least one lowercase letter
    4. At least one number
    5. At least one special character (excluding spaces)
    """
    password = field.data

    if len(password) < 8:
        raise ValidationError("Password must be at least 8 characters long")

    if not re.search(r"[A-Z]", password):
        raise ValidationError(
            "Password must contain at least one uppercase letter"
        )

    if not re.search(r"[a-z]", password):
        raise ValidationError(
            "Password must contain at least one lowercase letter"
        )

    if not re.search(r"[0-9]", password):
        raise ValidationError("Password must contain at least one number")

    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        raise ValidationError(
            "Password must contain at least one special character"
        )


class RegisterForm(FlaskForm):
    username = StringField(validators=[DataRequired(), Length(min=3, max=50)])
    email = EmailField(validators=[Email(), DataRequired()])
    password = PasswordField(
        validators=[DataRequired(), Length(min=6), password_check]
    )
    confirm_password = PasswordField(
        validators=[DataRequired(), EqualTo("password"), Length(min=6)]
    )
    submit = SubmitField()

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError("Email already exists.")


class TwoFactorForm(FlaskForm):
    token = StringField(
        "Verification Code", validators=[DataRequired(), Length(8, 8)]
    )
    submit = SubmitField("Submit")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    remember = BooleanField("Remember Me")
    submit = SubmitField("Login")


class RequestResetForm(FlaskForm):
    email = EmailField("Email:", validators=[Email(), DataRequired()])
    submit = SubmitField("Request Password Reset")

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError(
                "There is no account created with that Email. Please Sign UP."
            )


class PasswordResetForm(FlaskForm):
    password = PasswordField(validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField(
        validators=[
            DataRequired(),
            EqualTo("password"),
            Length(min=6),
            password_check,
        ]
    )
    submit = SubmitField("Reset Password")


class UpdateAccountForm(FlaskForm):
    username = StringField(
        "Username:", validators=[DataRequired(), Length(min=3, max=50)]
    )
    email = EmailField("Email:", validators=[Email(), DataRequired()])
    account_submit = SubmitField("Update Account")

    def validate_email(self, email):
        if current_user.email != email.data:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError("Email already exists.")


class UpdatePasswordForm(FlaskForm):
    new_password = PasswordField(
        "New Password:", validators=[Length(min=6), password_check]
    )
    confirm_new_password = PasswordField(
        "Confirm New Password:",
        validators=[Length(min=6), EqualTo("new_password")],
    )
    password_submit = SubmitField("Update Password")


class CreateGroupForm(FlaskForm):
    group_title = StringField(
        "Group Title", validators=[DataRequired(), Length(min=3, max=20)]
    )
    group_description = TextAreaField(
        "Group Description", validators=[DataRequired(), Length(max=300)]
    )
    group_image = FileField("Group Icon")
    group_tags = StringField("Group Tags")
    submit = SubmitField("Proceed to Create")


class EditGroupForm(FlaskForm):
    group_title = StringField(
        "Group Title", validators=[DataRequired(), Length(min=3, max=20)]
    )
    group_description = TextAreaField(
        "Group Description", validators=[DataRequired(), Length(max=300)]
    )
    group_image = FileField("Group Icon")
    group_tags = StringField("Group Tags")
    submit = SubmitField("Proceed to Create")
