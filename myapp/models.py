from flask_login import UserMixin
from itsdangerous.url_safe import URLSafeTimedSerializer as Serializer
from datetime import datetime

from myapp import app, db, login_manager
from myapp.utils import MessageEncryption, convert_to_local


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20))
    email = db.Column(db.Text, unique=True, nullable=False)
    password = db.Column(db.Text, nullable=False)

    def get_points_in_group(self, group_id):
        group_points = GroupPoints.query.filter_by(
            user_id=self.id, group_id=group_id
        ).first()

        return group_points.points if group_points else 0

    def to_dict(self):
        return {"username": self.username, "points": self.points}

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config["SECRET_KEY"])
        return s.dumps({"user_id": self.id}, salt=self.password)

    @staticmethod
    def verify_reset_token(token, user_id):
        s = Serializer(app.config["SECRET_KEY"])
        user = User.query.get(user_id)

        if not user:
            return None

        try:
            # Validate the token with the user's password as salt
            data = s.loads(token, salt=user.password, max_age=1800)

            # Confirm token is for this user
            if data.get("user_id") != user.id:
                return None

            return user
        except:
            return None

    def remove(self):
        db.session.delete(self)

    def get_id(self):
        return self.id

    def __repr__(self):
        return "<User %r>" % self.email


class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_title = db.Column(db.String(20), nullable=False)
    group_description = db.Column(db.Text, nullable=False)
    group_picture_file = db.Column(db.String(20), default="default.jpg", nullable=False)
    group_tags = db.Column(db.String(30))
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    bitz = db.Column(db.Integer, default=0)

    def award_bitz(self, amount=1):
        """Award bitz to a group"""
        self.bitz += amount
        db.session.commit()

    def add_admin(self, user):
        """Add a user as an admin member"""
        membership = GroupMember.query.filter_by(user=user, group=self).first()
        if not membership:
            membership = GroupMember(user=user, group=self, is_admin=True)
            db.session.add(membership)
        else:
            membership.is_admin = True
        return membership

    def add_member(self, user):
        if not self.is_member(user):
            membership = GroupMember(user=user, group=self)
            db.session.add(membership)
            return membership
        return None

    def remove_member(self, user):
        membership = GroupMember.query.filter_by(user=user, group=self).first()
        if membership:
            db.session.delete(membership)

    def is_member(self, user):
        return GroupMember.query.filter_by(user=user, group=self).first() is not None

    def is_admin(self, user):
        """Check if user is an admin of the group"""
        membership = GroupMember.query.filter_by(user=user, group=self).first()
        return membership.is_admin if membership else False

    def get_members(self):
        return [membership.user for membership in self.members]

    def __repr__(self) -> str:
        return f"Group ('{self.group_title}', '{self.group_description}','{self.group_picture_file}','{self.group_tags}','{self.created_at}')"


class GroupPoints(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey("group.id"), nullable=False)
    points = db.Column(db.Integer, default=0)

    user = db.relationship("User", backref="group_points")
    group = db.relationship("Group", backref="user_points")

    def __repr__(self):
        return f"<GroupPoints user={self.user.username} group={self.group.group_title} points={self.points}>"


class GroupMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey("group.id"), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)

    user = db.relationship("User", backref="memberships")
    group = db.relationship("Group", backref="members")

    def __repr__(self) -> str:
        return f"<GroupMember {self.user.username} in {self.group.group_title}>"


class GroupMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey("group.id"), nullable=False)

    user = db.relationship("User", backref="messages")
    group = db.relationship("Group", backref="messages")

    # Private encryptor field to encrypt socketio messages
    _encryptor = MessageEncryption()

    def __init__(self, *args, **kwargs):
        if "content" in kwargs:
            # Encrypt content before saving
            self.original_content = kwargs["content"]
            kwargs["content"] = self._encryptor.encrypt(kwargs["content"])
        super().__init__(*args, **kwargs)

    def decrypted_content(self):
        """Get decrypted message content"""
        return self._encryptor.decrypt(self.content)

    def to_dict(self):
        local_time = convert_to_local(self.timestamp)
        return {
            "id": self.id,
            "content": self.decrypted_content(),
            "timestamp": local_time.strftime("%I:%M %p"),
            "user": {
                "id": self.user.id,
                "username": self.user.username,
            },
        }


class GroupBitzLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey("group.id"), nullable=False)
    amount = db.Column(db.Integer, default=1)
    awarded_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref="bitz_awards")
    group = db.relationship("Group", backref="bitz_logs")
