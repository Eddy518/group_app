from flask_login import UserMixin
from itsdangerous.url_safe import URLSafeTimedSerializer as Serializer
from datetime import datetime

from myapp import app, db, login_manager


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20))
    email = db.Column(db.Text, unique=True, nullable=False)
    password = db.Column(db.Text, nullable=False)
    points = db.Column(db.Integer, default=0)

    def to_dict(self):
        return {"username": self.username, "points": self.points}

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config["SECRET_KEY"], expires_sec)
        return s.dumps({"user_id": self.id}).decode("utf-8")

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config["SECRET_KEY"])
        try:
            user_id = s.loads(token)["user_id"]
        except:
            return None
        return User.query.get(user_id)

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

    def __repr__(self) -> str:
        return f"Group ('{self.group_title}', '{self.group_description}','{self.group_picture_file}','{self.group_tags}','{self.created_at}')"


class GroupMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey("group.id"), nullable=False)

    user = db.relationship("User", backref="messages")
    group = db.relationship("Group", backref="messages")

    def to_dict(self):
        return {
            "id": self.id,
            "content": self.content,
            "timestamp": self.timestamp.isoformat(),
            "user": {
                "id": self.user.id,
                "username": self.user.username,
            },
        }
