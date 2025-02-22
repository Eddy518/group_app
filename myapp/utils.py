import re
from myapp.models import User, db


def handle_points(message, sender_id):
    """
    Parse messages for @username++ and award points
    """

    pattern = r"@(\w+)\+\+"

    matches = re.finditer(pattern, message)
    recipients = []

    for match in matches:
        username = match.group(1)

        recipient = User.query.filter_by(username=username).first()
        if recipient and recipient.id != sender_id:
            recipient.points += 1
            recipient.append(
                {"username": recipient.username, "new_points": recipient.points}
            )
            try:
                db.session.commit()
            except:
                db.session.rollback()
                return []

    return recipients
