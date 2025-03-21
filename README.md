# GruScholar - Group Chat Platform

GruScholar is a real-time group chat platform designed for academic collaboration. It allows users to create and join groups, chat in real-time, and award points to helpful community members.

## Features

- **User Authentication**
  - Email-based registration and login
  - Two-factor authentication via email
  - Password reset functionality
  - Account management

- **Group Management**
  - Create groups with titles, descriptions, tags, and images
  - Browse groups on the homepage
  - Filter groups by tags and other criteria
  - Join and leave groups

- **Real-time Chat**
  - Socket.IO-based live messaging
  - Message encryption for privacy
  - Point system (award points to helpful users with @username++)
  - "Bitz" awards for groups

- **Responsive Design**
  - Mobile-friendly interface
  - TailwindCSS styling

## Technology Stack

- **Backend**: Flask, SQLite, Flask-SocketIO
- **Frontend**: HTML, CSS (TailwindCSS), JavaScript
- **Authentication**: Flask-Login, Flask-Bcrypt
- **Data Security**: Cryptography (Fernet encryption)
- **Email**: Flask-Mail

## Project Structure

The project follows a modular structure:

- `group_app/myapp/` - Main application directory
  - `__init__.py` - Application initialization
  - `models.py` - Database models
  - `routes.py` - HTTP routes and socket events
  - `form.py` - Form definitions
  - `encryption.py` - Message encryption functionality
  - `utils.py` - Utility functions
  - `static/` - Static assets
  - `templates/` - HTML templates

## Setup and Installation

1. Clone the repository
2. Create a virtual environment and activate it:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
4. Create a `.env` file with the following variables:
   ```
   MAIL_USERNAME=your_email@gmail.com
   MAIL_PASSWORD=your_app_password
   MESSAGE_ENCRYPTION_KEY=your_fernet_key
   ```
   The encryption key is obtained by running `python generate_key.py`
5. Run `npm install -D tailwindcss@3 postcss autoprefixer
npx tailwindcss init -p` to install tailwind
6. Run `npm install flowbite ` to install flowbite
7. Start flask server by running `python run.py` in the created virtual environment
8. Run `npm run tailwind` to start tailwind
9. Run the application:
   ```
   python run.py
   ```

## Usage

1. Register an account with your email
2. Verify your account via the two-factor authentication code
3. Create a group or browse existing groups to join
4. Start chatting with group members
5. Award points to helpful users with @username++ in your messages
6. Award "Bitz" to groups you find valuable

## Security Features

- Passwords are hashed using Bcrypt
- Messages are encrypted using Fernet symmetric encryption
- CSRF protection on all forms
- Two-factor authentication
