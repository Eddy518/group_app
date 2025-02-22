from myapp import app, socketio

if __name__ == "__main__":
    # app.run(debug=True, port=9000)
    socketio.run(app, debug=True, port=9000)
