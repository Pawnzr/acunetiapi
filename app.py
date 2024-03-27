from flask import Flask

app = Flask(__name__)
from hehe import routing_acu2

app.register_blueprint(routing_acu2)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8090, debug=True)
