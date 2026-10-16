import os, re, sqlite3, secrets
from flask import Flask, request, jsonify, send_from_directory

HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(HERE, "data.db"))
MIN_MS = 700  # en dessous = impossible humainement (anti-triche basique)

app = Flask(__name__)


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


with db() as c:
    c.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY COLLATE NOCASE, token TEXT NOT NULL)")
    c.execute("""CREATE TABLE IF NOT EXISTS scores (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL COLLATE NOCASE,
        time_ms INTEGER NOT NULL,
        created TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")


def check_user(username, token):
    with db() as c:
        row = c.execute("SELECT token FROM users WHERE username = ?", (username,)).fetchone()
    return bool(row) and secrets.compare_digest(row["token"], token or "")


@app.get("/")
def index():
    return send_from_directory(HERE, "index.html")


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    token = data.get("token") or ""
    if not re.fullmatch(r"[\w\- .]{2,16}", username):
        return jsonify(error="Pseudo invalide (2-16 caractères : lettres, chiffres, _ ou -)."), 400
    with db() as c:
        row = c.execute("SELECT username, token FROM users WHERE username = ?", (username,)).fetchone()
        if row:
            if secrets.compare_digest(row["token"], token):
                return jsonify(username=row["username"], token=token)
            return jsonify(error="Ce pseudo est déjà pris."), 409
        new_token = secrets.token_hex(16)
        c.execute("INSERT INTO users (username, token) VALUES (?, ?)", (username, new_token))
    return jsonify(username=username, token=new_token)


@app.post("/api/score")
def score():
    data = request.get_json(silent=True) or {}
    username, token = data.get("username", ""), data.get("token", "")
    try:
        time_ms = int(data.get("time_ms"))
    except (TypeError, ValueError):
        return jsonify(error="Temps invalide."), 400
    if not check_user(username, token):
        return jsonify(error="Non authentifié."), 401
    if not (MIN_MS <= time_ms <= 600_000):
        return jsonify(error="Temps refusé."), 400
    with db() as c:
        c.execute("INSERT INTO scores (username, time_ms) VALUES (?, ?)", (username, time_ms))
    return jsonify(ok=True)


@app.get("/api/leaderboard")
def leaderboard():
    with db() as c:
        rows = c.execute("""SELECT username, MIN(time_ms) AS best, COUNT(*) AS tries
                            FROM scores GROUP BY username ORDER BY best ASC LIMIT 20""").fetchall()
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
