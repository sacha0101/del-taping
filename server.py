import os, re, secrets
import psycopg
from psycopg.rows import dict_row
from flask import Flask, request, jsonify, send_from_directory

HERE = os.path.dirname(os.path.abspath(__file__))
DATABASE_URL = os.environ["DATABASE_URL"]

app = Flask(__name__)


def db():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


with db() as c:
    c.execute("CREATE TABLE IF NOT EXISTS users (key TEXT PRIMARY KEY, username TEXT NOT NULL, token TEXT NOT NULL)")
    c.execute("""CREATE TABLE IF NOT EXISTS words (
        id SERIAL PRIMARY KEY, key TEXT UNIQUE NOT NULL, text TEXT NOT NULL, created_by TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS word_scores (
        id SERIAL PRIMARY KEY, word_id INTEGER NOT NULL, key TEXT NOT NULL,
        username TEXT NOT NULL, time_ms INTEGER NOT NULL, created TIMESTAMP DEFAULT NOW())""")
    c.execute("INSERT INTO words (key, text, created_by) VALUES ('delphine bichet', 'Delphine Bichet', 'admin') ON CONFLICT DO NOTHING")


def check_user(username, token):
    with db() as c:
        row = c.execute("SELECT token FROM users WHERE key = %s", ((username or "").lower(),)).fetchone()
    return bool(row) and secrets.compare_digest(row["token"], token or "")


@app.get("/")
def index():
    return send_from_directory(HERE, "index.html")


@app.post("/api/login")
def login():
    d = request.get_json(silent=True) or {}
    username, token = (d.get("username") or "").strip(), d.get("token") or ""
    if not re.fullmatch(r"[\w\- .]{2,16}", username):
        return jsonify(error="Pseudo invalide (2-16 caractères)."), 400
    key = username.lower()
    with db() as c:
        row = c.execute("SELECT username, token FROM users WHERE key = %s", (key,)).fetchone()
        if row:
            if secrets.compare_digest(row["token"], token):
                return jsonify(username=row["username"], token=token)
            return jsonify(error="Ce pseudo est déjà pris."), 409
        t = secrets.token_hex(16)
        c.execute("INSERT INTO users (key, username, token) VALUES (%s, %s, %s)", (key, username, t))
    return jsonify(username=username, token=t)


@app.get("/api/words")
def words():
    with db() as c:
        rows = c.execute("""SELECT w.id, w.text, COUNT(s.id) AS plays, MIN(s.time_ms) AS best
                            FROM words w LEFT JOIN word_scores s ON s.word_id = w.id
                            GROUP BY w.id ORDER BY plays DESC, w.id DESC LIMIT 200""").fetchall()
    return jsonify(rows)


@app.post("/api/words")
def add_word():
    d = request.get_json(silent=True) or {}
    if not check_user(d.get("username"), d.get("token")):
        return jsonify(error="Non authentifié."), 401
    text = re.sub(r"\s+", " ", (d.get("text") or "").strip())
    if not (2 <= len(text) <= 40) or not text.isprintable():
        return jsonify(error="Le mot doit faire 2 à 40 caractères."), 400
    with db() as c:
        c.execute("INSERT INTO words (key, text, created_by) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
                  (text.lower(), text, d["username"]))
        row = c.execute("SELECT id FROM words WHERE key = %s", (text.lower(),)).fetchone()
    return jsonify(id=row["id"])


@app.post("/api/score")
def score():
    d = request.get_json(silent=True) or {}
    if not check_user(d.get("username"), d.get("token")):
        return jsonify(error="Non authentifié."), 401
    try:
        time_ms, word_id = int(d.get("time_ms")), int(d.get("word_id"))
    except (TypeError, ValueError):
        return jsonify(error="Données invalides."), 400
    with db() as c:
        w = c.execute("SELECT text FROM words WHERE id = %s", (word_id,)).fetchone()
        if not w:
            return jsonify(error="Mot inconnu."), 404
        if not (max(300, len(w["text"]) * 50) <= time_ms <= 600_000):
            return jsonify(error="Temps refusé."), 400
        c.execute("INSERT INTO word_scores (word_id, key, username, time_ms) VALUES (%s, %s, %s, %s)",
                  (word_id, d["username"].lower(), d["username"], time_ms))
    return jsonify(ok=True)


@app.get("/api/leaderboard")
def leaderboard():
    try:
        word_id = int(request.args.get("word_id"))
    except (TypeError, ValueError):
        return jsonify([])
    with db() as c:
        rows = c.execute("""SELECT MAX(username) AS username, MIN(time_ms) AS best, COUNT(*) AS tries
                            FROM word_scores WHERE word_id = %s GROUP BY key ORDER BY best ASC LIMIT 20""",
                         (word_id,)).fetchall()
    return jsonify(rows)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
