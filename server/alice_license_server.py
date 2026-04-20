from flask import Flask, jsonify, request
import json
from pathlib import Path

app = Flask(__name__)

BASE = Path(__file__).resolve().parent
DB_PATH = BASE / "allowed_clients.json"

def load_db():
    if not DB_PATH.exists():
        DB_PATH.write_text(json.dumps({"clients": {}}, indent=2))
    return json.loads(DB_PATH.read_text())

def save_db(db):
    DB_PATH.write_text(json.dumps(db, indent=2))

@app.route("/")
def home():
    return jsonify({"message": "alice license server running", "ok": True})

@app.post("/api/v1/license/check")
def check():
    db = load_db()
    data = request.json
    pc = data.get("pc_code", "")

    if pc not in db["clients"]:
        db["clients"][pc] = {"blocked": False}

    if db["clients"][pc]["blocked"]:
        return jsonify({"ok": False, "message": "차단"})

    save_db(db)
    return jsonify({"ok": True})

# 🔥 관리자 페이지 추가
@app.get("/admin")
def admin():
    db = load_db()
    clients = db.get("clients", {})

    html = "<h1>관리자 페이지</h1><br>"
    for k, v in clients.items():
        status = "차단됨" if v.get("blocked") else "정상"
        html += f"<p>{k} : {status}</p>"

    return html

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
