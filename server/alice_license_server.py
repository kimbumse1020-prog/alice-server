from flask import Flask, jsonify, request, render_template_string, redirect
import json
import os
from pathlib import Path

app = Flask(__name__)

BASE = Path(__file__).resolve().parent
DB_PATH = BASE / "allowed_clients.json"

def load_db():
    if not DB_PATH.exists():
        DB_PATH.write_text(json.dumps({"clients": {}}, indent=2), encoding="utf-8")
    return json.loads(DB_PATH.read_text(encoding="utf-8"))

def save_db(db):
    DB_PATH.write_text(json.dumps(db, indent=2, ensure_ascii=False), encoding="utf-8")

@app.route("/")
def home():
    return jsonify({"message": "alice license server running", "ok": True})

@app.post("/api/v1/license/check")
def check():
    db = load_db()
    data = request.get_json(silent=True) or {}
    pc = str(data.get("pc_code", "")).strip()

    if not pc:
        return jsonify({"ok": False, "message": "pc_code 필요"}), 400

    if pc not in db["clients"]:
        db["clients"][pc] = {"blocked": False}

    if db["clients"][pc].get("blocked"):
        return jsonify({"ok": False, "message": "차단"})

    save_db(db)
    return jsonify({"ok": True})

# 관리자 페이지
HTML = '''
<h2>관리자 페이지</h2>
<table border=1 cellpadding=8>
<tr><th>PC</th><th>상태</th><th>액션</th></tr>
{% for pc, d in clients.items() %}
<tr>
<td>{{ pc }}</td>
<td>{{ "차단" if d.get("blocked") else "사용중" }}</td>
<td>
<a href="/block/{{ pc }}">차단</a> /
<a href="/unblock/{{ pc }}">해제</a>
</td>
</tr>
{% endfor %}
</table>
'''

@app.get("/admin")
def admin():
    db = load_db()
    return render_template_string(HTML, clients=db["clients"])

@app.get("/block/<pc>")
def block(pc):
    db = load_db()
    if pc not in db["clients"]:
        db["clients"][pc] = {"blocked": False}
    db["clients"][pc]["blocked"] = True
    save_db(db)
    return redirect("/admin")

@app.get("/unblock/<pc>")
def unblock(pc):
    db = load_db()
    if pc not in db["clients"]:
        db["clients"][pc] = {"blocked": False}
    db["clients"][pc]["blocked"] = False
    save_db(db)
    return redirect("/admin")

# 🔥 이게 핵심 (포트 자동)
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
