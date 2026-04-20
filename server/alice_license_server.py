
from flask import Flask, jsonify, request, render_template_string, redirect
import datetime as dt, json
from pathlib import Path

app = Flask(__name__)
BASE = Path(__file__).resolve().parent
DB_PATH = BASE / "allowed_clients.json"

def load_db():
    if not DB_PATH.exists():
        DB_PATH.write_text(json.dumps({"clients":{}}, indent=2))
    return json.loads(DB_PATH.read_text())

def save_db(db):
    DB_PATH.write_text(json.dumps(db, indent=2))

@app.post("/api/v1/license/check")
def check():
    db = load_db()
    data = request.json
    pc = data.get("pc_code","")

    if pc not in db["clients"]:
        db["clients"][pc] = {"blocked":False}

    if db["clients"][pc]["blocked"]:
        return jsonify({"ok":False,"message":"차단"})

    save_db(db)
    return jsonify({"ok":True})

HTML = '''
<h2>관리</h2>
<table border=1>
<tr><th>PC</th><th>상태</th><th>액션</th></tr>
{% for pc,d in clients.items() %}
<tr>
<td>{{pc}}</td>
<td>{{"차단" if d.blocked else "사용중"}}</td>
<td><a href="/block/{{pc}}">차단</a> | <a href="/unblock/{{pc}}">해제</a></td>
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
    db["clients"][pc]["blocked"]=True
    save_db(db)
    return redirect("/admin")

@app.get("/unblock/<pc>")
def unblock(pc):
    db = load_db()
    db["clients"][pc]["blocked"]=False
    save_db(db)
    return redirect("/admin")

if __name__=="__main__":
    app.run(host="0.0.0.0", port=8000)
