from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, Any

from flask import Flask, jsonify, redirect, render_template_string, request, url_for

app = Flask(__name__)

BASE = Path(__file__).resolve().parent
DB_PATH = BASE / "allowed_clients.json"


def load_db() -> Dict[str, Any]:
    if not DB_PATH.exists():
        DB_PATH.write_text(
            json.dumps({"clients": {}}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    try:
        data = json.loads(DB_PATH.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            data = {}
    except Exception:
        data = {}

    data.setdefault("clients", {})
    return data


def save_db(data: Dict[str, Any]) -> None:
    DB_PATH.write_text(
        json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


@app.get("/")
def home():
    return jsonify({"message": "alice license server running", "ok": True})


@app.post("/api/v1/license/check")
def license_check():
    db = load_db()
    payload = request.get_json(silent=True) or {}
    pc_code = str(payload.get("pc_code", "")).strip()

    if not pc_code:
        return jsonify({"ok": False, "message": "pc_code 필요"}), 400

    clients = db["clients"]
    row = clients.get(pc_code)

    if row is None:
        clients[pc_code] = {"blocked": False}
        save_db(db)
        row = clients[pc_code]

    if row.get("blocked"):
        return jsonify({"ok": False, "message": "차단"})

    return jsonify({"ok": True})


ADMIN_HTML = """
<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <title>ALICE 관리자 페이지</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 24px; background: #111; color: #eee; }
    h1 { margin-bottom: 16px; }
    table { width: 100%; border-collapse: collapse; background: #1b1b1b; }
    th, td { border: 1px solid #444; padding: 10px; text-align: left; }
    th { background: #222; }
    a.btn { display: inline-block; padding: 6px 10px; margin-right: 6px; border-radius: 6px; color: white; text-decoration: none; font-weight: bold; }
    .block { background: #c0392b; }
    .unblock { background: #27ae60; }
    .ok { color: #7CFC98; font-weight: bold; }
    .bad { color: #ff7b7b; font-weight: bold; }
    .note { color: #bbb; margin-bottom: 14px; }
  </style>
</head>
<body>
  <h1>ALICE 관리자 페이지</h1>
  <div class="note">고객 PC 목록 / 차단 / 해제</div>

  <table>
    <thead>
      <tr>
        <th>PC 코드</th>
        <th>상태</th>
        <th>동작</th>
      </tr>
    </thead>
    <tbody>
      {% for pc_code, row in rows %}
      <tr>
        <td>{{ pc_code }}</td>
        <td>
          {% if row.get("blocked") %}
            <span class="bad">차단</span>
          {% else %}
            <span class="ok">사용중</span>
          {% endif %}
        </td>
        <td>
          <a class="btn block" href="{{ url_for('admin_block', pc_code=pc_code) }}">차단</a>
          <a class="btn unblock" href="{{ url_for('admin_unblock', pc_code=pc_code) }}">해제</a>
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</body>
</html>
"""


@app.get("/admin")
def admin_page():
    db = load_db()
    rows = sorted(db["clients"].items(), key=lambda x: x[0])
    return render_template_string(ADMIN_HTML, rows=rows)


@app.get("/admin/block/<pc_code>")
def admin_block(pc_code: str):
    db = load_db()
    db["clients"].setdefault(pc_code, {"blocked": False})
    db["clients"][pc_code]["blocked"] = True
    save_db(db)
    return redirect(url_for("admin_page"))


@app.get("/admin/unblock/<pc_code>")
def admin_unblock(pc_code: str):
    db = load_db()
    db["clients"].setdefault(pc_code, {"blocked": False})
    db["clients"][pc_code]["blocked"] = False
    save_db(db)
    return redirect(url_for("admin_page"))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
