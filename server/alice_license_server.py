
from __future__ import annotations
import datetime as dt
import hashlib
import hmac
import json
import re
from pathlib import Path
from flask import Flask, jsonify, request
app = Flask(__name__)
BASE = Path(__file__).resolve().parent
DB_PATH = BASE / "allowed_clients.json"
LICENSE_SECRET = "ALICE_SOFT_LICENSE_V1_2026"

def load_db() -> dict:
    if not DB_PATH.exists():
        sample = BASE / "allowed_clients.sample.json"
        if sample.exists():
            DB_PATH.write_text(sample.read_text(encoding="utf-8"), encoding="utf-8")
        else:
            DB_PATH.write_text(json.dumps({"admin_token": "CHANGE_ME", "clients": {}, "choices": {}, "activations": {}}, ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        data = json.loads(DB_PATH.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            data.setdefault("clients", {})
            data.setdefault("choices", {})
            data.setdefault("activations", {})
            data.setdefault("admin_token", "CHANGE_ME")
            return data
    except Exception:
        pass
    return {"admin_token": "CHANGE_ME", "clients": {}, "choices": {}, "activations": {}}

def save_db(data: dict) -> None:
    DB_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

def sanitize_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9가-힣]+", "", (name or "").strip())
    return cleaned[:12] if cleaned else "USER"

def build_signature(name: str, expire_ymd: str, mode: str, days_label: str, pc_code: str) -> str:
    payload = f"{sanitize_name(name)}|{expire_ymd}|{mode}|{days_label}|{pc_code}"
    sig = hmac.new(LICENSE_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest().upper()
    return sig[:12]

def validate_key_for_pc(key: str, pc_code: str):
    key = (key or "").strip().upper()
    parts = key.split("-")
    if len(parts) != 5:
        return False, "키 형식이 올바르지 않습니다.", None
    name, expire_ymd, mode, days_label, sig = parts
    if mode not in ("PAY", "SHARE"):
        return False, "키 모드가 올바르지 않습니다.", None
    expected = build_signature(name, expire_ymd, mode, days_label, pc_code.strip().upper())
    if expected != sig:
        return False, "이 PC에서 사용할 수 없는 키입니다.", None
    try:
        expire_date = dt.datetime.strptime(expire_ymd, "%Y%m%d").date()
    except Exception:
        return False, "만료일 형식이 잘못되었습니다.", None
    if dt.date.today() > expire_date:
        return False, "사용 기간이 종료되었습니다.", None
    return True, "정상", {"name": name, "mode": mode, "expire_ymd": expire_ymd, "days_label": days_label}

def is_admin(req) -> bool:
    db = load_db()
    token = req.headers.get("X-ALICE-TOKEN", "").strip()
    return bool(token) and token == str(db.get("admin_token", "")).strip()

@app.get("/")
def home():
    return jsonify({"ok": True, "message": "alice license server running"})

@app.post("/api/v1/license/check")
def api_check():
    db = load_db()
    payload = request.get_json(silent=True) or {}
    pc_code = str(payload.get("pc_code", "")).strip().upper()
    key = str(payload.get("key", "")).strip().upper()
    if not pc_code or not key:
        return jsonify({"ok": False, "message": "pc_code와 key가 필요합니다."}), 400
    ok, msg, meta = validate_key_for_pc(key, pc_code)
    if not ok:
        return jsonify({"ok": False, "message": msg}), 200
    row = db.get("clients", {}).get(pc_code)
    if row:
        if bool(row.get("blocked")):
            return jsonify({"ok": False, "message": "이 PC는 서버에서 차단되었습니다."}), 200
        server_key = str(row.get("key", "")).strip().upper()
        if server_key and server_key != key:
            return jsonify({"ok": False, "message": "서버에 등록된 키와 다릅니다."}), 200
    else:
        db.setdefault("clients", {})[pc_code] = {"key": key, "first_seen": dt.datetime.now().isoformat(timespec="seconds"), "blocked": False}
        save_db(db)
    db.setdefault("activations", {})[pc_code] = {"pc_code": pc_code, "key_tail": key[-12:], "checked_at": dt.datetime.now().isoformat(timespec="seconds"), "mode": meta.get("mode", "") if meta else ""}
    save_db(db)
    return jsonify({"ok": True, "message": "정상", "pc_code": pc_code})

@app.put("/choices/<pc_code>")
def put_choice(pc_code: str):
    db = load_db()
    payload = request.get_json(silent=True) or {}
    db.setdefault("choices", {})[pc_code.strip().upper()] = payload
    save_db(db)
    return jsonify({"ok": True})

@app.put("/activations/<pc_code>")
def put_activation(pc_code: str):
    db = load_db()
    payload = request.get_json(silent=True) or {}
    db.setdefault("activations", {})[pc_code.strip().upper()] = payload
    save_db(db)
    return jsonify({"ok": True})

@app.get("/api/v1/choices/<pc_code>")
def get_choice(pc_code: str):
    db = load_db()
    return jsonify(db.get("choices", {}).get(pc_code.strip().upper(), {}))

@app.post("/api/v1/admin/register")
def admin_register():
    if not is_admin(request):
        return jsonify({"ok": False, "message": "관리자 토큰이 틀립니다."}), 403
    db = load_db()
    payload = request.get_json(silent=True) or {}
    pc_code = str(payload.get("pc_code", "")).strip().upper()
    key = str(payload.get("key", "")).strip().upper()
    if not pc_code or not key:
        return jsonify({"ok": False, "message": "pc_code와 key가 필요합니다."}), 400
    db.setdefault("clients", {})[pc_code] = {"key": key, "name": str(payload.get("name", "")).strip(), "mode": str(payload.get("mode", "")).strip().upper(), "days_value": str(payload.get("days_value", "")).strip(), "blocked": False, "updated_at": dt.datetime.now().isoformat(timespec="seconds")}
    save_db(db)
    return jsonify({"ok": True, "message": "서버 등록 완료"})

@app.post("/api/v1/admin/block")
def admin_block():
    if not is_admin(request):
        return jsonify({"ok": False, "message": "관리자 토큰이 틀립니다."}), 403
    db = load_db()
    payload = request.get_json(silent=True) or {}
    pc_code = str(payload.get("pc_code", "")).strip().upper()
    if not pc_code:
        return jsonify({"ok": False, "message": "pc_code가 필요합니다."}), 400
    db.setdefault("clients", {}).setdefault(pc_code, {})["blocked"] = True
    db["clients"][pc_code]["updated_at"] = dt.datetime.now().isoformat(timespec="seconds")
    save_db(db)
    return jsonify({"ok": True, "message": "차단 완료"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
