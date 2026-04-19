from __future__ import annotations
# ================== LICENSE / SECURITY START ==================
import base64
import datetime as _dt
import hashlib
import hmac
import json
import os
import platform
import re
import sys
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, simpledialog

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None


LICENSE_SECRET = "ALICE_SOFT_LICENSE_V1_2026"
LICENSE_CACHE_FILE = "alice_license_cache.json"
SERVER_CONFIG_FILE = "license_server_config.json"
AUTO_SERVER_URL = ""
AUTO_SERVER_TOKEN = ""
AUTO_SERVER_REQUIRED = False


def _license_base_dir() -> Path:
    try:
        return Path(sys.argv[0]).resolve().parent
    except Exception:
        return Path.cwd()


def _cache_path() -> Path:
    return _license_base_dir() / LICENSE_CACHE_FILE


def _server_config_path() -> Path:
    return _license_base_dir() / SERVER_CONFIG_FILE


def _load_server_config() -> dict:
    p = _server_config_path()
    if p.exists():
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
        except Exception:
            pass
    return {"enabled": False}


def _server_settings() -> dict:
    cfg = _load_server_config()
    base_url = str(cfg.get("base_url") or AUTO_SERVER_URL or "").strip().rstrip("/")
    token = str(cfg.get("client_token") or AUTO_SERVER_TOKEN or "").strip()
    enabled = bool(cfg.get("enabled")) if "enabled" in cfg else bool(base_url)
    required = bool(cfg.get("required", AUTO_SERVER_REQUIRED))
    return {"enabled": bool(enabled and base_url), "required": required, "base_url": base_url, "token": token}


def _server_enabled() -> bool:
    return bool(_server_settings().get("enabled"))


def _server_headers() -> dict:
    s = _server_settings()
    headers = {"Content-Type": "application/json"}
    token = str(s.get("token", "")).strip()
    if token:
        headers["X-ALICE-TOKEN"] = token
    return headers


def _server_put(path: str, payload: dict) -> None:
    if requests is None:
        return
    s = _server_settings()
    if not s.get("enabled"):
        return
    url = f"{str(s.get('base_url')).rstrip('/')}/{path.lstrip('/')}"
    try:
        requests.put(url, json=payload, timeout=4, headers=_server_headers())
    except Exception:
        return


def _server_post(path: str, payload: dict) -> dict | None:
    if requests is None:
        return None
    s = _server_settings()
    if not s.get("enabled"):
        return None
    url = f"{str(s.get('base_url')).rstrip('/')}/{path.lstrip('/')}"
    try:
        r = requests.post(url, json=payload, timeout=5, headers=_server_headers())
        if r.ok:
            data = r.json()
            return data if isinstance(data, dict) else None
    except Exception:
        return None
    return None


def _remote_license_check(pc_code: str, key: str, mode: str):
    s = _server_settings()
    if not s.get("enabled"):
        return True, "서버 미사용"
    res = _server_post(
        "api/v1/license/check",
        {
            "pc_code": (pc_code or "").strip().upper(),
            "key": (key or "").strip().upper(),
            "mode": (mode or "").strip().upper(),
            "host": platform.node(),
            "app": "ALICE_ENGINE",
        },
    )
    if not isinstance(res, dict):
        if s.get("required"):
            return False, "인증 서버에 연결할 수 없습니다."
        return True, "서버 응답 없음"
    ok = bool(res.get("ok"))
    msg = str(res.get("message") or ("정상" if ok else "서버 인증 실패"))
    return ok, msg

def _choice_cache_dir() -> Path:
    p = _license_base_dir() / "choice_cache"
    try:
        p.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    return p

def _save_choice_cache(pc_code: str, payload: dict) -> None:
    try:
        p = _choice_cache_dir() / f"{pc_code.strip().upper()}.json"
        p.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass

def get_pc_code() -> str:
    raw = f"{platform.node()}|{platform.system()}|{platform.machine()}|{platform.processor()}|{hex(getattr(__import__('uuid'), 'getnode')())}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12].upper()


def _sanitize_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9가-힣]+", "", (name or "").strip())
    return cleaned[:12] if cleaned else "USER"


def build_license_signature(name: str, expire_ymd: str, mode: str, days_label: str, pc_code: str) -> str:
    payload = f"{_sanitize_name(name)}|{expire_ymd}|{mode}|{days_label}|{pc_code}"
    sig = hmac.new(LICENSE_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest().upper()
    return sig[:12]


def validate_license_key(key: str, pc_code: str):
    key = (key or "").strip().upper()
    parts = key.split("-")
    if len(parts) != 5:
        return False, "키 형식이 올바르지 않습니다.", None

    name, expire_ymd, mode, days_label, sig = parts
    if not re.fullmatch(r"\d{8}", expire_ymd):
        return False, "만료일 형식이 올바르지 않습니다.", None

    if mode not in ("PAY", "SHARE"):
        return False, "키 모드가 올바르지 않습니다.", None

    if not re.fullmatch(r"(INF|\d+D)", days_label):
        return False, "기간 정보가 올바르지 않습니다.", None

    expected = build_license_signature(name, expire_ymd, mode, days_label, pc_code)
    if sig != expected:
        return False, "이 PC에서 사용할 수 없는 키이거나 키가 올바르지 않습니다.", None

    try:
        expire_date = _dt.datetime.strptime(expire_ymd, "%Y%m%d").date()
    except Exception:
        return False, "만료일을 읽을 수 없습니다.", None

    today = _dt.date.today()
    if mode in ("PAY", "SHARE") and today > expire_date:
        return False, "사용 기간이 종료되었습니다.", None

    meta = {
        "name": name,
        "expire_ymd": expire_ymd,
        "mode": mode,
        "days_label": days_label,
        "pc_code": pc_code,
        "key": key,
    }
    return True, "인증 완료", meta


def _save_cached_license(meta: dict) -> None:
    p = _cache_path()
    data = {
        "name": meta.get("name", ""),
        "expire_ymd": meta.get("expire_ymd", ""),
        "mode": meta.get("mode", ""),
        "days_label": meta.get("days_label", ""),
        "pc_code": meta.get("pc_code", ""),
        "key": meta.get("key", ""),
        "saved_at": _dt.datetime.now().isoformat(timespec="seconds"),
    }
    try:
        p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass


def _load_cached_license() -> dict | None:
    p = _cache_path()
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _show_warning() -> None:
    warning_text = (
        "[라이선스 및 사용 경고]\n\n"
        "본 프로그램은 라이선스 기반으로 제공되며,\n"
        "허가되지 않은 복제, 배포, 분석(리버스 엔지니어링)을 금지합니다.\n\n"
        "본 프로그램은 인증된 사용자 및 특정 PC에서만 사용이 허용됩니다.\n\n"
        "무단 복제, 공유, 해킹 시도 적발 시\n"
        "서비스 차단 및 민·형사상 책임이 발생할 수 있습니다.\n\n"
        "본 프로그램은 보안 및 사용 이력 확인을 위한 보호 기능이 포함되어 있습니다.\n\n"
        "정식 사용자만 이용하시기 바랍니다."
    )
    messagebox.showwarning("경고", warning_text)



def _show_mode_choice_dialog(pc_code: str) -> dict | None:
    result = {"mode": None, "days": None, "label": ""}

    top = tk.Toplevel()
    top.title("사용 방식 선택")
    top.configure(bg="white")
    top.geometry("620x520")
    top.resizable(False, False)
    top.attributes("-topmost", True)
    top.grab_set()

    tk.Label(top, text=f"PC 코드: {pc_code}", bg="white", fg="black", font=("맑은 고딕", 13, "bold")).pack(padx=18, pady=(18, 10))
    tk.Label(top, text="사용 방식을 선택하세요", bg="white", fg="black", font=("맑은 고딕", 12, "bold")).pack(padx=18, pady=(0, 12))

    info_frame = tk.Frame(top, bg="white", bd=1, relief="solid")
    info_frame.pack(fill="x", padx=18, pady=(0, 12))

    tk.Label(
        info_frame,
        text=("기간제\n"
            "하루 사용료 50,000원\n"
            "기간이 늘어날 경우 협의 후 하향 조정될 수 있습니다."),
        justify="left",
        anchor="w",
        bg="white",
        fg="black",
        font=("맑은 고딕", 11),
        wraplength=560,
    ).pack(fill="x", padx=14, pady=(12, 10))

    tk.Label(
        info_frame,
        text=("수익제\n"
            "수익 금액의 10% 기준이며\n"
            "수익 미발생 시 기본 사용료\n"
            "20,000원 발생합니다."),
        justify="left",
        anchor="w",
        bg="white",
        fg="black",
        font=("맑은 고딕", 11),
        wraplength=560,
    ).pack(fill="x", padx=14, pady=(0, 12))

    def choose_pay():
        days = simpledialog.askinteger("기간제", "며칠을 사용할 것입니까?", parent=top, minvalue=1, maxvalue=365)
        if not days:
            return
        result["mode"] = "PAY"
        result["days"] = int(days)
        result["label"] = f"사용자가 기간제 {days}일을 선택했습니다."
        payload = {
            "pc_code": pc_code,
            "mode": "PAY",
            "days": int(days),
            "label": result["label"],
            "selected_at": _dt.datetime.now().isoformat(timespec="seconds"),
        }
        _server_put(f"choices/{pc_code}", payload)
        _save_choice_cache(pc_code, payload)
        top.destroy()

    def choose_share():
        result["mode"] = "SHARE"
        result["days"] = None
        result["label"] = "사용자가 수익제(10%)를 선택했습니다."
        payload = {
            "pc_code": pc_code,
            "mode": "SHARE",
            "days": None,
            "label": result["label"],
            "selected_at": _dt.datetime.now().isoformat(timespec="seconds"),
        }
        _server_put(f"choices/{pc_code}", payload)
        _save_choice_cache(pc_code, payload)
        top.destroy()

    btn_frame = tk.Frame(top, bg="white")
    btn_frame.pack(fill="x", padx=18, pady=(0, 16))

    tk.Button(btn_frame, text="기간제 선택", command=choose_pay, width=22, height=2, font=("맑은 고딕", 11, "bold")).pack(pady=(0, 8))
    tk.Button(btn_frame, text="수익제 선택", command=choose_share, width=22, height=2, font=("맑은 고딕", 11, "bold")).pack()

    top.wait_window()
    return result if result["mode"] else None



def _prompt_for_license_key(pc_code: str, expected_mode: str | None, selected_plan_label: str = "") -> dict | None:
    key_root = tk.Tk()
    key_root.withdraw()
    menu = tk.Menu(key_root, tearoff=0)

    entry_ref = {"widget": None}

    def do_paste(event=None):
        try:
            w = entry_ref["widget"]
            if w is None:
                return
            txt = key_root.clipboard_get()
            try:
                w.delete("sel.first", "sel.last")
            except Exception:
                pass
            w.insert("insert", txt)
        except Exception:
            pass

    def do_copy(event=None):
        try:
            w = entry_ref["widget"]
            if w is None:
                return
            txt = w.selection_get()
            key_root.clipboard_clear()
            key_root.clipboard_append(txt)
        except Exception:
            pass

    def do_cut(event=None):
        try:
            do_copy()
            w = entry_ref["widget"]
            if w is None:
                return
            w.delete("sel.first", "sel.last")
        except Exception:
            pass

    def popup_menu(event):
        w = entry_ref["widget"]
        if w is None:
            return
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    menu.add_command(label="붙여넣기", command=do_paste)
    menu.add_command(label="복사", command=do_copy)
    menu.add_command(label="잘라내기", command=do_cut)

    for attempt in range(3):
        dlg = tk.Toplevel(key_root)
        dlg.title("키 입력")
        dlg.configure(bg="white")
        dlg.geometry("520x250")
        dlg.resizable(False, False)
        dlg.attributes("-topmost", True)
        dlg.grab_set()

        result = {"value": None}

        tk.Label(dlg, text=f"PC 코드: {pc_code}", bg="white", fg="black", font=("맑은 고딕", 13, "bold")).pack(padx=18, pady=(18, 8))
        if selected_plan_label:
            tk.Label(dlg, text=selected_plan_label, bg="white", fg="#0b63c9", font=("맑은 고딕", 11, "bold")).pack(padx=18, pady=(0, 10))
        tk.Label(dlg, text="발급받은 키를 입력하세요.", bg="white", fg="black", font=("맑은 고딕", 11)).pack(padx=18, pady=(0, 10))

        entry = tk.Entry(dlg, width=42, font=("Consolas", 13))
        entry.pack(padx=18, pady=(0, 14))
        entry.focus_set()
        entry_ref["widget"] = entry
        entry.bind("<Control-v>", do_paste)
        entry.bind("<Shift-Insert>", do_paste)
        entry.bind("<Button-3>", popup_menu)

        btns = tk.Frame(dlg, bg="white")
        btns.pack(pady=(4, 14))

        def on_ok():
            result["value"] = entry.get().strip()
            dlg.destroy()

        def on_cancel():
            result["value"] = None
            dlg.destroy()

        tk.Button(btns, text="확인", width=10, command=on_ok).pack(side="left", padx=6)
        tk.Button(btns, text="취소", width=10, command=on_cancel).pack(side="left", padx=6)

        dlg.wait_window()
        key = result["value"]
        if key is None:
            key_root.destroy()
            return None

        ok, msg, meta = validate_license_key(key, pc_code)
        if not ok:
            messagebox.showerror("인증 실패", f"{msg}\n\n남은 시도: {2 - attempt}", parent=key_root)
            continue

        if expected_mode and meta and meta.get("mode") != expected_mode:
            messagebox.showerror("인증 실패", "선택한 사용 방식과 키 모드가 다릅니다.", parent=key_root)
            continue

        remote_ok, remote_msg = _remote_license_check(pc_code, key, str(meta.get("mode", "")))
        if not remote_ok:
            messagebox.showerror("인증 실패", remote_msg, parent=key_root)
            continue

        _server_put(
            f"activations/{pc_code}",
            {
                "pc_code": pc_code,
                "key_tail": str(key)[-12:],
                "mode": meta.get("mode", ""),
                "activated_at": _dt.datetime.now().isoformat(timespec="seconds"),
            },
        )
        messagebox.showinfo("인증 완료", "라이선스 인증이 완료되었습니다.", parent=key_root)
        key_root.destroy()
        return meta

    messagebox.showerror("차단", "3회 실패로 프로그램이 종료됩니다.", parent=key_root)
    key_root.destroy()
    return None


def ensure_license_access() -> bool:
    root = tk.Tk()
    root.withdraw()

    _show_warning()
    pc_code = get_pc_code()

    cached = _load_cached_license()
    if cached and cached.get("pc_code") == pc_code:
        ok, _, meta = validate_license_key(str(cached.get("key", "")), pc_code)
        if ok and meta:
            remote_ok, _remote_msg = _remote_license_check(pc_code, str(cached.get("key", "")), str(meta.get("mode", "")))
            if remote_ok:
                root.destroy()
                return True

    messagebox.showinfo(
        "PC 코드",
        f"현재 PC 코드:\n{pc_code}\n\n이 코드를 판매자에게 보내서 키를 발급받으세요.",
    )

    mode_info = _show_mode_choice_dialog(pc_code)
    if mode_info is None:
        root.destroy()
        return False

    globals()["SELECTED_PLAN_LABEL"] = mode_info.get("label", "")
    globals()["SELECTED_PLAN_CODE"] = mode_info.get("mode", "") or ""
    globals()["SELECTED_PLAN_DAYS"] = mode_info.get("days")

    messagebox.showinfo("안내", SELECTED_PLAN_LABEL, parent=root)

    meta = _prompt_for_license_key(pc_code, mode_info.get("mode"), SELECTED_PLAN_LABEL)
    if not meta:
        root.destroy()
        return False

    _save_cached_license(meta)
    root.destroy()
    return True

# ================== LICENSE / SECURITY END ==================


# -*- coding: utf-8 -*-
"""
AI Engine Alice V50 — PAT64 FINAL v12_APPLIED (single file)

✅ v3에서 추가 반영(완성본)
- 추천 문구 색상: 플레이어(풀)=파랑, 뱅커(뱅)=빨강
- 승률(%) 높은 순으로 카드 자동 정렬 제거(위치 고정), 순위는 표시만
- 고유 패턴 번호 표시 + 현재 순위(상위10) 표시: (1) (2)  (가로 1~5, 다음 줄 6~10 )
- 가로 카드 개수: 6 → 5 (체크시트/추천/격자 가독성 개선)
- 기존 로직(맞으면 단계 유지 / 틀리면 다음 단계), UNDO/RESET, 승패/승률, 4매 OX 보드 모두 유지
"""


import sys
import time
import random
import tkinter as tk
from pathlib import Path
import subprocess
import tempfile
import urllib.request
import webbrowser


# ---------------- SITE SELECT / URL GUARD ----------------
SITE_OPTIONS = {
    "abb": {
        "label": "아바 접속",
        "url": "https://abb222.com",
        "allow": ["abb222.com", "abb", "damyto.biz", "vistanfit.net"],
    },
    "crown": {
        "label": "크라운 접속",
        "url": "https://cro-365.com",
        "allow": ["cro-365.com", "crown365.com", "crown", "cro-365", "cro365", "damyto.biz", "vistanfit.net"],
    },
    "sinseon": {
        "label": "신선 접속",
        "url": "https://신선1.com",
        "allow": ["신선1.com", "xn--9t4b11yi5a.com", "sinseon1.com", "sinseon", "신선", "damyto.biz", "vistanfit.net"],
    },
}
ALWAYS_ALLOWED_URL_KEYWORDS = []
ALWAYS_ALLOWED_TITLE_KEYWORDS = ["anydesk"]
ALLOWED_GAME_KEYWORDS = ["evolution", "evo-games", "evo games", "pragmatic", "pragmaticplay"]
EXTRA_SAFE_PREFIXES = ["about:", "chrome:", "chrome-extension:", "data:", "blob:", "devtools:"]
BANNED_URL_KEYWORDS = ["google.", "naver.", "daum.", "youtube.", "youtu.be", "facebook.", "instagram.", "x.com", "twitter.", "tiktok.", "discord."]
SELECTED_SITE_KEY = None
SELECTED_SITE_INFO = None
CHROME_DEBUG_PORT = 9222
CHROME_PROFILE_DIR = Path(tempfile.gettempdir()) / "alice_selected_site_profile"
SELECTED_PLAN_LABEL = ""
SELECTED_PLAN_CODE = ""
SELECTED_PLAN_DAYS = None
_SITE_WINDOW_OPENED = False
SITE_GUARD_GRACE_SECONDS = 5.0
SITE_GUARD_STARTED_AT = 0.0


def _find_chrome_exe() -> str | None:
    candidates = [
        Path(os.environ.get("ProgramFiles", "")) / "Google/Chrome/Application/chrome.exe",
        Path(os.environ.get("ProgramFiles(x86)", "")) / "Google/Chrome/Application/chrome.exe",
        Path(os.environ.get("LocalAppData", "")) / "Google/Chrome/Application/chrome.exe",
    ]
    for c in candidates:
        if str(c) and c.exists():
            return str(c)
    return None


def _launch_selected_site_in_debug_chrome(url: str) -> bool:
    chrome = _find_chrome_exe()
    try:
        os.system("taskkill /f /im chrome.exe >nul 2>&1")
        time.sleep(0.8)
    except Exception:
        pass
    try:
        CHROME_PROFILE_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    if chrome:
        try:
            subprocess.Popen(
                [
                    chrome,
                    f"--remote-debugging-port={CHROME_DEBUG_PORT}",
                    f"--user-data-dir={CHROME_PROFILE_DIR}",
                    "--new-window",
                    "--no-first-run",
                    "--disable-sync",
                    url,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
        except Exception:
            pass
    try:
        webbrowser.open(url)
        return False
    except Exception:
        return False


def _show_site_ready_popup() -> None:
    messagebox.showinfo(
        "안내",
        "키 발급 완료"
    )


def _show_site_choice_dialog() -> dict | None:
    result = {"key": None, "info": None}
    top = tk.Toplevel()
    top.title("사이트 선택")
    top.configure(bg="white")
    top.resizable(False, False)
    top.attributes("-topmost", True)
    top.grab_set()

    tk.Label(top, text="사이트를 선택하세요", bg="white", fg="black", font=("맑은 고딕", 12, "bold")).pack(padx=18, pady=(16, 12))

    def choose(site_key: str):
        if result["key"] is not None:
            return
        result["key"] = site_key
        result["info"] = SITE_OPTIONS[site_key]
        top.destroy()

    wrap = tk.Frame(top, bg="white")
    wrap.pack(fill="x", padx=18, pady=(0, 16))
    tk.Button(wrap, text="아바 접속", width=22, height=2, font=("맑은 고딕", 11, "bold"), command=lambda: choose("abb")).pack(pady=(0, 8))
    tk.Button(wrap, text="크라운 접속", width=22, height=2, font=("맑은 고딕", 11, "bold"), command=lambda: choose("crown")).pack(pady=(0, 8))
    tk.Button(wrap, text="신선 접속", width=22, height=2, font=("맑은 고딕", 11, "bold"), command=lambda: choose("sinseon")).pack()
    top.wait_window()
    return result if result["key"] else None


def _prepare_site_session() -> bool:
    global SELECTED_SITE_KEY, SELECTED_SITE_INFO, SITE_GUARD_STARTED_AT
    root = tk.Tk()
    root.withdraw()
    _show_site_ready_popup()
    sel = _show_site_choice_dialog()
    if not sel:
        root.destroy()
        return False
    SELECTED_SITE_KEY = sel["key"]
    SELECTED_SITE_INFO = sel["info"]
    SITE_GUARD_STARTED_AT = time.time()
    _launch_selected_site_in_debug_chrome(SELECTED_SITE_INFO["url"])
    root.destroy()
    return True


def _fetch_debug_tabs() -> list[dict]:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{CHROME_DEBUG_PORT}/json", timeout=1.5) as r:
            data = json.loads(r.read().decode("utf-8", "ignore"))
            return data if isinstance(data, list) else []
    except Exception:
        return []

def _has_external_chrome_process() -> bool:
    """전용 프로필이 아닌 별도 브라우저 프로세스만 감지한다."""
    try:
        cmd = (
            "Get-CimInstance Win32_Process | "
            "Where-Object {$_.Name -eq 'chrome.exe'} | "
            "Select-Object -ExpandProperty CommandLine"
        )
        raw = subprocess.check_output(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd],
            stderr=subprocess.DEVNULL,
            timeout=3,
        )
        try:
            out = raw.decode("cp949", errors="ignore")
        except Exception:
            out = raw.decode("utf-8", errors="ignore")
        profile_hint = str(CHROME_PROFILE_DIR).lower()
        port_hint = f"--remote-debugging-port={CHROME_DEBUG_PORT}".lower()
        for line in out.splitlines():
            ln = (line or "").strip().lower()
            if not ln or "chrome.exe" not in ln:
                continue
            if profile_hint and profile_hint in ln:
                continue
            if port_hint in ln:
                continue
            # 크롬 내부 유틸리티/렌더러/크래시핸들러는 제외
            if "--type=" in ln:
                continue
            if "crashpad" in ln or "notification-helper" in ln:
                continue
            return True
    except Exception:
        return False
    return False



def _guard_should_block_from_tabs(tabs: list[dict]) -> tuple[bool, str]:
    if not SELECTED_SITE_INFO:
        return False, ""
    try:
        if SITE_GUARD_STARTED_AT and (time.time() - SITE_GUARD_STARTED_AT) < SITE_GUARD_GRACE_SECONDS:
            return False, ""
    except Exception:
        pass
    if _has_external_chrome_process():
        return True, "external chrome detected"
    allow_keywords = [k.lower() for k in SELECTED_SITE_INFO.get("allow", [])] + ALWAYS_ALLOWED_URL_KEYWORDS + ALLOWED_GAME_KEYWORDS
    for tab in tabs:
        url = str(tab.get("url", "")).lower()
        title = str(tab.get("title", "")).lower()
        combo = f"{url} {title}".strip()
        if not combo:
            continue
        if any(url.startswith(prefix) for prefix in EXTRA_SAFE_PREFIXES):
            continue
        if "newtab" in combo or "새 탭" in combo:
            continue
        if any(k in combo for k in ALWAYS_ALLOWED_TITLE_KEYWORDS):
            continue
        if any(k in combo for k in allow_keywords):
            continue
        if any(k in combo for k in BANNED_URL_KEYWORDS):
            return True, combo
        if url.startswith("http://") or url.startswith("https://"):
            return True, combo
    return False, ""

# ---------------- UI constants ----------------
APP_TITLE = "AI Engine Alice V70"
C_BG   = "#1a1a1d"
C_PANEL= "#232931"
C_TXT  = "#f2f2f2"
C_BLUE = "#4AA3F0"
C_RED  = "#F85C50"
C_TIE  = "#00FF88"
C_TIE_NUM = "#FFD54A"  # 타이 연속 표시 숫자
C_PPAIR= "#3399FF"
C_BPAIR= "#FF4444"
C_FRAMEB="#3a4a5e"
C_CELL="#242b33"
C_CELL_O="#3d4f5c"

C_MAIN_P = "#0077FF"  # P 글자색
C_MAIN_B = "#CC0000"  # B 글자색

MAX_COLS = 25
OX_ROWS  = 4  # ✅ 4매 고정
BON_ROWS = 6  # ✅ 본매는 6매
BON_MAX_COLS = 80  # 본매 내부 최대 열(렌더링은 화면에 맞게 잘라서 표시)
MAIN_OX_MAX_COLS = 60
GRID_COLS_DEFAULT = 5
# 반반화면/작은창 대응용 반응형 컬럼 기준(캔버스 폭 기준)
GRID_BP_3COL = 1200  # 이보다 작으면 3열
GRID_BP_2COL = 860   # 이보다 작으면 2열
 # ✅ 한 줄에 5개(가독성)

BASE_DIR = Path(sys.argv[0]).resolve().parent
DB_DIR = BASE_DIR / "DB"
DB_DIR.mkdir(exist_ok=True)

# ---------------- Pattern helpers ----------------
def build_patterns_64() -> list[str]:
    pats: list[str] = []
    # 0 -> P, 1 -> B
    for i in range(64):
        b = format(i, "06b")
        pat = "".join("P" if c == "0" else "B" for c in b)
        pats.append(pat)
    return pats


def build_patterns_16() -> list[str]:
    """16개(4칸) 패턴: 4비트(0~15) -> P/B로 매핑.
    - 0은 P, 1은 B
    - 예: 0000=PPPP, 1010=BPBP
    """
    pats = []
    for i in range(16):
        bits = format(i, "04b")
        pat = "".join("B" if b == "1" else "P" for b in bits)
        pats.append(pat)
    return pats
def pretty_side(ch: str) -> str:
    # 사용자 용어(풀/뱅)
    if ch == "P":
        return "플레이어(풀)"
    if ch == "B":
        return "뱅커(뱅)"
    return "-"

def side_color(ch: str) -> str:
    return C_MAIN_P if ch == "P" else C_MAIN_B if ch == "B" else C_TXT


def pretty_pat(pat: str) -> str:
    """패턴 문자열(P/B)을 사용자 표기(플/뱅)로 변환."""
    if not pat:
        return ""
    return "".join("플" if ch == "P" else "뱅" if ch == "B" else "-" for ch in pat)

# ---------------- App ----------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self._site_guard_running = True
        self.title(APP_TITLE)
        self.geometry("1600x900")
        self.configure(bg=C_BG)

        # --- state ---
        self.hist: list[str] = []  # "P","B","TIE","P_PAIR","B_PAIR"
        self._judging = False  # 중복 판정(재진입) 방지


        # ---- 패턴 풀 ----
        self.pats64 = build_patterns_64()
        self.pats16 = build_patterns_16()

        # 16패턴 전용 고정
        self.mode = 16
        self.active_pool: list[str] = self.pats16
        self.pat_len = 4
        self.active_board_n = 16

        # 현재 모드에서 운영되는 보드 ID들 (1..N)
        self.cycle_pos = 0  # ✅ 사이클 내 현재 판 인덱스(0-based)
        self.board_ids: list[int] = list(range(1, self.active_board_n + 1))


        # 보드 상태(1~64): 각 보드는 현재 패턴(pat)을 들고 있고, 결과(O/X)에 따라 랜덤 스왑 로테이션
        self.pstate: dict[int, dict] = {
            bid: {"pat": "", "step": 0, "ox": [], "cycle_ox": [], "win": 0, "lose": 0}
            for bid in self.board_ids
        }

        # 초기 패턴 할당(겹침 없이 랜덤)
        self._assign_initial_patterns(reset_steps=True, reset_cycle=True)

        # UNDO 스택(입력 1회당)
        # entry = {"hist_tok": str, "deltas": list[(pat, prev_step, appended, prev_win, prev_lose)]}
        self.undo_stack: list[dict] = []
        self._undo_snap_enabled = True  # UNDO는 전체 스냅샷 복원 방식

        # --- main panel state (본매/메인OX/메인추천) ---
        self.bon_occ: dict[tuple[int,int], str] = {}  # (col,row)->'P'/'B'
        self.bon_points: list[tuple[int,int,str]] = []
        self.bon_flags: list[dict] = []  # 각 본매 점의 타이/페어 플래그
        self.bon_cur_side: str|None = None
        self.bon_col = 0
        self.bon_row = 0
        self.bon_run_start_col = 0

        self.main_ox: list[str] = []  # 'O'/'X' only for P/B when recommendation exists
        self.main_flags: list[dict] = []  # 메인 OX 칸의 타이/페어 플래그(표시용)
        self.main_win = 0
        self.main_lose = 0
        self.reco_bid: int | None = None
        self.reco_side: str | None = None
        self.reco_from_no: int | None = None
        self.reco_side: str|None = None
        self.reco_from_no: int|None = None
        self.last_event_lbl = None


        # --- support panel state (서포트OX/서포트추천) ---
        self.support_ox: list[str] = []
        self.support_flags: list[dict] = []
        self.support_win = 0
        self.support_lose = 0
        self.support_reco_bid: int | None = None
        self.support_reco_side: str | None = None

        # --- support reco lock (MAIN_OX last4 state match) ---
        self.support_lock_bid: int|None = None
        self.support_lock_pat: str = ""
        self.support_lock_idx: int = 0
        self.support_lock_remain: int = 0

        # --- main reco lock (X4 column trigger) ---
        # 세로로 X가 4개(한 컬럼 완성) 발생한 보드의 패턴을 4회 고정 추천
        self.main_lock_bid: int|None = None
        self.main_lock_pat: str = ""
        self.main_lock_idx: int = 0  # 다음 추천에 사용할 패턴 인덱스
        self.main_lock_remain: int = 0  # 남은 추천 횟수(최대 4)


        # --- UI ---
        self._build_header()
        self._build_topbar()
        self._build_main_panel()
        self._build_pattern_area()
        # 현재 그리드 열 수(반응형)
        self.grid_cols = GRID_COLS_DEFAULT
        self._build_pattern_cards()

        # 첫 렌더
        self._refresh_all()
        self.after(1200, self._start_site_guard)


    def _start_site_guard(self):
        def loop():
            violation_count = 0
            last_reason = ""
            while getattr(self, "_site_guard_running", False):
                blocked, info = _guard_should_block_from_tabs(_fetch_debug_tabs())
                reason = (info or "").strip()
                if blocked:
                    if reason and reason == last_reason:
                        violation_count += 1
                    else:
                        violation_count = 1
                        last_reason = reason
                    if violation_count >= 3:
                        try:
                            self.after(0, lambda: messagebox.showerror("차단", "허용되지 않은 사이트가 감지되어 프로그램을 종료합니다."))
                        except Exception:
                            pass
                        try:
                            self.after(0, self.destroy)
                        except Exception:
                            pass
                        break
                else:
                    violation_count = 0
                    last_reason = ""
                time.sleep(1.0)
        threading = __import__('threading')
        threading.Thread(target=loop, daemon=True).start()


    def destroy(self):
        self._site_guard_running = False
        super().destroy()


    def _start_site_guard(self):
        def loop():
            violation_count = 0
            last_reason = ""
            while getattr(self, "_site_guard_running", False):
                blocked, info = _guard_should_block_from_tabs(_fetch_debug_tabs())
                reason = (info or "").strip()
                if blocked:
                    if reason and reason == last_reason:
                        violation_count += 1
                    else:
                        violation_count = 1
                        last_reason = reason
                    if violation_count >= 3:
                        try:
                            self.after(0, lambda: messagebox.showerror("차단", "허용되지 않은 사이트가 감지되어 프로그램을 종료합니다."))
                        except Exception:
                            pass
                        try:
                            self.after(0, self.destroy)
                        except Exception:
                            pass
                        break
                else:
                    violation_count = 0
                    last_reason = ""
                time.sleep(1.0)
        threading = __import__('threading')
        threading.Thread(target=loop, daemon=True).start()

    # ---------- UI blocks ----------
    def _build_header(self):
        h = tk.Frame(self, bg=C_BG, height=48)
        h.pack(side="top", fill="x")
        h.pack_propagate(False)
        tk.Label(
            h,
            text=APP_TITLE,
            fg="#8ec6ff",
            bg=C_BG,
            font=("HY중고딕", 22, "bold"),
        ).pack(pady=(6, 2))

    def _load_topbar_icon(self, key: str):
        """내장 base64 아이콘 사용. 외부 파일 없이 바로 표시."""
        if not hasattr(self, "_topbar_icons"):
            self._topbar_icons = {}
        if key in self._topbar_icons:
            return self._topbar_icons[key]

        import base64 as _b64

        EMBEDDED = {
            "player": """iVBORw0KGgoAAAANSUhEUgAAABwAAAAcCAYAAAByDd+UAAABIUlEQVR4nGNgoDNgxCaoduzWf2oYfstKDcN8JlpZhsssJkIKqG0pEy4JWlnKRGvL0C3FiENag1ELh76FLMQqnKspzWAjwAXn/2NgYHj16w/DpS8/GCY9fstw+9svoswh2Ycf/vxlUD9+m8H41F2G05++M7gJ8TCs1pVjUOJko42FMPDt7z+G6U/eMTAwMDBwMjEyhIvz09ZCBgYGhpe//sDZEmzExQ5FFoojWfICyXKaWMjJxMSQKSPEwMDAwPD933+GlS8/EqWP6FQKAwIszAw3LVUZ/jNAUunud18YJj5+y3DvO3GplGQLP/z5y2B++h6p2uBgtKSBg+TrT6li4cAEKbbWFbUBzA4mdAFaWoZiIa0sRTcTIw6paSk9ooogAADOZGHnr9uNJQAAAABJRU5ErkJggg==""",
            "banker": """iVBORw0KGgoAAAANSUhEUgAAABwAAAAcCAYAAAByDd+UAAABSUlEQVR4nO2WzUrDQBSFvxkTxdCC7vURCu0L6F5cKCoouBffQYqIL6IiulAUf96hq6KbLqpddm1LGmJj0nFRbTVNaSKZiuCBbO7MPd9NThgGxiwRVXxZW1FpmM9eXg/4S12wYV5y1Ia0oXLYgi6o1A0LQwcy1K1/4N8HGnE3ZvaKGPlCv9DpoJwWQa2Ge35G8PwUyyfxGyrbprG+SnN7C79SwcgXyBT3EdOWHmAP7Hm8lcsACMtiYn5OL1CYJmah+4mVbRPU67H6YmfYA2WzzFxc9QtK4Z6eoBwnVv+PM2xsbuAeH4EQWDu7GLmcHmBPvk/77gaCAIRgcmFRMxBAiO7zMUAcJc6w32kwtbQMUoJSeKWSHuDXn0a1X/GrVbz7W/zHh3SBrcODpLNF6ncO76jbVdr6ZMhwQSfsG1AXNOw5kGGa0HFENVLv9NR223Y0u1UAAAAASUVORK5CYII=""",
            "tie": """iVBORw0KGgoAAAANSUhEUgAAABwAAAAcCAYAAAByDd+UAAAAqklEQVR4nGNgoDNgxCaYtjvrPzUMn+U6DcN8JlpZhsssJkIKqG0pEy4JWlnKRGvL0C3FiENag1ELh76FLMQomuDQw8DJwolXzfo7Gxl2PNhFHQsLDpTA2SGqQQyu8s4MDAwMDKWHKhk+/fpEjBFwMPzjcNTCUQsHv4VEZXxksOb2OoY1t9eRbeHABCm21hW1AcwOJnQBWlqGYiGtLEU3EyMOqWkpPaKKIAAAkyo2SKKHZoQAAAAASUVORK5CYII=""",
            "ppair": """iVBORw0KGgoAAAANSUhEUgAAABwAAAAcCAYAAAByDd+UAAAA+ElEQVR4nO2WMQ/BQBiG354mSIjJbjDaDSJ+gsQPaP+bmInRKGLobrRIDIKFVLhonYEm9K69XtLrQJ/x3rvvae9LvxTIGEO02F9cWRrFp90yV5/okkXVIrINaUtJVKBLSnTLwlKuh7rJhblQGTMuHHdKIO/h5DPgQBlmOx+TrZcoF5HoDS2HwnYoLh6D3TDRqxeUcmUhALgew+r0AAA0q/zMl+XKwoppoFV7bV+7/GCS5QGxPQwYtovwGXCkDKONh/neV8qVhZZDcb5HP7Us/+TPv8PB8hZ7WJaL+P0rJYD47yptAgcJL+iUfQl1ScM1uR6mKc2iVVKedYiAXNuGdCMAAAAASUVORK5CYII=""",
            "bpair": """iVBORw0KGgoAAAANSUhEUgAAABwAAAAcCAYAAAByDd+UAAABPklEQVR4nO2WvUrDUBiGn5wqdKmIbro4CJ108AqkizgIXkAQ8Tq8G51FcNAiHOoVOLiJIFKrg39QLa2p6XFIQ0hO/iQ5HaTv9HHec77n5HtDCExYVtyiOt9RpTTfPtP6C1OwpF4ia0PZUJFkmIIK07AoVMvQtKbAKfDPmkl1t07BGt9p5MDgDdpNuD/RfeVC/wXaF4Efo3xPKG1oHUClCvV9qK3ovtyDn57nL20WBAJY42EoBaOh7g8/4f3Gq+dWE9ukj9RX4zioOxJ6HX3PbA0W1ry6e1cQKG1wHdg4hOUGvF7D81X4Qn6Gt0fw1CoIBHAH3sgW12G+HgZKG5xurjb5M6xUg5F9PeQ+FlX+DJUL3x/eK/94aQjY3E0/neXH6P9/2gTE/12VLZ8hogsmYSGgKWi0p5ZhmdBJRJWpX3rkbwtiTxGTAAAAAElFTkSuQmCC""",
            "undo": """iVBORw0KGgoAAAANSUhEUgAAABwAAAAcCAYAAAByDd+UAAABcElEQVR4nO2WS0sCURiGH0cdNW+MaVkmJWSEXRYhtCgI+gX91JatWmUELYwoBizMzDLMRNOKnAlbJeRtppwRot7ld77zPnznPQcOjFiWXsXd/VTLCPOd7Y0uf8EsWD8vQavBaKjQb8EsqGA2rBPalaHZ+gf+fqDtJ5umggEkvxdaLcrVJ0qVqjlAh2gnmVggKPnbtfgsFMsV0vIliqoaC1xfWUTyebnI35IvlrBYLMQiYWKRMEIiztGpPDzQZrXidIi4HCKSz0u2UOSu9Ejj5RWA00wWu83KzGQIv8dNrfE80E/z0izNz7G5tkw0PAGA0yGylVwl4Pe2e27uH3hrKnjGXFp22hPK2Wskn4doOATAdGicTK5ApVZv95QqVfZSx5ow0DFhU1E5PDlvH1UmV0C+yusy7yVdl6apqBykz3C7nNTqgzPSku6Hr6rvQ8O+BTRKfwTY63dltD4ZQmfBTNgXoFnQTs+uDI2EjiIqTX0ArFJ+01u/ZAsAAAAASUVORK5CYII=""",
            "reset": """iVBORw0KGgoAAAANSUhEUgAAABwAAAAcCAYAAAByDd+UAAABh0lEQVR4nO2Wy07CUBCG/56WUgooQYIgRIKIrkyMGxfu9AV8VJ/AlSbsjERBEwVviSKXcmLLndaNNCkFqeQUY+K/m+nM/6WdSc8BFixuUvLk9NxgYX58eGDzJ27BpnmRWQWsoWTaA7egxG3YONQ2Q7f1D/z7QGHexmg4hHQiZsZU1XBTfmYHFD0Cev2BGWdTSURCS9ANAzWFgnDOPpajKp/kxdH+HmKRsN2A4/Baa6BQemQHzCTjED0CdF235Ct1Ba1OF1uppCOYY2AoGECvP8B7o2nm1FYbVNVQqSvweUVIosgOqBsGCLGeNJe39yiWnsAT8lWjT2qdD1hVmhB43rKVACBLEtaiK6CqZlmo7+RoS8svb0jFV7GT3UDQL6PWpJAlLzbXE+AJj+u7B0cwx8DBcIiziyvsbmeQTsTMN213e8jlC6gqlC0QADrdHnL5IpYDfvhlCf3+AHX6YdtcZsCRqKqBqtpP20z9zs970u2KtUYMMp5wE2YBugUd97TNkCV0EaOaqU+GgpKGOmNNLgAAAABJRU5ErkJggg==""",
        }

        img = None
        try:
            data = EMBEDDED.get(key)
            if data:
                raw = tk.PhotoImage(data=_b64.b64decode(data))
                # 안전하게 24~28px 수준 유지
                w = max(1, raw.width())
                h = max(1, raw.height())
                sx = max(1, w // 24)
                sy = max(1, h // 24)
                img = raw.subsample(sx, sy)
        except Exception:
            img = None

        self._topbar_icons[key] = img
        return img

    
    def _build_topbar(self):
        top = tk.Frame(self, bg=C_BG, height=78)
        top.pack(side="top", fill="x")
        top.pack_propagate(False)

        # 7개 버튼을 균등 재정렬 (학습저장 제거)
        for i in range(7):
            top.grid_columnconfigure(i, weight=1, uniform="topbtn")

        def btn(col, txt, color, cb, icon_key=None):
            img = self._load_topbar_icon(icon_key) if icon_key else None
            b = tk.Button(
                top,
                text=txt,
                image=img if img is not None else None,
                compound="left" if img is not None else None,
                bg=color,
                fg="white",
                activebackground=color,
                activeforeground="white",
                font=("맑은 고딕", 10, "bold"),
                relief="flat",
                bd=0,
                cursor="hand2",
                padx=6,
                pady=6,
                command=cb
            )
            # 아이콘 참조 유지
            b._img_ref = img
            b.grid(row=0, column=col, padx=5, pady=8, sticky="we")
            return b

        btn(0, "PLAYER", C_BLUE,  lambda: self.play("P"),      "player")
        btn(1, "BANKER", C_RED,   lambda: self.play("B"),      "banker")
        btn(2, "TIE",    C_TIE,   lambda: self.play("TIE"),    "tie")
        btn(3, "P-PAIR", C_PPAIR, lambda: self.play("P_PAIR"), "ppair")
        btn(4, "B-PAIR", C_BPAIR, lambda: self.play("B_PAIR"), "bpair")
        btn(5, "UNDO",   "#777b83", self.undo,                 "undo")
        btn(6, "RESET",  "#555960", self.reset,                "reset")


    # ---------- Pattern rotation / mode ----------
    def _recalc_in_use(self) -> None:
        return

    def _choose_new_pattern(self, old_pat: str) -> str:
        # (구버전 호환) 활성 보드 수 == 패턴 수인 경우 '미사용'이 없어도 되므로, 기본은 old_pat 반환
        return old_pat
        return random.choice(available)


    def _swap_pattern_for_board(self, bid: int) -> None:
        """패턴 겹침(중복) 없이 '교체' 효과를 내기 위한 스왑.
        원칙:
        - 패턴 교체가 필요한 보드(bid)만 '교체'되었다고 간주 (step은 0으로 리셋)
        - 진행 중인 보드(step>0)를 다른 보드 이벤트로 흔들지 않기 위해,
          스왑 파트너는 가능한 한 '대기(step==0)' 보드에서만 선택한다.
        - 대기 보드가 전혀 없을 때만(매우 드문 케이스) 임의 보드와 스왑하되,
          그 경우에도 파트너의 step은 그대로 유지한다.
        """
        import random as _random

        active_bids = list(self.board_ids[: self.active_board_n])
        if bid not in active_bids or len(active_bids) <= 1:
            return

        st_me = self.pstate.get(bid)
        if not st_me:
            return

        # 파트너 후보: 대기(step==0) 보드 우선
        idle = []
        for x in active_bids:
            if x == bid:
                continue
            stx = self.pstate.get(x)
            if not stx:
                continue
            if int(stx.get("step", 0) or 0) == 0:
                idle.append(x)

        if idle:
            other = _random.choice(idle)
        else:
            other = _random.choice([x for x in active_bids if x != bid])

        st_ot = self.pstate.get(other)
        if not st_ot:
            return

        # 패턴만 스왑 (OX/승패는 유지). 단, 파트너가 진행 중(step>0)이면
        # 패턴이 바뀌면서 판정이 뒤집히는 혼선을 막기 위해 파트너 step을 0으로 리셋한다.
        # (요구사항: "틀리면 끝까지 간다"를 우선 보장)
        if int(st_ot.get("step", 0) or 0) != 0:
            st_ot["step"] = 0
        p1 = st_me.get("pat", "")
        p2 = st_ot.get("pat", "")
        st_me["pat"], st_ot["pat"] = p2, p1
    def set_mode(self, mode: int) -> None:
        # 16패턴 전용 고정
        mode = 16

        # UNDO 가능하도록 스냅샷
        self._push_undo_snapshot()

        self.mode = 16
        self.active_pool = list(self.pats16)
        self.active_board_n = 16
        self.pat_len = 4

        self.board_ids = list(range(1, self.active_board_n + 1))
        self._assign_initial_patterns(reset_steps=True, reset_cycle=True)
        self._reflow_cards()
        self._refresh_all()


    def _assign_initial_patterns(self, reset_steps: bool = True, reset_cycle: bool = True) -> None:
        """활성 모드(64/16)에 맞춰 패턴을 **겹침 없이** 랜덤 배정한다.
        - ✅ 사이클(16=4판 / 64=6판) 시작 시 호출
        - ✅ 사이클 중간에는 절대 교체하지 않음(동시 시작/동시 종료 보장)
        """
        import random as _random

        pool = list(self.active_pool)
        _random.shuffle(pool)

        active_bids = list(self.board_ids[: self.active_board_n])
        for i, bid in enumerate(active_bids):
            st = self.pstate[bid]
            st["pat"] = pool[i]
            if reset_steps:
                st["step"] = 0  # (구버전 호환 필드, 사이클 운영에서는 사용하지 않음)
            if reset_cycle:
                st["cycle_ox"] = []  # ✅ 현재 사이클 OX(추천/분포 계산용)

        if reset_cycle:
            self.cycle_pos = 0  # ✅ 사이클 판 인덱스 리셋

        # 비활성 보드는 그대로 둔다(16모드일 때 17~64)

    def _build_main_panel(self):
        # 버튼 아래: 메인 추천 + 본매(6매) + 메인 OX(4매)
        self.main_panel = tk.Frame(self, bg=C_BG)
        self.main_panel.pack(side="top", fill="x")

        # 추천 라인 (메인/서포트 2줄)
        rec_line = tk.Frame(self.main_panel, bg=C_BG, height=64)
        rec_line.pack(side="top", fill="x", pady=(0, 4))
        rec_line.pack_propagate(False)

        center_box = tk.Frame(rec_line, bg=C_BG)
        center_box.place(relx=0.5, rely=0.5, anchor="center")

        self.main_rec_lbl = tk.Label(
            center_box,
            text="서포트 추천: 없음",
            fg=C_TXT,
            bg=C_BG,
            font=("맑은 고딕", 12, "bold"),
            anchor="center",
            justify="center"
        )
        self.main_rec_lbl.pack(anchor="center")

        self.support_rec_lbl = tk.Label(
            center_box,
            text="메인 추천: 없음",
            fg=C_TXT,
            bg=C_BG,
            font=("맑은 고딕", 14, "bold"),
            anchor="center",
            justify="center"
        )
        self.support_rec_lbl.pack(anchor="center")

        self.event_lbl = tk.Label(
            rec_line,
            text="",
            fg="#cbd5e1",
            bg=C_BG,
            font=("맑은 고딕", 11, "bold"),
            anchor="e"
        )
        self.event_lbl.place(relx=0.98, rely=0.5, anchor="e")
        self.last_event_lbl = self.event_lbl

        # 본매 + 메인 OX 영역 (폭에 따라 가로/세로 재배치)
        self.boards_wrap = tk.Frame(self.main_panel, bg=C_BG)
        self.boards_wrap.pack(side="top", fill="x", padx=10, pady=(0, 6))

        self.bon_card = tk.Frame(self.boards_wrap, bg=C_PANEL, bd=1, relief="solid")
        self.ox_card  = tk.Frame(self.boards_wrap, bg=C_PANEL, bd=1, relief="solid")

        # 제목
        tk.Label(self.bon_card, text="본매", fg="#9ae6b4", bg=C_PANEL,
                 font=("맑은 고딕", 12, "bold")).pack(anchor="w", padx=8, pady=(6, 2))
        self.bon_cv = tk.Canvas(self.bon_card, bg=C_PANEL, highlightthickness=0, height=120)
        self.bon_cv.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        self.mainox_title = tk.Label(self.ox_card, text="서포트 OX 보드", fg="#fbbf24", bg=C_PANEL,
                                     font=("맑은 고딕", 12, "bold"))
        self.mainox_title.pack(anchor="w", padx=8, pady=(6, 2))
        self.mainox_cv = tk.Canvas(self.ox_card, bg=C_PANEL, highlightthickness=0, height=58)
        self.mainox_cv.pack(fill="both", expand=False, padx=8, pady=(0, 6))

        self.supportox_title = tk.Label(self.ox_card, text="메인 OX 보드", fg="#93c5fd", bg=C_PANEL,
                                        font=("맑은 고딕", 12, "bold"))
        self.supportox_title.pack(anchor="w", padx=8, pady=(0, 2))
        self.supportox_cv = tk.Canvas(self.ox_card, bg=C_PANEL, highlightthickness=0, height=58)
        self.supportox_cv.pack(fill="both", expand=True, padx=8, pady=(0, 8))



        # 초기 배치
        self._reflow_top_boards(self.winfo_width())

        def _on_wrap_cfg(evt):
            self._reflow_top_boards(evt.width)

        self.boards_wrap.bind("<Configure>", _on_wrap_cfg)

    def _reflow_top_boards(self, width: int):
        # 반반 화면에서도 보드가 사라지지 않게: 폭이 좁으면 세로 스택
        for w in (self.bon_card, self.ox_card):
            w.pack_forget()
        if width < 950:
            self.bon_card.pack(side="top", fill="x", padx=0, pady=(0, 6))
            self.ox_card.pack(side="top", fill="x", padx=0, pady=(0, 0))
        else:
            self.bon_card.pack(side="left", fill="x", expand=True, padx=(0, 6))
            self.ox_card.pack(side="left", fill="x", expand=True, padx=(6, 0))

    def _build_pattern_area(self):
        # 스크롤 영역(고밀도)
        self.pattern_frame = tk.Frame(self, bg=C_BG)
        self.pattern_frame.pack(side="top", fill="both", expand=True)

        self.canvas = tk.Canvas(self.pattern_frame, bg=C_BG, highlightthickness=0)
        self.vscroll = tk.Scrollbar(self.pattern_frame, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.vscroll.set)

        self.vscroll.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)

        self.inner = tk.Frame(self.canvas, bg=C_BG)
        self.inner_id = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")

        def on_configure(_evt=None):
            self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        self.inner.bind("<Configure>", on_configure)

        def on_canvas_configure(evt):
            # inner 폭을 canvas 폭에 맞추기
            self.canvas.itemconfigure(self.inner_id, width=evt.width)
            # 반응형 재배치(폭 변동)
            self._schedule_reflow(evt.width)
        self.canvas.bind("<Configure>", on_canvas_configure)

        # 마우스 휠 스크롤
        def _on_mousewheel(event):
            delta = -1 * int(event.delta / 120)
            self.canvas.yview_scroll(delta, "units")
        self.canvas.bind_all("<MouseWheel>", _on_mousewheel)

    def _build_pattern_cards(self):
        # 최초는 기본 열수로 구성(이후 창 폭에 따라 자동 재배치)
        for c in range(GRID_COLS_DEFAULT):
            self.inner.grid_columnconfigure(c, weight=1)

        for bid in self.board_ids:
            card = tk.Frame(self.inner, bg=C_PANEL, bd=1, relief="solid")

            # 상단: 랭킹+패턴(색상 표시) + 단계표시
            top = tk.Frame(card, bg=C_PANEL)
            top.pack(fill="x", padx=6, pady=(6, 2))


            pat_cv = tk.Canvas(top, bg=C_PANEL, highlightthickness=0, height=18)

            rank_lbl = tk.Label(top, text="", fg=C_TXT, bg=C_PANEL, font=("맑은 고딕", 9, "bold"))
            step_lbl = tk.Label(top, text=f"(1/{self.pat_len})", fg=C_TXT, bg=C_PANEL, font=("맑은 고딕", 9, "bold"))

            step_lbl.pack(side="right")
            pat_cv.pack(side="left", fill="x", expand=True)

            # 체크 시트(6칸 격자)
            grid_cv = tk.Canvas(card, bg=C_PANEL, highlightthickness=0, height=26)
            grid_cv.pack(fill="x", padx=6, pady=(0, 2))

            # 현재 추천(색상 적용)
            rec_lbl = tk.Label(card, text="추천: -", fg=C_TXT, bg=C_PANEL, font=("맑은 고딕", 9, "bold"))
            rec_lbl.pack(anchor="w", padx=6, pady=(0, 2))

            # OX 보드(4매)
            ox_cv = tk.Canvas(card, bg=C_PANEL, highlightthickness=0, height=70)
            ox_cv.pack(fill="x", padx=6, pady=(0, 2))

            # 승/패/승률
            stat_lbl = tk.Label(card, text="승 0 / 패 0 (0.0%)", fg=C_TXT, bg=C_PANEL, font=("맑은 고딕", 9, "bold"))
            stat_lbl.pack(anchor="e", padx=6, pady=(0, 6))

            self.pstate[bid]["widgets"] = {
                "card": card,
                "pat_cv": pat_cv,
                "step_lbl": step_lbl,
                 "rank_lbl": rank_lbl,
                "grid_cv": grid_cv,
                "rec_lbl": rec_lbl,
                "ox_cv": ox_cv,
                "stat_lbl": stat_lbl,
            }

        # 최초 배치(이후 폭 변동 시 자동 재배치)
        self._last_canvas_w = self.canvas.winfo_width() or 1600
        self._grid_ready = False
        self._reflow_cards()

    
    # ---------- Responsive grid ----------
    def _compute_cols(self, canvas_width: int) -> int:
        """캔버스 폭 기준으로 카드 열 수를 결정."""
        try:
            w = int(canvas_width)
        except Exception:
            w = 1600
        if w < GRID_BP_2COL:
            return 2
        if w < GRID_BP_3COL:
            return 3
        return GRID_COLS_DEFAULT

    def _schedule_reflow(self, canvas_width: int):
        """폭 변화가 연속으로 올 때 깜빡임/과부하를 막기 위해 디바운스."""
        self._last_canvas_w = int(canvas_width) if canvas_width else 0
        job = getattr(self, "_reflow_job", None)
        if job:
            try:
                self.after_cancel(job)
            except Exception:
                pass
        self._reflow_job = self.after(60, self._reflow_cards)

    def _reflow_cards(self):
        """현재 폭에 맞춰 64개 카드를 재배치(카드 위치 자체는 고정, 재배치만)."""
        w = getattr(self, "_last_canvas_w", 0) or self.canvas.winfo_width() or 1600
        cols = self._compute_cols(w)
        if getattr(self, "grid_cols", GRID_COLS_DEFAULT) == cols and getattr(self, "_grid_ready", False):
            # 컬럼 수 변화 없음: 헤더만 반응형 렌더(겹침 방지)
            self._refresh_all()
            return

        self.grid_cols = cols

        # 컬럼 configure 초기화
        for c in range(0, 10):
            self.inner.grid_columnconfigure(c, weight=0)
        for c in range(cols):
            self.inner.grid_columnconfigure(c, weight=1)

        # 전체 카드 재배치
        visible = self.board_ids[:self.active_board_n]
        # 비활성 카드는 숨김
        for bid in self.board_ids[self.active_board_n:]:
            card = self.pstate.get(bid, {}).get("widgets", {}).get("card")
            if card:
                try:
                    card.grid_remove()
                except Exception:
                    pass

        for idx, bid in enumerate(visible):
            card = self.pstate.get(bid, {}).get("widgets", {}).get("card")
            if not card:
                continue
            card.grid_forget()
            r = idx // cols
            c = idx % cols
            card.grid(row=r, column=c, padx=6, pady=6, sticky="nsew")

        self._grid_ready = True
        # 재배치 후 한 번 더 렌더(헤더/줄바꿈 반영)
        self._refresh_all()

# ---------- Sorting / Layout ----------
    
    def _rate_key(self, bid: int) -> tuple[float, int]:
        st = self.pstate.get(bid, {})
        win = int(st.get("win", 0) or 0)
        lose = int(st.get("lose", 0) or 0)
        total = win + lose
        if total == 0:
            return (-1.0, 0)  # 맨 뒤
        return (win / total, total)

    def _sorted_boards(self) -> list[int]:
        # 승률 높은 순, 그 다음 표본(total) 많은 순
        bids = list(self.board_ids[:self.active_board_n])
        return sorted(
            bids,
            key=lambda b: (self._rate_key(b)[0], self._rate_key(b)[1]),
            reverse=True
        )

    def _rank_map(self) -> dict[int, int]:
        """승률 기준 현재 순위만 계산(카드 위치는 고정)."""
        ordered = self._sorted_boards()
        return {bid: idx + 1 for idx, bid in enumerate(ordered)}

    def _regrid_cards(self):
        # (호환용) 카드 재배치 기능은 사용하지 않음. 위치는 항상 고정.
        return
    def _regrid_cards(self):
        # (호환용) 카드 재배치 기능은 사용하지 않음. 위치는 항상 고정.
        return

    # ---------- Logic ----------
    # ---------- UNDO Snapshot ----------
    def _snapshot_state(self) -> dict:
        # 깊은 복사로 전체 상태 저장 (입력 1회 = UNDO 1회)
        return {
            "hist": list(self.hist),
            "mode": int(getattr(self, "mode", 64) or 64),
            "active_board_n": int(getattr(self, "active_board_n", 64) or 64),
            "cycle_pos": int(getattr(self, "cycle_pos", 0) or 0),
            "pstate": {bid: {
                "pat": str(st.get("pat", "")),
                "step": int(st.get("step", 0) or 0),
                "ox": list(st.get("ox", [])),
                "cycle_ox": list(st.get("cycle_ox", [])),
                "win": int(st.get("win", 0) or 0),
                "lose": int(st.get("lose", 0) or 0),
            } for bid, st in self.pstate.items()},
            # 본매(6매)
            "bon_occ": dict(self.bon_occ),
            "bon_points": list(self.bon_points),
            "bon_flags": [dict(f) for f in self.bon_flags],
            "bon_cur_side": self.bon_cur_side,
            "bon_col": int(getattr(self, "bon_col", 0) or 0),
            "bon_row": int(getattr(self, "bon_row", 0) or 0),
            "bon_run_start_col": int(getattr(self, "bon_run_start_col", 0) or 0),
            # 메인 OX(4매)
            "main_ox": list(self.main_ox),
            "main_flags": [dict(f) for f in getattr(self, "main_flags", [])],
            "main_win": int(getattr(self, "main_win", 0) or 0),
            "main_lose": int(getattr(self, "main_lose", 0) or 0),
            # 서포트 OX(4매)
            "support_ox": list(getattr(self, "support_ox", [])),
            "support_flags": [dict(f) for f in getattr(self, "support_flags", [])],
            "support_win": int(getattr(self, "support_win", 0) or 0),
            "support_lose": int(getattr(self, "support_lose", 0) or 0),
            # 서포트 추천
            "support_reco_bid": getattr(self, "support_reco_bid", None),
            "support_reco_side": getattr(self, "support_reco_side", None),
            "support_lock_bid": getattr(self, "support_lock_bid", None),
            "support_lock_pat": getattr(self, "support_lock_pat", ""),
            "support_lock_idx": int(getattr(self, "support_lock_idx", 0) or 0),
            "support_lock_remain": int(getattr(self, "support_lock_remain", 0) or 0),
            # 메인 추천
            "reco_bid": getattr(self, "reco_bid", None),
            "reco_side": getattr(self, "reco_side", None),
            "reco_from_no": getattr(self, "reco_from_no", None),
            # main reco lock
            "main_lock_bid": getattr(self, "main_lock_bid", None),
            "main_lock_pat": getattr(self, "main_lock_pat", ""),
            "main_lock_idx": int(getattr(self, "main_lock_idx", 0) or 0),
            "main_lock_remain": int(getattr(self, "main_lock_remain", 0) or 0),
            # (레거시 변수들 혹시 남아있으면 같이)
            "reco_main": getattr(self, "reco_main", None),
            "reco_board_id": getattr(self, "reco_board_id", None),
            "reco_score": getattr(self, "reco_score", None),
            # 마지막 이벤트 라벨
            "last_event_text": (self.last_event_lbl.cget("text") if getattr(self, "last_event_lbl", None) is not None else ""),
        }

    def _restore_state(self, snap: dict) -> None:
        # hist / pattern states / mode
        self.hist = list(snap.get("hist", []))

        self.mode = 16
        self.active_board_n = 16
        self.active_pool = list(self.pats16)
        self.cycle_pos = int(snap.get("cycle_pos", 0) or 0)

        pst_all = (snap.get("pstate", {}) or {})
        for bid, st in self.pstate.items():
            pst = pst_all.get(bid, {})
            if pst:
                if "pat" in pst and pst["pat"]:
                    st["pat"] = str(pst.get("pat", st.get("pat", "")))
                st["step"] = int(pst.get("step", 0) or 0)
                st["ox"] = list(pst.get("ox", []))
                st["cycle_ox"] = list(pst.get("cycle_ox", []))
                st["win"] = int(pst.get("win", 0) or 0)
                st["lose"] = int(pst.get("lose", 0) or 0)

        self._recalc_in_use()

        # bonmae# bonmae
        self.bon_occ = dict(snap.get("bon_occ", {}))
        self.bon_points = list(snap.get("bon_points", []))
        self.bon_flags = [dict(f) for f in snap.get("bon_flags", [])]
        self.bon_cur_side = snap.get("bon_cur_side", None)
        self.bon_col = int(snap.get("bon_col", 0) or 0)
        self.bon_row = int(snap.get("bon_row", 0) or 0)
        self.bon_run_start_col = int(snap.get("bon_run_start_col", 0) or 0)

        # main ox
        self.main_ox = list(snap.get("main_ox", []))
        self.main_flags = [dict(f) for f in snap.get("main_flags", [])]
        self.main_win = int(snap.get("main_win", 0) or 0)
        self.main_lose = int(snap.get("main_lose", 0) or 0)

        # support ox/reco
        self.support_ox = list(snap.get("support_ox", []))
        self.support_flags = [dict(f) for f in snap.get("support_flags", [])]
        self.support_win = int(snap.get("support_win", 0) or 0)
        self.support_lose = int(snap.get("support_lose", 0) or 0)
        self.support_reco_bid = snap.get("support_reco_bid", None)
        self.support_reco_side = snap.get("support_reco_side", None)
        self.support_lock_bid = snap.get("support_lock_bid", None)
        self.support_lock_pat = str(snap.get("support_lock_pat", "") or "")
        self.support_lock_idx = int(snap.get("support_lock_idx", 0) or 0)
        self.support_lock_remain = int(snap.get("support_lock_remain", 0) or 0)

        # reco
        self.reco_bid = snap.get("reco_bid", None)
        self.reco_side = snap.get("reco_side", None)
        self.reco_from_no = snap.get("reco_from_no", None)

        # main reco lock
        self.main_lock_bid = snap.get("main_lock_bid", None)
        self.main_lock_pat = str(snap.get("main_lock_pat", "") or "")
        self.main_lock_idx = int(snap.get("main_lock_idx", 0) or 0)
        self.main_lock_remain = int(snap.get("main_lock_remain", 0) or 0)


        # legacy reco vars
        self.reco_main = snap.get("reco_main", None)
        self.reco_board_id = snap.get("reco_board_id", None)
        self.reco_score = snap.get("reco_score", None)

        if getattr(self, "last_event_lbl", None) is not None:
            try:
                self.last_event_lbl.config(text=snap.get("last_event_text", ""))
            except Exception:
                pass

    def _push_undo_snapshot(self) -> None:
        """입력 1회 전 상태를 UNDO 스택에 저장한다 (전체 스냅샷)."""
        if not getattr(self, "_undo_snap_enabled", True):
            return
        try:
            snap = self._snapshot_state()
            self.undo_stack.append({"type": "SNAP", "snap": snap})
            # 스택 과다 방지(메모리): 최근 500개까지만 유지
            if len(self.undo_stack) > 500:
                self.undo_stack = self.undo_stack[-500:]
        except Exception:
            # 스냅샷 실패 시에도 게임 진행은 막지 않음
            return

    def play(self, tok: str):

        # 중복 클릭/재진입 방지 (판정 스냅샷 안정화)
        if getattr(self, "_judging", False):
            return
        self._judging = True
        try:
            # 입력 1회 = UNDO 1회 (변경 전 전체 스냅샷 저장)
            self._push_undo_snapshot()

            # 히스토리 기록
            self.hist.append(tok)

            # 이벤트 표시(타이/페어 포함)
            if getattr(self, "last_event_lbl", None) is not None:
                map_txt = {"P": "플레이어(풀)", "B": "뱅커(뱅)", "TIE": "타이", "P_PAIR": "P-페어", "B_PAIR": "B-페어"}
                self.last_event_lbl.config(text=f"입력: {map_txt.get(tok, tok)}")

            # 입력 직전 추천 상태 백업(UNDO용)
            reco_prev = (self.reco_bid, self.reco_side, self.reco_from_no)

            # P/B 입력일 때만 본매/패턴/메인OX 판정
            deltas: list[tuple] = []
            bon_prev = None
            mainox_prev = None

            if tok in ("P", "B"):
                # (1) 패턴 보드 판정(64/16 모드 공통) — ✅ 동기 사이클(동시 시작/동시 종료) + 사이클 내 고정패턴
                # 규칙:
                # - 16모드: 4판이 1사이클, 64모드: 6판이 1사이클
                # - 사이클 진행 중: 패턴 교체 금지(모든 보드가 같은 판 인덱스로 동시에 판정)
                # - 사이클 종료 시: 모든 보드가 동시에 '겹침 없이' 무작위 랜덤으로 패턴 재배정
                cycle_pos = int(getattr(self, "cycle_pos", 0) or 0)
                cycle_len = int(getattr(self, "pat_len", 6) or 6)
                if cycle_pos < 0 or cycle_pos >= cycle_len:
                    cycle_pos = 0

                # 이번 판 판정
                triggered_bids: list[tuple[int, str]] = []  # 세로 X 4칸(한 컬럼) 완성 트리거(보드, 당시패턴)
                for bid in self.board_ids[:self.active_board_n]:
                    st = self.pstate.get(bid)
                    if not st:
                        continue
                    pat = str(st.get("pat", ""))
                    if not pat:
                        continue

                    expected = pat[cycle_pos] if cycle_pos < len(pat) else pat[0]
                    mark = "O" if tok == expected else "X"

                    st.setdefault("cycle_ox", [])
                    st["cycle_ox"].append(mark)

                    st["ox"].append(mark)
                    if mark == "O":
                        st["win"] = int(st.get("win", 0) or 0) + 1
                    else:
                        st["lose"] = int(st.get("lose", 0) or 0) + 1

                    # ✅ 세로 X 4칸(한 컬럼) 완성 트리거 감지
                    # - 이전 열(X 이어짐)은 보지 않음
                    # - 오직 '같은 column에 X 4개'가 완성되는 순간만 트리거
                    if mark == "X":
                        ox_seq = st.get("ox", []) or []
                        if len(ox_seq) >= OX_ROWS and (len(ox_seq) % OX_ROWS) == 0:
                            if all(v == "X" for v in ox_seq[-OX_ROWS:]):
                                triggered_bids.append((bid, pat))

                # 다음 판으로
                cycle_pos += 1

                # ✅ 사이클 종료 처리: 전체 동시 랜덤 교체 (추천 평가는 "입력 직전 추천"으로 먼저 채점)
                cycle_ended = False
                if cycle_pos >= cycle_len:
                    cycle_ended = True
                    self.cycle_pos = 0
                    self._assign_initial_patterns(reset_steps=True, reset_cycle=True)
                else:
                    self.cycle_pos = cycle_pos

                # (2) 본매 누적            # (2) 본매 누적 (UNDO 대비 전체 스냅샷) 누적 (UNDO 대비 전체 스냅샷)
                bon_prev = (dict(self.bon_occ), list(self.bon_points), list(self.bon_flags), self.bon_cur_side, self.bon_col, self.bon_row, self.bon_run_start_col)
                self._bonmae_apply_pb(tok)
                # (3) 메인 추천: '세로 X 4칸(한 컬럼)' 트리거 보드의 패턴을 4회 고정 추천
                # - 추천 유지: 맞든 틀리든 4회는 무조건 진행
                # - 메인 OX: 추천 vs 본매(P/B) 결과로 O/X 기록
                prev_rp, prev_rs, _prev_rno = reco_prev

                # (3-1) 이전 추천 채점(추천 vs 본매)
                if prev_rs in ("P", "B"):
                    mainox_prev = (list(self.main_ox), list(self.main_flags), self.main_win, self.main_lose)
                    mark = "O" if tok == prev_rs else "X"
                    self.main_ox.append(mark)
                    self.main_flags.append({"TIE": False, "P_PAIR": False, "B_PAIR": False})
                    if mark == "O":
                        self.main_win += 1
                    else:
                        self.main_lose += 1

                # (3-2) 메인 추천 1회 소비(락 진행)
                if prev_rs in ('P', 'B') and self.main_lock_remain > 0:
                    # 이번 판(prev_rs)을 소비하고 다음 단계로 진행
                    self.main_lock_remain -= 1
                    if self.main_lock_remain > 0 and self.main_lock_pat:
                        self.main_lock_idx = (self.main_lock_idx + 1) % len(self.main_lock_pat)
                        self.main_reco_side = self.main_lock_pat[self.main_lock_idx]
                    else:
                        # 4단계 종료(락 해제)
                        self.main_lock_remain = 0
                        self.main_lock_bid = None
                        self.main_lock_pat = ''
                        self.main_lock_idx = 0
                        self.main_reco_side = None
                
                # (S-1) 서포트 추천 채점(서포트 추천 vs 본매)
                prev_support = getattr(self, "support_reco_side", None)
                if prev_support in ("P", "B") and int(getattr(self, "support_lock_remain", 0) or 0) > 0:
                    mark_s = "O" if tok == prev_support else "X"
                    self.support_ox.append(mark_s)
                    self.support_flags.append({"TIE": False, "P_PAIR": False, "B_PAIR": False})
                    if mark_s == "O":
                        self.support_win = int(getattr(self, "support_win", 0) or 0) + 1
                    else:
                        self.support_lose = int(getattr(self, "support_lose", 0) or 0) + 1

                    # 추천 1회 소비
                    self.support_lock_remain = int(getattr(self, "support_lock_remain", 0) or 0) - 1
                    if int(getattr(self, "support_lock_remain", 0) or 0) > 0:
                        # 다음 단계 추천으로 이동
                        self.support_lock_idx = int(getattr(self, "support_lock_idx", 0) or 0) + 1
                        if self.support_lock_idx >= 4:
                            self.support_lock_idx = 0
                        sp = str(getattr(self, "support_lock_pat", "") or "")
                        if len(sp) >= 1:
                            self.support_reco_side = sp[self.support_lock_idx % min(4, len(sp))]
                    else:
                        # 서포트 추천 종료
                        self.support_reco_side = None
                        self.support_reco_bid = None
                        self.support_lock_bid = None
                        self.support_lock_idx = 0
                        self.support_lock_pat = ""
                # (3-3) 이번 판에서 X4 트리거 발생 → 해당 보드를 메인 추천으로 '새로' 올림
                if 'triggered_bids' in locals() and triggered_bids:
                    # 락 진행 중이면 새 트리거로 덮어쓰지 않는다(안정성)
                    if int(getattr(self, 'main_lock_remain', 0) or 0) <= 0:
                        rmap = self._rank_map()
                        # triggered_bids: (bid, pat_at_trigger)
                        triggered_bids.sort(key=lambda bp: (int(rmap.get(bp[0], 9999) or 9999), int(bp[0])))
                        tbid, tpat = triggered_bids[0]
                        tpat = str(tpat or '')
                        if tpat:
                            self.main_lock_bid = int(tbid)

                        self.main_lock_pat = tpat
                        self.main_lock_idx = 0
                        self.main_lock_remain = 4

                # (3-4) 다음 추천 갱신(락이 있으면 락 패턴대로, 없으면 추천 없음)
                if int(getattr(self, "main_lock_remain", 0) or 0) > 0 and str(getattr(self, "main_lock_pat", "") or ""):
                    pat = str(self.main_lock_pat)
                    idx = int(getattr(self, "main_lock_idx", 0) or 0)
                    if pat:
                        ch = pat[idx] if idx < len(pat) else pat[idx % len(pat)]
                    else:
                        ch = None
                    self.reco_bid = getattr(self, "main_lock_bid", None)
                    self.reco_side = ch if ch in ("P", "B") else None
                    self.reco_from_no = getattr(self, "main_lock_bid", None)
                else:
                    self.reco_bid, self.reco_side, self.reco_from_no = (None, None, None)

                # (S-2) 메인 OX 마지막 4칸 상태 매칭 → 서포트 추천 4회 고정 시작
                # 규칙: 메인 OX 보드의 최근 4칸(O/X)이 완성되는 순간(4,8,12...)에만,
                #      16개 보드 중 '자기 OX(미니 OX)'가 동일한 보드 1개를 찾아 그 보드의 패턴(4칸)을 4회 고정 추천.
                if int(getattr(self, "support_lock_remain", 0) or 0) <= 0:
                    if len(getattr(self, "main_ox", [])) >= 4 and (len(self.main_ox) % 4 == 0):
                        target4 = list(self.main_ox[-4:])

                        candidates = []
                        for bid2 in self.board_ids[:self.active_board_n]:
                            st2 = self.pstate.get(bid2, {}) or {}
                            # '서포트'는 각 보드에 표시되는 OX(= st2["ox"])와 매칭한다.
                            cox = list(st2.get("ox", []) or [])
                            if len(cox) >= 4 and cox[-4:] == target4:
                                wr = float(st2.get("winrate", 0.0) or 0.0)
                                rk = int(st2.get("rank", 10**9) or 10**9)
                                pat2 = str(st2.get("pat", "") or "")
                                candidates.append(( -wr, rk, int(bid2), pat2 ))

                        if candidates:
                            candidates.sort()
                            _, _, match_bid, match_pat = candidates[0]
                            if match_pat:
                                self.support_lock_bid = match_bid
                                self.support_reco_bid = match_bid
                                self.support_lock_pat = str(match_pat)[:4]
                                self.support_lock_idx = 0
                                self.support_lock_remain = 4
                                chs = self.support_lock_pat[0] if self.support_lock_pat else None
                                self.support_reco_side = chs if chs in ("P", "B") else None
            # TIE/PAIR 입력은 본매/메인OX 진행에는 영향이 없고, 마지막 칸에 '표시'만 한다.
            if tok in ("TIE", "P_PAIR", "B_PAIR"):
                # 본매(6매) 마지막 칸에만 표시 (메인 OX에는 표시하지 않음)
                if not self.bon_points:
                    return
                bon_prev = (dict(self.bon_occ), list(self.bon_points), [dict(x) for x in self.bon_flags])
                if not getattr(self, "_undo_snap_enabled", True):
                    self.undo_stack.append({"type": "BON_FLAG", "bon_prev": bon_prev})

                if tok == "TIE":
                    # 타이는 연속으로 여러 번 나올 수 있으므로 마지막 칸에 누적 카운트
                    f = self.bon_flags[-1]
                    f["TIE"] = True
                    prev_n = int(f.get("TIE_N", 0) or 0)
                    f["TIE_N"] = max(1, prev_n + 1)
                else:
                    # P-PAIR / B-PAIR는 마지막 칸에 작은 표시만
                    f = self.bon_flags[-1]
                    f[tok] = True
                    # 레거시 키 호환(혹시 과거 데이터/표시 루틴이 다른 키를 참조하는 경우)
                    if tok == "P_PAIR":
                        f["PPAIR"] = True
                    elif tok == "B_PAIR":
                        f["BPAIR"] = True

                self._refresh_all()
                return

            # UNDO 스택 (레거시 모드에서만)
            if not getattr(self, "_undo_snap_enabled", True):
                self.undo_stack.append({
                    "type": "PB",
                    "hist_tok": tok,
                "deltas": deltas,
                "bon_prev": bon_prev,
                "mainox_prev": mainox_prev,
                "reco_prev": reco_prev,
            })

            self._refresh_all()

    
        finally:
            self._judging = False

    
    def undo(self):
        """되돌리기(UNDO)

        - 입력 1회 = UNDO 1회
        - 스냅샷 기반으로 전체 상태를 복원한다(안전/일관성 우선).
        """
        if not self.undo_stack:
            return

        # UNDO 중에는 판정 락 해제
        self._judging = False

        entry = self.undo_stack.pop()
        if isinstance(entry, dict) and entry.get("type") == "SNAP":
            snap = entry.get("snap", {})
            if isinstance(snap, dict):
                self._restore_state(snap)
                self._judging = False
                self._refresh_all()
                return

        # 레거시(예전 버전 호환)
        try:
            etype = entry.get("type") if isinstance(entry, dict) else None
        except Exception:
            etype = None

        if etype == "BON_FLAG":
            bon_prev = entry.get("bon_prev")
            if bon_prev is not None:
                try:
                    self.bon_occ, self.bon_points, self.bon_flags = bon_prev
                except Exception:
                    pass
            self._refresh_all()
            return

        if etype == "PB":
            if self.hist:
                self.hist.pop()
            bon_prev = entry.get("bon_prev")
            if bon_prev is not None:
                try:
                    self.bon_occ, self.bon_points, self.bon_flags = bon_prev
                except Exception:
                    pass
            self._refresh_all()
            return

        self._refresh_all()


    def reset(self):
        # ✅ 완전 초기화(패턴 위치/메인OX 불일치 방지)
        self.hist.clear()
        self.undo_stack.clear()

        # 사이클/패턴 위치 초기화
        self.cycle_pos = 0
        for bid in self.board_ids[:self.active_board_n]:
            st = self.pstate[bid]
            st["step"] = 0
            st["ox"].clear()
            st["cycle_ox"] = []   # ✅ 사이클 OX도 같이 초기화(RESET 후 추천/판정 꼬임 방지)
            st["win"] = 0
            st["lose"] = 0

        # ✅ 패턴도 새로(겹침 없이) 랜덤 배정 + 사이클 시작점(0)로 고정
        self._assign_initial_patterns(reset_steps=True, reset_cycle=True)

        # 본매/메인OX/추천 초기화
        self.bon_occ.clear()
        self.bon_points.clear()
        self.bon_flags.clear()
        self.bon_cur_side = None
        self.bon_col = 0
        self.bon_row = 0
        self.bon_run_start_col = 0

        self.main_ox.clear()
        self.main_flags.clear()
        self.main_win = 0
        self.main_lose = 0

        # 서포트 OX/추천 초기화
        self.support_ox.clear()
        self.support_flags.clear()
        self.support_win = 0
        self.support_lose = 0
        self.support_reco_bid = None
        self.support_reco_side = None
        self.support_lock_bid = None
        self.support_lock_pat = ""
        self.support_lock_idx = 0
        self.support_lock_remain = 0

        self.reco_bid = None
        self.reco_side = None
        self.reco_from_no = None

        # 메인 추천 락 초기화
        self.main_lock_bid = None
        self.main_lock_pat = ""
        self.main_lock_idx = 0
        self.main_lock_remain = 0


        if getattr(self, "last_event_lbl", None) is not None:
            self.last_event_lbl.config(text="")

        self._refresh_all()

    def flush_save(self):
        # 요구상 버튼은 유지. 현재 상태를 DB 폴더에 저장
        try:
            ts = int(time.time())
            out = {
                "ts": ts,
                "hist": self.hist,
                "patterns": {
                    str(bid): {
                        "pat": self.pstate[bid].get("pat", ""),
                        "step": int(self.pstate[bid].get("step", 0) or 0),
                        "win": int(self.pstate[bid].get("win", 0) or 0),
                        "lose": int(self.pstate[bid].get("lose", 0) or 0),
                        "ox": list(self.pstate[bid].get("ox", []))[-(OX_ROWS*MAX_COLS):],
                    }
                    for bid in self.board_ids[:self.active_board_n]
                }
            }
            p = DB_DIR / f"pat64_state_{ts}.json"
            import json
            with p.open("w", encoding="utf-8") as f:
                json.dump(out, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    # ---------- Rendering ----------
    
    def _refresh_all(self):
        # 상단(본매/메인OX/추천) 갱신
        if getattr(self, "main_rec_lbl", None) is not None:
            # 메인 추천 표시: X4(세로 4칸) 트리거 기반 4회 고정 추천
            if getattr(self, "main_lock_remain", 0) > 0 and self.reco_side in ("P", "B") and self.reco_bid is not None:
                bid = int(self.reco_bid)
                pat = str(getattr(self, "main_lock_pat", "") or "")
                step_done = 4 - int(getattr(self, "main_lock_remain", 0) or 0)
                step_no = step_done + 1  # 다음 추천이 몇 번째인지(1~4)
                st = self.pstate.get(bid, {})
                wv = int(st.get("win", 0) or 0)
                lv = int(st.get("lose", 0) or 0)
                tv = wv + lv
                rate = (wv / tv * 100.0) if tv else 0.0
                self.main_rec_lbl.config(
                    text=f"서포트 추천: 보드 {bid}번 · 패턴 {pretty_pat(pat)}  ({step_no}/4)  → {pretty_side(self.reco_side)}  · 승률 {rate:.1f}%",
                    fg=side_color(self.reco_side)
                )
            else:
                self.main_rec_lbl.config(text="서포트 추천: 없음", fg=C_TXT)

        # 서포트 추천 표시: 메인 OX 마지막 4칸 상태 매칭 기반 4회 고정 추천
        if getattr(self, "support_rec_lbl", None) is not None:
            if int(getattr(self, "support_lock_remain", 0) or 0) > 0 and getattr(self, "support_reco_side", None) in ("P", "B") and getattr(self, "support_reco_bid", None) is not None:
                bid = int(getattr(self, "support_reco_bid", 0) or 0)
                pat = str(getattr(self, "support_lock_pat", "") or "")
                step_done = 4 - int(getattr(self, "support_lock_remain", 0) or 0)
                step_no = step_done + 1
                st = self.pstate.get(bid, {})
                wv = int(st.get("win", 0) or 0)
                lv = int(st.get("lose", 0) or 0)
                tv = wv + lv
                rate = (wv / tv * 100.0) if tv else 0.0
                side = str(getattr(self, "support_reco_side", "") or "")
                self.support_rec_lbl.config(
                    text=f"메인 추천: 보드 {bid}번 · 패턴 {pretty_pat(pat[:4])}  ({step_no}/4)  → {pretty_side(side)}  · 승률 {rate:.1f}%",
                    fg=side_color(side)
                )
            else:
                self.support_rec_lbl.config(text="메인 추천: 없음", fg=C_TXT)

        self._draw_bonmae()
        self._draw_mainox()
        self._draw_supportox()

        # 카드 위치는 고정. 순위는 계산만 해서 표시한다.
        rmap = self._rank_map()
        for bid in self.board_ids:
            # 16모드에서는 0..15만 표시/갱신
            if bid > self.active_board_n:
                continue
            self._render_card(bid, cur_rank=rmap.get(bid))

    def _render_card(self, bid: int, cur_rank: int | None):
        st = self.pstate.get(bid, {})
        w = st.get("widgets", {})
        if not w:
            return

        pat = str(st.get("pat", ""))
        pat_no = int(bid)

        # ✅ 동기 사이클(16=4판 / 64=6판)에서는 '보드별 step'을 쓰지 않고,
        #    앱 공통 cycle_pos(현재 판 인덱스)로 동일하게 판정/표시한다.
        cycle_pos = int(getattr(self, "cycle_pos", 0) or 0)
        cycle_pos = max(0, min(cycle_pos, max(0, self.pat_len - 1)))
        expected = pat[cycle_pos] if pat and cycle_pos < len(pat) else "-"

        # 단계 라벨(현재 판/사이클 길이)
        w["step_lbl"].config(text=f"({cycle_pos+1}/{self.pat_len})")

        # 추천 라벨(색상 적용)
        w["rec_lbl"].config(
            text=f"추천: {pretty_side(expected)}",
            fg=side_color(expected)
        )

        # 패턴 문자열(색상 + 고유 번호 + 현재 순위)
        self._draw_pattern_text(w["pat_cv"], pat, pat_no, cur_rank)

        # 체크 시트(6칸 격자)
        self._draw_check_grid(w["grid_cv"], pat, cycle_pos)

        # OX 보드(4매) 렌더
        self._draw_ox(w["ox_cv"], st.get("ox", []))

        # 승/패/승률
        win = int(st.get("win", 0) or 0)
        lose = int(st.get("lose", 0) or 0)
        total = win + lose
        rate = (win / total * 100.0) if total else 0.0
        w["stat_lbl"].config(text=f"승 {win} / 패 {lose} ({rate:.1f}%)")
    def _draw_pattern_text(self, cv: tk.Canvas, pat: str, pat_no: int, cur_rank: int | None):
        """상단 캔버스(패턴 + 현재 순위). 좁은 폭에서는 2줄로 분리해 겹침 방지."""
        cv.delete("all")
        cv.update_idletasks()

        try:
            W = int(cv.winfo_width())
        except Exception:
            W = 260

        # 폭이 좁으면 2줄(패턴/순위 분리), 넓으면 1줄(기존처럼)
        narrow = (W < 320) or (getattr(self, "grid_cols", GRID_COLS_DEFAULT) <= 3)

        if narrow:
            # 2줄 표시를 위해 높이 확보
            try:
                cv.configure(height=34)
            except Exception:
                pass
            y_pat = 11
            y_rank = 26
        else:
            try:
                cv.configure(height=18)
            except Exception:
                pass
            y_pat = 9
            y_rank = 9

        # --- 패턴(좌측) ---
        x = 2
        cv.create_text(x, y_pat, text=f"({pat_no})", fill=C_TXT, anchor="w", font=("맑은 고딕", 10, "bold"))
        x += 28

        for ch in pat:
            color = C_MAIN_P if ch == "P" else C_MAIN_B
            cv.create_text(x, y_pat, text=ch, fill=color, anchor="w", font=("맑은 고딕", 10, "bold"))
            x += 10

        # --- 현재 순위(상단 중앙, 1줄만) ---
        if cur_rank is not None:
            if cur_rank <= 20:
                rcol = "#00ff66"
            elif cur_rank <= 40:
                rcol = "#ffd400"
            else:
                rcol = "#ff4d4d"

            cx = max(10, W // 2)
            cv.create_text(cx, y_rank, text=f"현재 {cur_rank}위", fill=rcol, anchor="center", font=("맑은 고딕", 10, "bold"))


    def _draw_check_grid(self, cv: tk.Canvas, pat: str, step: int):
        cv.delete("all")
        cv.update_idletasks()
        W = max(1, cv.winfo_width())
        H = max(1, cv.winfo_height())

        pad = 2
        gap = 2
        cell_w = max(16, min(34, (W - pad*2 - gap*5) // 6))
        cell_h = max(18, H - pad*2)

        x = pad
        y = pad
        for i, ch in enumerate(pat):
            fill = C_CELL_O if i == step else C_CELL
            outline = "#9AE6B4" if i == step else C_FRAMEB
            cv.create_rectangle(x, y, x+cell_w, y+cell_h, fill=fill, outline=outline, width=2 if i == step else 1)
            color = C_MAIN_P if ch == "P" else C_MAIN_B
            cv.create_text(x+cell_w/2, y+cell_h/2, text=ch, fill=color, font=("맑은 고딕", 10, "bold"))
            x += cell_w + gap

    def _draw_ox(self, cv: tk.Canvas, ox: list[str]):
        cv.delete("all")
        cv.update_idletasks()
        W = max(1, cv.winfo_width())
        H = max(1, cv.winfo_height())

        pad = 2
        gap = 1

        cell = max(10, min(14, (W - pad*2 - gap*(MAX_COLS-1)) // MAX_COLS))
        cell_h = max(10, min(16, (H - pad*2 - gap*(OX_ROWS-1)) // OX_ROWS))
        s = min(cell, cell_h)

        start_x = pad
        start_y = pad

        max_len = OX_ROWS * MAX_COLS
        seq = ox[-max_len:]

        for idx, v in enumerate(seq):
            col = idx // OX_ROWS
            row = idx % OX_ROWS
            x = start_x + col * (s + gap)
            y = start_y + row * (s + gap)
            cv.create_rectangle(x, y, x+s, y+s, fill=C_CELL, outline=C_FRAMEB, width=1)
            color = C_BLUE if v == "O" else C_RED
            cv.create_text(x + s/2, y + s/2, text=v, fill=color, font=("맑은 고딕", 10, "bold"))


    # ---------- Main recommendation / Bonmae / Main OX ----------
    

    def _pick_reco_pattern(self) -> tuple[int|None, str|None, int|None]:
        """메인 추천(사이클 기반):
        - ✅ 16모드(4판): 2판부터 O>=1 → 3판 O>=2 → 4판 O>=3
        - ✅ 64모드(6판): 2판부터 O>=1 → ... → 6판 O>=5
        - 후보가 없으면 단계 하향(O>=k-1 ... O>=1) 후 그래도 없으면 '없음'
        - 후보가 여러 개면: (1) 사이클 O개수 많은 보드 (2) 현재 순위(승률 기반) 좋은 보드
        반환: (bid, side, board_no)
        """
        cycle_pos = int(getattr(self, "cycle_pos", 0) or 0)  # 다음에 칠 판(0-based)
        cycle_len = int(getattr(self, "pat_len", 6) or 6)

        # 1판 시작 전(0)에는 추천 없음 (사용자 운영 안정성)
        if cycle_pos <= 0:
            return None, None, None

        # 이번 판(다음 입력)에서 요구되는 최소 O 개수 = cycle_pos (2판 전=1, 3판 전=2 ...)
        need = max(1, min(cycle_pos, cycle_len - 1))

        rmap = self._rank_map()

        def count_o(bid: int) -> int:
            ox = self.pstate[bid].get("cycle_ox", []) or []
            return sum(1 for x in ox if x == "O")

        # 단계 하향 검색
        best: tuple = ()
        chosen_bid: int | None = None

        for k in range(need, 0, -1):
            cands = []
            for bid in self.board_ids[:self.active_board_n]:
                if count_o(bid) >= k:
                    cands.append(bid)
            if cands:
                # 가장 O 많은 보드 우선, 동률이면 순위(작은 값) 우선
                cands.sort(key=lambda b: (-count_o(b), int(rmap.get(b, 9999) or 9999), b))
                chosen_bid = cands[0]
                break

        if chosen_bid is None:
            return None, None, None

        st = self.pstate[chosen_bid]
        pat = str(st.get("pat", ""))

        # 다음 판에서의 추천 side는 패턴의 cycle_pos 인덱스
        side = pat[cycle_pos] if pat and cycle_pos < len(pat) else None
        return chosen_bid, side, chosen_bid

    def _bonmae_next_pos(self, side: str) -> tuple[int,int]:
        """
        본매 6매식:
        - 시작: (0,0)
        - 동일 결과: 아래로(최대 6칸). 아래가 막히거나 바닥이면 같은 행에서 오른쪽(꼬리)
        - 결과 변경: '현재 덩어리 시작열(run_start_col) + 1'로 이동, row=0
        """
        if self.bon_cur_side is None:
            self.bon_cur_side = side
            self.bon_col = 0
            self.bon_row = 0
            self.bon_run_start_col = 0
            return 0, 0

        if side == self.bon_cur_side:
            # 동일: 아래 우선
            if self.bon_row < BON_ROWS-1 and (self.bon_col, self.bon_row+1) not in self.bon_occ:
                return self.bon_col, self.bon_row+1
            # 아래가 막히거나 바닥: 꼬리로 오른쪽
            return self.bon_col + 1, self.bon_row
        else:
            # 변경: 덩어리 시작열 다음 컬럼으로 (공백 방지)
            new_col = self.bon_run_start_col + 1
            return new_col, 0

    def _bonmae_apply_pb(self, side: str):
        c, r = self._bonmae_next_pos(side)
        # 상태 업데이트
        if self.bon_cur_side is None:
            self.bon_cur_side = side
            self.bon_run_start_col = c
        elif side != self.bon_cur_side:
            self.bon_cur_side = side
            self.bon_run_start_col = c
        self.bon_col, self.bon_row = c, r
        self.bon_occ[(c, r)] = side
        self.bon_points.append((c, r, side))
        self.bon_flags.append({"TIE": False, "P_PAIR": False, "B_PAIR": False})

    def _draw_bonmae(self):
        cv = getattr(self, "bon_cv", None)
        if cv is None:
            return
        cv.delete("all")
        cv.update_idletasks()
        W = max(1, cv.winfo_width())
        H = max(1, cv.winfo_height())

        pad = 2
        gap = 1
        # 보여줄 열 수는 화면에 맞춤
        cell = max(10, min(18, (H - pad*2 - gap*(BON_ROWS-1)) // BON_ROWS))
        cell_w = cell
        vis_cols = max(10, (W - pad*2) // (cell_w + gap))
        # 최신 열이 오른쪽으로 계속 늘어나므로, 너무 길면 마지막 구간만 표시(왼쪽에서 시작하되, 화면 넘치면 스크롤처럼 잘라 표시)
        max_col = max([c for c,_,_ in self.bon_points], default=0)
        start_col = max(0, max_col - vis_cols + 1)

        # 그리드
        for rr in range(BON_ROWS):
            for cc in range(vis_cols):
                x = pad + cc*(cell_w+gap)
                y = pad + rr*(cell+gap)
                cv.create_rectangle(x, y, x+cell_w, y+cell, fill=C_CELL, outline=C_FRAMEB, width=1)

        # 점 찍기
        for i, (c, r, side) in enumerate(self.bon_points[-(BON_ROWS*BON_MAX_COLS):]):
            if c < start_col:
                continue
            cc = c - start_col
            if cc >= vis_cols or r < 0 or r >= BON_ROWS:
                continue
            x = pad + cc*(cell_w+gap)
            y = pad + r*(cell+gap)
            color = C_MAIN_P if side == "P" else C_MAIN_B
            cv.create_rectangle(x, y, x+cell_w, y+cell, fill=C_CELL_O, outline=C_FRAMEB, width=1)
            cv.create_text(x+cell_w/2, y+cell/2, text=("P" if side=="P" else "B"), fill=color, font=("맑은 고딕", 10, "bold"))

            # 타이/페어 표시(마지막 점 기준으로 누적)
            start_index = max(0, len(self.bon_points) - (BON_ROWS*BON_MAX_COLS))
            fi = start_index + i
            if 0 <= fi < len(self.bon_flags):
                fl = self.bon_flags[fi]
                # TIE: 우상단 초록 점
                if fl.get("TIE"):
                    cv.create_oval(x+cell_w-7, y+2, x+cell_w-2, y+7, fill=C_TIE, outline="")
                    n = int(fl.get("TIE_N", 0) or 0)
                    if n >= 2:
                        tx = max(0, x-10)
                        ty = max(0, y-2)
                        cv.create_text(tx, ty, text=str(n), anchor="nw", fill=C_TIE_NUM, font=("맑은 고딕", 9, "bold"))
                # P-PAIR: 좌하단 파란 링
                if fl.get("P_PAIR"):
                    cv.create_oval(x+2, y+cell-7, x+7, y+cell-2, outline=C_PPAIR, width=2)
                # B-PAIR: 우하단 빨간 링
                if fl.get("B_PAIR"):
                    cv.create_oval(x+cell_w-7, y+cell-7, x+cell_w-2, y+cell-2, outline=C_BPAIR, width=2)

    def _draw_mainox(self):
        cv = getattr(self, "mainox_cv", None)
        if cv is None:
            return
        # 제목 갱신
        total = self.main_win + self.main_lose
        rate = (self.main_win/total*100.0) if total else 0.0
        if getattr(self, "mainox_title", None) is not None:
            self.mainox_title.config(text=f"서포트 OX 보드  승 {self.main_win} / 패 {self.main_lose} ({rate:.1f}%)")

        cv.delete("all")
        cv.update_idletasks()
        W = max(1, cv.winfo_width())
        H = max(1, cv.winfo_height())

        pad=2
        gap=1
        cell = max(10, min(14, (H - pad*2 - gap*(OX_ROWS-1)) // OX_ROWS))
        cell_w = cell
        vis_cols = max(10, (W - pad*2) // (cell_w + gap))
        max_len = OX_ROWS * vis_cols
        seq = self.main_ox[-max_len:]
        fseq = self.main_flags[-max_len:]

        # grid
        for rr in range(OX_ROWS):
            for cc in range(vis_cols):
                x = pad + cc*(cell_w+gap)
                y = pad + rr*(cell+gap)
                cv.create_rectangle(x,y,x+cell_w,y+cell, fill=C_CELL, outline=C_FRAMEB, width=1)

        for idx, v in enumerate(seq):
            col = idx // OX_ROWS
            row = idx % OX_ROWS
            x = pad + col*(cell_w+gap)
            y = pad + row*(cell+gap)
            color = C_BLUE if v=="O" else C_RED
            cv.create_text(x+cell_w/2, y+cell/2, text=v, fill=color, font=("맑은 고딕", 10, "bold"))

            # (TIE/PAIR 표시는 본매(6매)에만 표시)



    def _draw_supportox(self):
        cv = getattr(self, "supportox_cv", None)
        if cv is None:
            return
        total = int(getattr(self, "support_win", 0) or 0) + int(getattr(self, "support_lose", 0) or 0)
        rate = (float(getattr(self, "support_win", 0) or 0) / total * 100.0) if total else 0.0
        if getattr(self, "supportox_title", None) is not None:
            self.supportox_title.config(text=f"메인 OX 보드  승 {self.support_win} / 패 {self.support_lose} ({rate:.1f}%)")

        cv.delete("all")
        cv.update_idletasks()
        W = max(1, cv.winfo_width())
        H = max(1, cv.winfo_height())

        pad = 2
        gap = 1
        cell = max(10, min(14, (H - pad*2 - gap*(OX_ROWS-1)) // OX_ROWS))
        cell_w = cell
        vis_cols = max(10, (W - pad*2) // (cell_w + gap))
        max_len = OX_ROWS * vis_cols
        seq = list(getattr(self, "support_ox", []))[-max_len:]
        # grid
        for rr in range(OX_ROWS):
            for cc in range(vis_cols):
                x = pad + cc*(cell_w+gap)
                y = pad + rr*(cell+gap)
                cv.create_rectangle(x, y, x+cell_w, y+cell, fill=C_CELL, outline=C_FRAMEB, width=1)

        for i, v in enumerate(seq):
            col = i // OX_ROWS
            row = i % OX_ROWS
            x = pad + col*(cell_w+gap)
            y = pad + row*(cell+gap)
            color = C_BLUE if v == "O" else C_RED
            cv.create_text(x+cell_w/2, y+cell/2, text=v, fill=color, font=("맑은 고딕", 10, "bold"))


# ---------------- main ----------------
if __name__ == "__main__":
    if ensure_license_access() and _prepare_site_session():
        App().mainloop()