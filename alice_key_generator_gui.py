
from __future__ import annotations
import datetime as _dt
import hashlib
import hmac
import json
import platform
import re
import tkinter as tk
from pathlib import Path
from tkinter import messagebox

try:
    import requests
except Exception:
    requests = None

LICENSE_SECRET = "ALICE_SOFT_LICENSE_V1_2026"
AUTO_SERVER_URL = ""
AUTO_SERVER_TOKEN = ""


def _server_config_path() -> Path:
    return Path(__file__).resolve().parent / "license_server_config.template.json"


def _load_server_config() -> dict:
    p = _server_config_path()
    if p.exists():
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
        except Exception:
            pass
    if AUTO_SERVER_URL:
        return {"enabled": True, "base_url": AUTO_SERVER_URL, "client_token": AUTO_SERVER_TOKEN}
    return {"enabled": False}


def _server_headers() -> dict:
    cfg = _load_server_config()
    headers = {"Content-Type": "application/json"}
    token = str(cfg.get("client_token", "")).strip()
    if token:
        headers["X-ALICE-TOKEN"] = token
    return headers



def _choice_cache_dir() -> Path:
    p = Path(__file__).resolve().parent / "choice_cache"
    return p

def load_local_choice(pc_code: str) -> dict | None:
    try:
        p = _choice_cache_dir() / f"{pc_code.strip().upper()}.json"
        if p.exists():
            data = json.loads(p.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else None
    except Exception:
        pass
    return None


def fetch_choice(pc_code: str) -> dict | None:
    local = load_local_choice(pc_code)
    if local:
        return local
    if requests is None:
        return None
    cfg = _load_server_config()
    if not bool(cfg.get("enabled")):
        return None
    base_url = str(cfg.get("base_url", "")).rstrip("/")
    if not base_url:
        return None
    try:
        r = requests.get(f"{base_url}/api/v1/choices/{pc_code.strip().upper()}", timeout=4, headers=_server_headers())
        if r.ok:
            data = r.json()
            return data if isinstance(data, dict) else None
    except Exception:
        pass
    return None


def register_key_to_server(pc_code: str, key: str, user_name: str, mode: str, days_value: str):
    if requests is None:
        return False, "requests 모듈이 없습니다."
    cfg = _load_server_config()
    if not bool(cfg.get("enabled")):
        return False, "서버 설정이 꺼져 있습니다."
    base_url = str(cfg.get("base_url", "")).rstrip("/")
    if not base_url:
        return False, "서버 주소가 없습니다."
    payload = {"pc_code": pc_code.strip().upper(), "key": key.strip().upper(), "name": _sanitize_name(user_name), "mode": mode.strip().upper(), "days_value": str(days_value)}
    try:
        r = requests.post(f"{base_url}/api/v1/admin/register", json=payload, timeout=5, headers=_server_headers())
        if r.ok:
            data = r.json()
            if isinstance(data, dict) and data.get("ok"):
                return True, str(data.get("message") or "등록 완료")
            return False, str(data.get("message") or "등록 실패")
    except Exception as e:
        return False, f"서버 연결 실패: {e}"
    return False, "등록 실패"


def _sanitize_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9가-힣]+", "", (name or "").strip())
    return cleaned[:12] if cleaned else "USER"

def build_signature(name: str, expire_ymd: str, mode: str, days_label: str, pc_code: str) -> str:
    payload = f"{_sanitize_name(name)}|{expire_ymd}|{mode}|{days_label}|{pc_code}"
    sig = hmac.new(LICENSE_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest().upper()
    return sig[:12]

def build_key(name: str, pc_code: str, mode: str, days_value: str) -> str:
    name = _sanitize_name(name)
    pc_code = pc_code.strip().upper()
    if not re.fullmatch(r"[A-F0-9]{12}", pc_code):
        raise ValueError("PC 코드는 12자리 영문/숫자여야 합니다.")

    if mode == "PAY":
        days = int(days_value)
        if days < 1 or days > 30:
            raise ValueError("기간제는 1일~30일 사이만 가능합니다.")
        expire = (_dt.date.today() + _dt.timedelta(days=days))
        expire_ymd = expire.strftime("%Y%m%d")
        days_label = f"{days}D"
    else:
        expire = (_dt.date.today() + _dt.timedelta(days=1))
        expire_ymd = expire.strftime("%Y%m%d")
        days_label = "1D"

    sig = build_signature(name, expire_ymd, mode, days_label, pc_code)
    return f"{name}-{expire_ymd}-{mode}-{days_label}-{sig}"

def guidance_text(key: str, mode: str, style: str) -> str:
    if style == "강한":
        if mode == "PAY":
            return f"""[사용 안내]\n\n본 프로그램은 1PC 전용입니다.\n다른 PC 사용 시 실행되지 않습니다.\n\n기간제 라이선스가 적용된 키입니다.\n기간 종료 시 사용이 제한됩니다.\n\n키: {key}"""
        return f"""[사용 안내]\n\n본 프로그램은 1PC 전용입니다.\n다른 PC 사용 시 실행되지 않습니다.\n\n수익 공유 방식(10%) 키입니다.\n자세한 조건은 별도 안내에 따릅니다.\n\n키: {key}"""
    if style == "친절":
        return f"""안녕하세요 🙂\n프로그램 실행 후 아래 키를 입력하시면 됩니다.\n\n키: {key}"""
    return f"""사용 방법:\n프로그램 실행 후 키 입력하세요.\n\n키: {key}"""

class KeyGeneratorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Alice Key Generator")
        self.geometry("620x640")
        self.resizable(False, False)

        self.name_var = tk.StringVar(value="KIM")
        self.pc_var = tk.StringVar()
        self.mode_var = tk.StringVar(value="PAY")
        self.days_var = tk.StringVar(value="1")
        self.guide_var = tk.StringVar(value="강한")
        self.key_var = tk.StringVar()
        self.loaded_choice = None

        self._build_ui()
        self._on_mode_change()

    def _build_ui(self):
        pad = {"padx": 14, "pady": 6}

        tk.Label(self, text="이름").pack(anchor="w", **pad)
        tk.Entry(self, textvariable=self.name_var, width=40, font=("맑은 고딕", 12)).pack(fill="x", padx=14)

        tk.Label(self, text="PC 코드 (고객 프로그램에 뜨는 12자리 코드)").pack(anchor="w", **pad)
        tk.Entry(self, textvariable=self.pc_var, width=40, font=("맑은 고딕", 12)).pack(fill="x", padx=14)
        tk.Button(self, text="고객 선택 정보 불러오기", command=self.load_choice).pack(anchor="w", padx=14, pady=(4, 4))
        self.choice_label = tk.Label(self, text="고객 선택 정보: 없음", anchor="w", justify="left")
        self.choice_label.pack(fill="x", padx=14)

        tk.Label(self, text="사용 방식").pack(anchor="w", **pad)
        mode_frame = tk.Frame(self)
        mode_frame.pack(fill="x", padx=14)
        tk.Radiobutton(mode_frame, text="기간제", variable=self.mode_var, value="PAY", command=self._on_mode_change).pack(side="left", padx=(0, 10))
        tk.Radiobutton(mode_frame, text="수익 10%", variable=self.mode_var, value="SHARE", command=self._on_mode_change).pack(side="left")

        self.days_wrap = tk.Frame(self)
        self.days_wrap.pack(fill="x", padx=14, pady=(2, 6))
        tk.Label(self.days_wrap, text="기간(1~30일)").pack(anchor="w")
        tk.Entry(self.days_wrap, textvariable=self.days_var, width=12, font=("맑은 고딕", 12)).pack(anchor="w")

        tk.Label(self, text="안내 문구 스타일").pack(anchor="w", **pad)
        guide_frame = tk.Frame(self)
        guide_frame.pack(fill="x", padx=14)
        for txt in ("기본", "강한", "친절"):
            tk.Radiobutton(guide_frame, text=txt, variable=self.guide_var, value=txt).pack(side="left", padx=(0, 10))

        btn_frame = tk.Frame(self)
        btn_frame.pack(fill="x", padx=14, pady=14)
        tk.Button(btn_frame, text="키 생성", command=self.generate, height=2, font=("맑은 고딕", 11, "bold")).pack(side="left", padx=(0, 8))
        tk.Button(btn_frame, text="키 복사", command=self.copy_key, height=2).pack(side="left", padx=(0, 8))
        tk.Button(btn_frame, text="안내문 복사", command=self.copy_guide, height=2).pack(side="left")

        tk.Label(self, text="생성된 키").pack(anchor="w", **pad)
        tk.Entry(self, textvariable=self.key_var, width=70, font=("Consolas", 12)).pack(fill="x", padx=14)

        tk.Label(self, text="고객에게 보낼 안내 문구").pack(anchor="w", **pad)
        self.guide_text = tk.Text(self, height=14, font=("맑은 고딕", 11))
        self.guide_text.pack(fill="both", expand=True, padx=14, pady=(0, 14))

    def load_choice(self):
        pc = self.pc_var.get().strip().upper()
        if not pc:
            messagebox.showerror("오류", "먼저 PC 코드를 입력하세요.")
            return
        data = fetch_choice(pc)
        if not data:
            self.loaded_choice = None
            self.choice_label.config(text="고객 선택 정보: 없음")
            return
        self.loaded_choice = data
        label = str(data.get("label") or "").strip() or "없음"
        mode = str(data.get("mode") or "").strip()
        days = data.get("days")
        self.choice_label.config(text=f"고객 선택 정보: {label}")
        if mode == "PAY":
            self.mode_var.set("PAY")
            if days:
                self.days_var.set(str(days))
        elif mode == "SHARE":
            self.mode_var.set("SHARE")
        self._on_mode_change()

    def _on_mode_change(self):
        if self.mode_var.get() == "PAY":
            self.days_wrap.pack(fill="x", padx=14, pady=(2, 6))
        else:
            self.days_wrap.pack_forget()

    def generate(self):
        # 고객 선택 정보와 관리자 입력값이 다르면 생성 금지
        if self.loaded_choice:
            choice_mode = str(self.loaded_choice.get("mode") or "").strip().upper()
            choice_days = self.loaded_choice.get("days")
            current_mode = self.mode_var.get().strip().upper()

            if choice_mode and choice_mode != current_mode:
                messagebox.showerror("생성 실패", "사용자가 선택한 요금제와 일치하지 않습니다.")
                return

            if choice_mode == "PAY":
                try:
                    input_days = int(str(self.days_var.get()).strip())
                except Exception:
                    messagebox.showerror("생성 실패", "기간 입력이 올바르지 않습니다.")
                    return
                try:
                    choice_days_int = int(choice_days)
                except Exception:
                    choice_days_int = None
                if choice_days_int is not None and input_days != choice_days_int:
                    messagebox.showerror("생성 실패", f"사용자 선택 기간({choice_days_int}일)과 일치하지 않습니다.")
                    return

        try:
            key = build_key(
                self.name_var.get(),
                self.pc_var.get(),
                self.mode_var.get(),
                self.days_var.get() if self.mode_var.get() == "PAY" else "INF",
            )
        except Exception as e:
            messagebox.showerror("생성 실패", str(e))
            return

        self.key_var.set(key)
        guide = guidance_text(key, self.mode_var.get(), self.guide_var.get())
        self.guide_text.delete("1.0", "end")
        self.guide_text.insert("1.0", guide)
        messagebox.showinfo("완료", "키가 생성되었습니다.")

    def copy_key(self):
        key = self.key_var.get().strip()
        if not key:
            messagebox.showerror("오류", "먼저 키를 생성하세요.")
            return
        self.clipboard_clear()
        self.clipboard_append(key)
        self.update()
        messagebox.showinfo("복사 완료", "키가 복사되었습니다.")

    def copy_guide(self):
        txt = self.guide_text.get("1.0", "end").strip()
        if not txt:
            messagebox.showerror("오류", "먼저 키를 생성하세요.")
            return
        self.clipboard_clear()
        self.clipboard_append(txt)
        self.update()
        messagebox.showinfo("복사 완료", "안내 문구가 복사되었습니다.")

if __name__ == "__main__":
    app = KeyGeneratorApp()
    app.mainloop()
