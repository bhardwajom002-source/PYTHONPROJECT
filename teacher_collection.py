# school_hackathon_material.py
"""
Hackathon-grade Single-file School Management System
Option A: Modern Material UI (Glass Effect)
Run: python school_hackathon_material.py
DB file: school_hackathon_material.db
"""

import sqlite3
import threading
import json
import csv
import os
import hashlib
import secrets
import hmac
import base64
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse
from datetime import datetime, date, timedelta
from functools import wraps

from tkinter import *
from tkinter import ttk, messagebox, filedialog, simpledialog

# ---------- CONFIG ----------
DB_FILE = "school_hackathon_material.db"
API_HOST = "localhost"
API_PORT = 7200
TOKEN_SECRET = secrets.token_hex(32)
TOKEN_EXP_SECONDS = 60 * 60 * 12  # 12 hours
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX = 120  # requests per WINDOW per IP

# ---------- Database helpers ----------
def get_conn():
    con = sqlite3.connect(DB_FILE, check_same_thread=False)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con = get_conn()
    cur = con.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS students(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        first_name TEXT NOT NULL,
        last_name TEXT,
        roll TEXT,
        grade TEXT,
        phone TEXT,
        notes TEXT
    )""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        pwd_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        role TEXT NOT NULL
    )""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS fees(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER NOT NULL,
        amount REAL NOT NULL,
        paid INTEGER DEFAULT 0,
        note TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(student_id) REFERENCES students(id)
    )""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS attendance(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER NOT NULL,
        att_date TEXT NOT NULL,
        status TEXT NOT NULL, -- present / absent
        note TEXT,
        FOREIGN KEY(student_id) REFERENCES students(id)
    )""")
    con.commit()

    # default admin user
    cur.execute("SELECT id FROM users WHERE username = ?", ("admin",))
    if not cur.fetchone():
        create_user("admin", "admin123", "admin")
        print("Created default admin: admin/admin123")
    con.close()

# ---------- security helpers ----------
def sha256_hex(s):
    return hashlib.sha256(s.encode()).hexdigest()

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    h = sha256_hex(salt + password)
    return h, salt

def create_user(username, password, role="staff"):
    con = get_conn()
    cur = con.cursor()
    h, salt = hash_password(password)
    try:
        cur.execute("INSERT INTO users(username,pwd_hash,salt,role) VALUES(?,?,?,?)", (username, h, salt, role))
        con.commit()
    except sqlite3.IntegrityError:
        con.close()
        raise ValueError("Username exists")
    con.close()

def verify_user(username, password):
    con = get_conn()
    cur = con.cursor()
    cur.execute("SELECT pwd_hash, salt, role FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    con.close()
    if not row:
        return False, None
    stored_hash, salt, role = row
    h, _ = hash_password(password, salt)
    return (h == stored_hash), role

# ---------- token (JWT-like minimal) ----------
def encode_token(payload: dict) -> str:
    # payload: must include 'exp' (unix seconds)
    header = {"alg": "HS256", "typ": "JWT"}
    def b64(obj):
        j = json.dumps(obj, separators=(",", ":"), sort_keys=True)
        return base64.urlsafe_b64encode(j.encode()).rstrip(b"=").decode()
    header_b = b64(header)
    payload_b = b64(payload)
    sig = hmac.new(TOKEN_SECRET.encode(), f"{header_b}.{payload_b}".encode(), hashlib.sha256).digest()
    sig_b = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    return f"{header_b}.{payload_b}.{sig_b}"

def decode_token(token: str):
    try:
        header_b, payload_b, sig_b = token.split(".")
        sig_check = hmac.new(TOKEN_SECRET.encode(), f"{header_b}.{payload_b}".encode(), hashlib.sha256).digest()
        sig_check_b = base64.urlsafe_b64encode(sig_check).rstrip(b"=").decode()
        if not hmac.compare_digest(sig_check_b, sig_b):
            return None
        # decode payload
        padded = payload_b + "=" * (-len(payload_b) % 4)
        payload_json = base64.urlsafe_b64decode(padded.encode()).decode()
        payload = json.loads(payload_json)
        # check expiry
        if payload.get("exp", 0) < int(time.time()):
            return None
        return payload
    except Exception:
        return None

def token_for_user(username, role):
    payload = {"sub": username, "role": role, "exp": int(time.time()) + TOKEN_EXP_SECONDS}
    return encode_token(payload)

# ---------- rate limiter ----------
_rate_store = {}  # ip -> [timestamps]

def check_rate(ip):
    now = time.time()
    arr = _rate_store.get(ip, [])
    # drop older than window
    arr = [t for t in arr if t > now - RATE_LIMIT_WINDOW]
    if len(arr) >= RATE_LIMIT_MAX:
        _rate_store[ip] = arr
        return False
    arr.append(now)
    _rate_store[ip] = arr
    return True

# ---------- DB operations (students/fees/attendance) ----------
def students_all():
    con = get_conn(); cur = con.cursor()
    cur.execute("SELECT * FROM students ORDER BY id ASC"); rows = cur.fetchall(); con.close()
    return [dict(r) for r in rows]

def students_get(sid):
    con = get_conn(); cur = con.cursor()
    cur.execute("SELECT * FROM students WHERE id = ?", (sid,)); r = cur.fetchone(); con.close()
    return dict(r) if r else None

def students_add(data):
    con = get_conn(); cur = con.cursor()
    cur.execute("INSERT INTO students(first_name,last_name,roll,grade,phone,notes) VALUES(?,?,?,?,?,?)",
                (data.get("first_name"), data.get("last_name"), data.get("roll"), data.get("grade"), data.get("phone"), data.get("notes")))
    con.commit(); nid = cur.lastrowid; con.close()
    return nid

def students_update(sid, data):
    con = get_conn(); cur = con.cursor()
    cur.execute("""UPDATE students SET first_name=?, last_name=?, roll=?, grade=?, phone=?, notes=? WHERE id=?""",
                (data.get("first_name"), data.get("last_name"), data.get("roll"), data.get("grade"), data.get("phone"), data.get("notes"), sid))
    con.commit(); con.close()

def students_delete(sid):
    con = get_conn(); cur = con.cursor()
    cur.execute("DELETE FROM students WHERE id=?", (sid,))
    cur.execute("DELETE FROM fees WHERE student_id=?", (sid,))
    cur.execute("DELETE FROM attendance WHERE student_id=?", (sid,))
    con.commit(); con.close()

def fees_add(student_id, amount, note=""):
    con = get_conn(); cur = con.cursor()
    cur.execute("INSERT INTO fees(student_id,amount,paid,note,created_at) VALUES(?,?,?,?,?)",
                (student_id, float(amount), 0, note or "", datetime.utcnow().isoformat()))
    con.commit(); con.close()

def fees_list(student_id=None):
    con = get_conn(); cur = con.cursor()
    if student_id:
        cur.execute("SELECT f.id, f.student_id, s.first_name||' '||ifnull(s.last_name,'') as student_name, f.amount, f.paid, f.note, f.created_at FROM fees f JOIN students s ON s.id=f.student_id WHERE student_id=? ORDER BY f.id DESC", (student_id,))
    else:
        cur.execute("SELECT f.id, f.student_id, s.first_name||' '||ifnull(s.last_name,'') as student_name, f.amount, f.paid, f.note, f.created_at FROM fees f JOIN students s ON s.id=f.student_id ORDER BY f.id DESC")
    rows = cur.fetchall(); con.close()
    return [dict(r) for r in rows]

def fees_mark_paid(fid):
    con = get_conn(); cur = con.cursor()
    cur.execute("UPDATE fees SET paid=1 WHERE id=?", (fid,)); con.commit(); con.close()

def attendance_mark(student_id, att_date, status, note=""):
    con = get_conn(); cur = con.cursor()
    cur.execute("SELECT id FROM attendance WHERE student_id=? AND att_date=?", (student_id, att_date))
    r = cur.fetchone()
    if r:
        cur.execute("UPDATE attendance SET status=?, note=? WHERE id=?", (status, note or "", r[0]))
    else:
        cur.execute("INSERT INTO attendance(student_id,att_date,status,note) VALUES(?,?,?,?)", (student_id, att_date, status, note or ""))
    con.commit(); con.close()

def attendance_list(att_date):
    con = get_conn(); cur = con.cursor()
    cur.execute("""SELECT a.id, a.student_id, s.first_name||' '||ifnull(s.last_name,'') as student_name, s.roll, s.grade, a.status, a.note
                   FROM attendance a JOIN students s ON s.id=a.student_id WHERE a.att_date=? ORDER BY s.id""", (att_date,))
    rows = cur.fetchall(); con.close()
    return [dict(r) for r in rows]

# ---------- API Server ----------
def json_response(handler, data, code=200):
    s = json.dumps(data, default=str)
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json")
    # CORS
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Methods", "GET,POST,PATCH,DELETE,OPTIONS")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
    handler.end_headers()
    handler.wfile.write(s.encode())

class APIServer(BaseHTTPRequestHandler):
    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            raw = self.rfile.read(length).decode()
            try:
                return json.loads(raw)
            except:
                return parse_qs(raw)
        return {}

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,PATCH,DELETE,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self):
        ip = self.client_address[0]
        if not check_rate(ip):
            json_response(self, {"error": "rate_limited"}, 429); return

        path = urlparse(self.path)
        if path.path == "/":
            # API docs
            docs = {
                "routes": [
                    {"method": "POST", "path": "/api/login", "desc": "body: username,password -> token"},
                    {"method": "GET", "path": "/api/students", "desc": "list students (auth needed)"},
                    {"method": "POST", "path": "/api/students", "desc": "create student"},
                    {"method": "PATCH", "path": "/api/students/{id}", "desc": "update student"},
                    {"method": "DELETE", "path": "/api/students/{id}", "desc": "delete student"},
                    {"method": "GET", "path": "/api/fees", "desc": "list fees"},
                    {"method": "POST", "path": "/api/fees", "desc": "add fee"},
                    {"method": "POST", "path": "/api/fees/{id}/pay", "desc": "mark paid"},
                    {"method": "GET", "path": "/api/attendance?date=YYYY-MM-DD", "desc": "get attendance"}
                ]
            }
            json_response(self, docs); return

        if path.path.startswith("/api/students"):
            # must check token
            token = self.headers.get("Authorization", "").replace("Bearer ", "")
            payload = decode_token(token) if token else None
            if not payload:
                json_response(self, {"error": "unauthorized"}, 401); return
            # list
            rows = students_all()
            json_response(self, rows); return

        if path.path.startswith("/api/fees"):
            token = self.headers.get("Authorization", "").replace("Bearer ", "")
            payload = decode_token(token) if token else None
            if not payload:
                json_response(self, {"error": "unauthorized"}, 401); return
            q = parse_qs(path.query)
            sid = q.get("student_id", [None])[0]
            rows = fees_list(sid)
            json_response(self, rows); return

        if path.path.startswith("/api/attendance"):
            token = self.headers.get("Authorization", "").replace("Bearer ", "")
            payload = decode_token(token) if token else None
            if not payload:
                json_response(self, {"error": "unauthorized"}, 401); return
            q = parse_qs(path.query)
            att_date = q.get("date", [date.today().isoformat()])[0]
            rows = attendance_list(att_date)
            json_response(self, rows); return

        json_response(self, {"error": "not_found"}, 404)

    def do_POST(self):
        ip = self.client_address[0]
        if not check_rate(ip):
            json_response(self, {"error": "rate_limited"}, 429); return

        path = urlparse(self.path)
        data = self._read_json()

        if path.path == "/api/login":
            username = (data.get("username") or [""])[0] if isinstance(data, dict) and "username" not in data and isinstance(data, list) else data.get("username") if isinstance(data, dict) else None
            # Accept both JSON and form-parsed dict
            if isinstance(data, dict):
                username = data.get("username", "")
                password = data.get("password", "")
            else:
                username = ""
                password = ""
            ok, role = verify_user(username, password)
            if not ok:
                json_response(self, {"error": "invalid_credentials"}, 401); return
            token = token_for_user(username, role)
            json_response(self, {"token": token, "role": role})
            return

        # other routes require token
        token = self.headers.get("Authorization", "").replace("Bearer ", "")
        payload = decode_token(token) if token else None
        if not payload:
            json_response(self, {"error": "unauthorized"}, 401); return

        if path.path == "/api/students":
            # create
            if isinstance(data, dict):
                sid = students_add(data)
                json_response(self, {"id": sid}, 201); return
            json_response(self, {"error": "bad_request"}, 400); return

        if path.path == "/api/fees":
            try:
                student_id = int(data.get("student_id"))
                amount = float(data.get("amount"))
                note = data.get("note", "")
                fees_add(student_id, amount, note)
                json_response(self, {"status": "ok"})
            except Exception as e:
                json_response(self, {"error": "bad_request", "detail": str(e)}, 400)
            return

        if path.path.startswith("/api/fees/") and path.path.endswith("/pay"):
            # /api/fees/{id}/pay
            parts = path.path.strip("/").split("/")
            if len(parts) >= 3:
                fid = int(parts[1])
                fees_mark_paid(fid)
                json_response(self, {"status": "ok"})
                return

        if path.path == "/api/attendance":
            try:
                student_id = int(data.get("student_id"))
                att_date = data.get("date", date.today().isoformat())
                status = data.get("status", "present")
                note = data.get("note", "")
                attendance_mark(student_id, att_date, status, note)
                json_response(self, {"status": "ok"})
            except Exception as e:
                json_response(self, {"error": "bad_request", "detail": str(e)}, 400)
            return

        json_response(self, {"error": "not_found"}, 404)

# ---------- API Server thread ----------
def start_api_server():
    server = HTTPServer((API_HOST, API_PORT), APIServer)
    print(f"API listening at http://{API_HOST}:{API_PORT}")
    server.serve_forever()

# ---------- UI helpers (Material-ish) ----------
def rounded_rect(canvas, x1, y1, x2, y2, r=20, **kwargs):
    # draw rounded rectangle with four arcs
    points = [x1+r, y1, x2-r, y1, x2, y1, x2, y1+r, x2, y2-r, x2, y2, x2-r, y2, x1+r, y2, x1, y2, x1, y2-r, x1, y1+r, x1, y1]
    return canvas.create_polygon(points, smooth=True, **kwargs)

def draw_gradient(canvas, w, h, color1, color2):
    # vertical gradient
    steps = 100
    r1,g1,b1 = canvas.winfo_rgb(color1)
    r2,g2,b2 = canvas.winfo_rgb(color2)
    r1,g1,b1 = r1/256, g1/256, b1/256
    r2,g2,b2 = r2/256, g2/256, b2/256
    for i in range(steps):
        r = int(r1 + (r2-r1)*i/steps)
        g = int(g1 + (g2-g1)*i/steps)
        b = int(b1 + (b2-b1)*i/steps)
        color = f"#{r:02x}{g:02x}{b:02x}"
        y1 = int(h*i/steps)
        y2 = int(h*(i+1)/steps)
        canvas.create_rectangle(0,y1,w,y2, outline=color, fill=color)

# ---------- Main App (Tkinter) ----------
class MaterialApp:
    def __init__(self, root, username, role, token):
        self.root = root
        self.username = username
        self.role = role
        self.token = token
        self.root.title(f"Material School — {username} ({role})")
        self.root.geometry("1200x720")
        self.root.minsize(1000, 600)
        self.setup_style()
        self.build_ui()
        self.refresh_all()

    def setup_style(self):
        self.style = ttk.Style()
        try:
            self.style.theme_use('clam')
        except:
            pass
        self.style.configure('TButton', font=('Segoe UI', 10), padding=6)
        self.style.configure('TLabel', font=('Segoe UI', 10))
        self.style.configure('Header.TLabel', font=('Segoe UI', 18, 'bold'), foreground='white')
        self.style.configure('Card.TFrame', background='#ffffff', relief='flat')

    def build_ui(self):
        # top gradient header + user info
        top = Canvas(self.root, height=120, highlightthickness=0)
        top.pack(fill=X)
        w = 1200; h = 120
        draw_gradient(top, w, h, "#3b82f6", "#8b5cf6")
        # glass rectangle
        rounded_rect(top, 20, 20, w-20, h-20, r=18, fill="#ffffff", outline="", )
        top.create_text(60, 60, text="🏫 School Material Dashboard", anchor="w", font=("Segoe UI", 20, "bold"), fill="#0b1226")
        top.create_text(w-200, 60, text=f"User: {self.username} | Role: {self.role}", anchor="e", font=("Segoe UI", 10), fill="#0b1226")
        top.create_text(w-200, 90, text=f"API: http://{API_HOST}:{API_PORT}", anchor="e", font=("Segoe UI", 9), fill="#0b1226")

        # main frame
        main = Frame(self.root)
        main.pack(fill=BOTH, expand=1, padx=12, pady=12)

        # sidebar
        sidebar = Frame(main, width=220, bg="#0b1226")
        sidebar.pack(side=LEFT, fill=Y, padx=(0,12), pady=0)
        sidebar.pack_propagate(False)
        btn_cfg = {"font": ("Segoe UI", 11, "bold"), "fg": "white", "bg": "#111827", "bd":0, "activebackground": "#1f2937", "relief":FLAT}
        Label(sidebar, text="Menu", bg="#0b1226", fg="white", font=("Segoe UI", 12, "bold")).pack(pady=(12,8))
        self.btn_dashboard = Button(sidebar, text="Dashboard", command=self.show_dashboard, **btn_cfg)
        self.btn_students = Button(sidebar, text="Students", command=self.show_students, **btn_cfg)
        self.btn_fees = Button(sidebar, text="Fees", command=self.show_fees, **btn_cfg)
        self.btn_att = Button(sidebar, text="Attendance", command=self.show_attendance, **btn_cfg)
        self.btn_api = Button(sidebar, text="API Tester", command=self.show_api_tester, **btn_cfg)
        self.btn_dashboard.pack(fill=X, padx=10, pady=6)
        self.btn_students.pack(fill=X, padx=10, pady=6)
        self.btn_fees.pack(fill=X, padx=10, pady=6)
        self.btn_att.pack(fill=X, padx=10, pady=6)
        self.btn_api.pack(fill=X, padx=10, pady=6)
        if self.role == "admin":
            self.btn_users = Button(sidebar, text="Users", command=self.show_users, **btn_cfg)
            self.btn_users.pack(fill=X, padx=10, pady=6)

        # content area
        self.content = Frame(main, bg="#f3f4f6")
        self.content.pack(side=LEFT, fill=BOTH, expand=1)

        # panels (stacked; manage via lift)
        self.panel_dashboard = Frame(self.content, bg="#f3f4f6")
        self.panel_students = Frame(self.content, bg="#f3f4f6")
        self.panel_fees = Frame(self.content, bg="#f3f4f6")
        self.panel_att = Frame(self.content, bg="#f3f4f6")
        self.panel_api = Frame(self.content, bg="#f3f4f6")
        self.panel_users = Frame(self.content, bg="#f3f4f6")

        for p in (self.panel_dashboard, self.panel_students, self.panel_fees, self.panel_att, self.panel_api, self.panel_users):
            p.place(relx=0, rely=0, relwidth=1, relheight=1)

        self.build_dashboard()
        self.build_students_panel()
        self.build_fees_panel()
        self.build_att_panel()
        self.build_api_tester()
        self.build_users_panel()

        self.show_dashboard()

    # ---------- Panels ----------
    def build_dashboard(self):
        p = self.panel_dashboard
        # summary cards
        top_frame = Frame(p, bg="#f3f4f6")
        top_frame.pack(fill=X, padx=18, pady=12)
        self.card_students = self.make_card(top_frame, "Students", "0", "#06b6d4")
        self.card_fees_due = self.make_card(top_frame, "Pending Fees", "0", "#f97316")
        self.card_att_today = self.make_card(top_frame, "Attendance Today", "0", "#10b981")
        self.card_backup = self.make_card(top_frame, "Backup", "Ready", "#8b5cf6", action=self.backup_db)
        self.card_students.pack(side=LEFT, padx=8, ipadx=6, ipady=6)
        self.card_fees_due.pack(side=LEFT, padx=8)
        self.card_att_today.pack(side=LEFT, padx=8)
        self.card_backup.pack(side=LEFT, padx=8)

        # charts area
        chart_frame = Frame(p, bg="#f3f4f6")
        chart_frame.pack(fill=BOTH, expand=1, padx=18, pady=6)
        # left chart - fees trend
        left = Frame(chart_frame, bg="#ffffff", bd=0, relief=FLAT)
        left.pack(side=LEFT, fill=BOTH, expand=1, padx=6, pady=6)
        Label(left, text="Fees Collected (last 12 entries)", font=("Segoe UI", 11, "bold"), bg="#ffffff").pack(anchor="w", padx=8, pady=6)
        self.canvas_fees = Canvas(left, height=220, bg="#ffffff", highlightthickness=0)
        self.canvas_fees.pack(fill=X, padx=8, pady=8)
        # right chart - attendance
        right = Frame(chart_frame, bg="#ffffff", bd=0)
        right.pack(side=LEFT, fill=BOTH, expand=1, padx=6, pady=6)
        Label(right, text="Attendance Snapshot (Today)", font=("Segoe UI", 11, "bold"), bg="#ffffff").pack(anchor="w", padx=8, pady=6)
        self.canvas_att = Canvas(right, height=220, bg="#ffffff", highlightthickness=0)
        self.canvas_att.pack(fill=X, padx=8, pady=8)

    def make_card(self, parent, title, value, color, action=None):
        f = Frame(parent, bg="white", bd=0, relief=FLAT)
        Label(f, text=title, font=("Segoe UI", 10), bg="white").pack(anchor="w", padx=10, pady=(10,0))
        lbl = Label(f, text=value, font=("Segoe UI", 20, "bold"), bg="white", fg=color)
        lbl.pack(anchor="w", padx=10, pady=(6,12))
        if action:
            Button(f, text="Run", command=action).pack(anchor="e", padx=10, pady=(0,10))
        return f

    def build_students_panel(self):
        p = self.panel_students
        # top form
        form = Frame(p, bg="#f3f4f6")
        form.pack(fill=X, padx=18, pady=12)
        Label(form, text="First name").grid(row=0, column=0, sticky=W)
        self.i_first = Entry(form); self.i_first.grid(row=0, column=1, padx=6, pady=4)
        Label(form, text="Last name").grid(row=0, column=2, sticky=W)
        self.i_last = Entry(form); self.i_last.grid(row=0, column=3, padx=6, pady=4)
        Label(form, text="Roll").grid(row=1, column=0, sticky=W)
        self.i_roll = Entry(form); self.i_roll.grid(row=1, column=1, padx=6, pady=4)
        Label(form, text="Grade").grid(row=1, column=2, sticky=W)
        self.i_grade = Entry(form); self.i_grade.grid(row=1, column=3, padx=6, pady=4)
        Label(form, text="Phone").grid(row=2, column=0, sticky=W)
        self.i_phone = Entry(form); self.i_phone.grid(row=2, column=1, padx=6, pady=4)
        Label(form, text="Notes").grid(row=2, column=2, sticky=W)
        self.i_notes = Entry(form); self.i_notes.grid(row=2, column=3, padx=6, pady=4)
        Button(form, text="Add Student", command=self.ui_add_student).grid(row=3, column=1, pady=8)
        Button(form, text="Update Selected", command=self.ui_update_student).grid(row=3, column=2, pady=8)
        Button(form, text="Delete Selected", command=self.ui_delete_student).grid(row=3, column=3, pady=8)
        Button(form, text="Import CSV", command=self.import_students).grid(row=3, column=0, pady=8)

        # search and table
        search_frame = Frame(p, bg="#f3f4f6")
        search_frame.pack(fill=X, padx=18)
        Label(search_frame, text="Search").pack(side=LEFT)
        self.search_var = StringVar()
        Entry(search_frame, textvariable=self.search_var).pack(side=LEFT, padx=6)
        Button(search_frame, text="Go", command=self.search_students).pack(side=LEFT, padx=6)
        Button(search_frame, text="Export CSV", command=self.export_students).pack(side=LEFT, padx=6)

        table_frame = Frame(p, bg="#f3f4f6")
        table_frame.pack(fill=BOTH, expand=1, padx=18, pady=12)
        cols = ("id","first_name","last_name","roll","grade","phone")
        self.tree_students = ttk.Treeview(table_frame, columns=cols, show="headings")
        for c in cols:
            self.tree_students.heading(c, text=c.replace("_"," ").title())
            self.tree_students.column(c, width=120)
        self.tree_students.pack(fill=BOTH, expand=1)
        self.tree_students.bind("<<TreeviewSelect>>", self.on_student_select)

    def build_fees_panel(self):
        p = self.panel_fees
        top = Frame(p, bg="#f3f4f6"); top.pack(fill=X, padx=18, pady=12)
        Label(top, text="Student ID").pack(side=LEFT); self.f_sid = Entry(top, width=8); self.f_sid.pack(side=LEFT, padx=6)
        Label(top, text="Amount").pack(side=LEFT); self.f_amt = Entry(top, width=10); self.f_amt.pack(side=LEFT, padx=6)
        Label(top, text="Note").pack(side=LEFT); self.f_note = Entry(top, width=20); self.f_note.pack(side=LEFT, padx=6)
        Button(top, text="Add Fee", command=self.ui_add_fee).pack(side=LEFT, padx=6)
        Button(top, text="Mark Paid", command=self.ui_mark_fee_paid).pack(side=LEFT, padx=6)
        Button(top, text="Export Fees", command=self.export_fees).pack(side=LEFT, padx=6)

        table_frame = Frame(p, bg="#f3f4f6"); table_frame.pack(fill=BOTH, expand=1, padx=18, pady=12)
        cols = ("id","student_id","student_name","amount","paid","note","created_at")
        self.tree_fees = ttk.Treeview(table_frame, columns=cols, show="headings")
        for c in cols:
            self.tree_fees.heading(c, text=c.replace("_"," ").title())
            self.tree_fees.column(c, width=120)
        self.tree_fees.pack(fill=BOTH, expand=1)

    def build_att_panel(self):
        p = self.panel_att
        top = Frame(p, bg="#f3f4f6"); top.pack(fill=X, padx=18, pady=12)
        Label(top, text="Date").pack(side=LEFT); self.att_date = Entry(top, width=12); self.att_date.pack(side=LEFT, padx=6); self.att_date.insert(0, date.today().isoformat())
        Button(top, text="Load", command=self.ui_load_attendance).pack(side=LEFT, padx=6)
        Button(top, text="Export", command=self.export_attendance).pack(side=LEFT, padx=6)

        mid = Frame(p, bg="#f3f4f6"); mid.pack(fill=X, padx=18, pady=6)
        Label(mid, text="Student ID").pack(side=LEFT); self.att_sid = Entry(mid, width=8); self.att_sid.pack(side=LEFT, padx=6)
        Button(mid, text="Present", command=lambda: self.ui_mark_att("present")).pack(side=LEFT, padx=6)
        Button(mid, text="Absent", command=lambda: self.ui_mark_att("absent")).pack(side=LEFT, padx=6)
        Label(mid, text="Note").pack(side=LEFT); self.att_note = Entry(mid, width=30); self.att_note.pack(side=LEFT, padx=6)

        table_frame = Frame(p, bg="#f3f4f6"); table_frame.pack(fill=BOTH, expand=1, padx=18, pady=12)
        cols = ("id","student_id","student_name","roll","grade","status","note")
        self.tree_att = ttk.Treeview(table_frame, columns=cols, show="headings")
        for c in cols:
            self.tree_att.heading(c, text=c.replace("_"," ").title())
            self.tree_att.column(c, width=120)
        self.tree_att.pack(fill=BOTH, expand=1)

    def build_api_tester(self):
        p = self.panel_api
        top = Frame(p, bg="#f3f4f6"); top.pack(fill=X, padx=18, pady=12)
        Label(top, text="Endpoint").pack(side=LEFT); self.api_endpoint = Entry(top, width=60); self.api_endpoint.pack(side=LEFT, padx=6); self.api_endpoint.insert(0, f"http://{API_HOST}:{API_PORT}/api/students")
        Label(top, text="Method").pack(side=LEFT); self.api_method = ttk.Combobox(top, values=["GET","POST","PATCH","DELETE"], width=6); self.api_method.set("GET"); self.api_method.pack(side=LEFT, padx=6)
        Button(top, text="Send", command=self.api_send).pack(side=LEFT, padx=6)
        self.api_result = Text(p, height=20)
        self.api_result.pack(fill=BOTH, expand=1, padx=18, pady=12)

    def build_users_panel(self):
        p = self.panel_users
        top = Frame(p, bg="#f3f4f6"); top.pack(fill=X, padx=18, pady=12)
        Button(top, text="Create User", command=self.ui_create_user).pack(side=LEFT, padx=6)
        Button(top, text="List Users", command=self.ui_list_users).pack(side=LEFT, padx=6)

    # ---------- UI actions ----------
    def show_dashboard(self):
        self.panel_dashboard.lift()
        self.refresh_all()

    def show_students(self):
        self.panel_students.lift()
        self.refresh_all()

    def show_fees(self):
        self.panel_fees.lift()
        self.refresh_all()

    def show_attendance(self):
        self.panel_att.lift()
        self.refresh_all()

    def show_api_tester(self):
        self.panel_api.lift()

    def show_users(self):
        self.panel_users.lift()

    def refresh_all(self):
        self.refresh_cards()
        self.refresh_students_table()
        self.refresh_fees_table()
        self.ui_load_attendance()
        self.redraw_charts()

    def refresh_cards(self):
        st = students_all()
        self.card_students.children.get('!label', None)
        # update card values
        # brute-force: recreate cards? Simpler: update labels inside frames
        # We'll set text on the second child (index 1)
        try:
            self.card_students.children[list(self.card_students.children.keys())[1]].config(text=str(len(st)))
        except Exception:
            pass
        # pending fees
        fees = fees_list()
        pending = sum(f["amount"] for f in fees if not f["paid"])
        try:
            self.card_fees_due.children[list(self.card_fees_due.children.keys())[1]].config(text=f"{pending:.2f}")
        except Exception:
            pass
        # attendance today
        att = attendance_list(date.today().isoformat())
        present = sum(1 for a in att if a["status"] == "present")
        try:
            self.card_att_today.children[list(self.card_att_today.children.keys())[1]].config(text=str(present))
        except Exception:
            pass

    def refresh_students_table(self):
        for i in self.tree_students.get_children():
            self.tree_students.delete(i)
        for s in students_all():
            self.tree_students.insert("", END, values=(s["id"], s["first_name"], s["last_name"], s["roll"], s["grade"], s["phone"]))

    def refresh_fees_table(self):
        for i in self.tree_fees.get_children():
            self.tree_fees.delete(i)
        for f in fees_list():
            self.tree_fees.insert("", END, values=(f["id"], f["student_id"], f["student_name"], f["amount"], "Yes" if f["paid"] else "No", f["note"], f["created_at"]))

    def ui_add_student(self):
        data = {
            "first_name": self.i_first.get().strip(),
            "last_name": self.i_last.get().strip(),
            "roll": self.i_roll.get().strip(),
            "grade": self.i_grade.get().strip(),
            "phone": self.i_phone.get().strip(),
            "notes": self.i_notes.get().strip()
        }
        if not data["first_name"]:
            messagebox.showwarning("Validation","First name required"); return
        students_add(data)
        messagebox.showinfo("Saved","Student added")
        self.clear_student_inputs()
        self.refresh_all()

    def ui_update_student(self):
        sel = self.tree_students.selection()
        if not sel: messagebox.showwarning("Select","Select a student"); return
        sid = int(self.tree_students.item(sel[0])["values"][0])
        data = {
            "first_name": self.i_first.get().strip(),
            "last_name": self.i_last.get().strip(),
            "roll": self.i_roll.get().strip(),
            "grade": self.i_grade.get().strip(),
            "phone": self.i_phone.get().strip(),
            "notes": self.i_notes.get().strip()
        }
        students_update(sid, data)
        messagebox.showinfo("Updated","Student updated")
        self.clear_student_inputs()
        self.refresh_all()

    def ui_delete_student(self):
        sel = self.tree_students.selection()
        if not sel: messagebox.showwarning("Select","Select a student"); return
        sid = int(self.tree_students.item(sel[0])["values"][0])
        if not messagebox.askyesno("Confirm","Delete student?"): return
        students_delete(sid)
        messagebox.showinfo("Deleted","Student deleted")
        self.refresh_all()

    def on_student_select(self, e):
        sel = self.tree_students.selection()
        if not sel: return
        vals = self.tree_students.item(sel[0])["values"]
        self.i_first.delete(0,END); self.i_first.insert(0, vals[1])
        self.i_last.delete(0,END); self.i_last.insert(0, vals[2])
        self.i_roll.delete(0,END); self.i_roll.insert(0, vals[3])
        self.i_grade.delete(0,END); self.i_grade.insert(0, vals[4])
        self.i_phone.delete(0,END); self.i_phone.insert(0, vals[5])

    def clear_student_inputs(self):
        self.i_first.delete(0,END); self.i_last.delete(0,END); self.i_roll.delete(0,END); self.i_grade.delete(0,END); self.i_phone.delete(0,END); self.i_notes.delete(0,END)

    def import_students(self):
        path = filedialog.askopenfilename(filetypes=[("CSV files","*.csv")])
        if not path: return
        with open(path, newline='', encoding='utf-8') as f:
            r = csv.DictReader(f)
            count = 0
            for row in r:
                students_add({
                    "first_name": row.get("first_name") or row.get("first") or row.get("name") or "",
                    "last_name": row.get("last_name") or "",
                    "roll": row.get("roll") or "",
                    "grade": row.get("grade") or "",
                    "phone": row.get("phone") or "",
                    "notes": row.get("notes") or ""
                })
                count += 1
        messagebox.showinfo("Imported", f"Imported {count} students")
        self.refresh_all()

    def export_students(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv")
        if not path: return
        rows = students_all()
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f); w.writerow(["id","first_name","last_name","roll","grade","phone","notes"])
            for r in rows:
                w.writerow([r["id"], r["first_name"], r["last_name"], r["roll"], r["grade"], r["phone"], r["notes"]])
        messagebox.showinfo("Exported", f"Exported {len(rows)} students")

    def ui_add_fee(self):
        sid = self.f_sid.get().strip()
        amt = self.f_amt.get().strip()
        if not sid.isdigit():
            messagebox.showwarning("Validation","Student ID numeric"); return
        try:
            amtf = float(amt)
        except:
            messagebox.showwarning("Validation","Amount numeric"); return
        fees_add(int(sid), amtf, self.f_note.get().strip())
        messagebox.showinfo("Saved","Fee added"); self.f_sid.delete(0,END); self.f_amt.delete(0,END); self.f_note.delete(0,END)
        self.refresh_all()

    def ui_mark_fee_paid(self):
        sel = self.tree_fees.selection()
        if not sel: messagebox.showwarning("Select","Select a fee"); return
        fid = int(self.tree_fees.item(sel[0])["values"][0])
        fees_mark_paid(fid)
        messagebox.showinfo("Updated","Marked paid"); self.refresh_all()

    def ui_load_attendance(self):
        ad = self.att_date.get().strip() or date.today().isoformat()
        try:
            datetime.fromisoformat(ad)
        except:
            messagebox.showwarning("Validation","Date must be YYYY-MM-DD"); return
        rows = attendance_list(ad)
        for i in self.tree_att.get_children(): self.tree_att.delete(i)
        for r in rows: self.tree_att.insert("", END, values=(r["id"], r["student_id"], r["student_name"], r["roll"], r["grade"], r["status"], r["note"]))
        # also refresh cards
        self.refresh_cards()

    def ui_mark_att(self, status):
        sid = self.att_sid.get().strip()
        if not sid.isdigit(): messagebox.showwarning("Validation","Student ID numeric"); return
        ad = self.att_date.get().strip() or date.today().isoformat()
        attendance_mark(int(sid), ad, status, self.att_note.get().strip())
        messagebox.showinfo("Saved", f"Marked {status}")
        self.att_sid.delete(0,END); self.att_note.delete(0,END)
        self.ui_load_attendance()

    def export_fees(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv")
        if not path: return
        rows = fees_list()
        with open(path,"w",newline="",encoding="utf-8") as f:
            w = csv.writer(f); w.writerow(["id","student_id","student_name","amount","paid","note","created_at"]); w.writerows([[r["id"],r["student_id"],r["student_name"],r["amount"],r["paid"],r["note"],r["created_at"]] for r in rows])
        messagebox.showinfo("Exported","Fees exported")

    def export_attendance(self):
        ad = self.att_date.get().strip()
        if not ad: messagebox.showwarning("Validation","Date required"); return
        rows = attendance_list(ad)
        if not rows: messagebox.showinfo("Empty","No data"); return
        path = filedialog.asksaveasfilename(defaultextension=".csv")
        if not path: return
        with open(path,"w",newline="",encoding="utf-8") as f:
            w = csv.writer(f); w.writerow(["id","student_id","student_name","roll","grade","status","note"]); w.writerows([[r["id"],r["student_id"],r["student_name"],r["roll"],r["grade"],r["status"],r["note"]] for r in rows])
        messagebox.showinfo("Exported","Attendance exported")

    def ui_create_user(self):
        u = simpledialog.askstring("Username","Username"); 
        if not u: return
        p = simpledialog.askstring("Password","Password", show="*"); 
        if not p: return
        role = simpledialog.askstring("Role","admin or staff", initialvalue="staff")
        try:
            create_user(u.strip(), p, role.strip() if role else "staff"); messagebox.showinfo("Created","User created")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def ui_list_users(self):
        con = get_conn(); cur = con.cursor()
        cur.execute("SELECT id,username,role FROM users ORDER BY id"); rows = cur.fetchall(); con.close()
        txt = "\n".join([f"{r['id']} | {r['username']} | {r['role']}" for r in rows])
        messagebox.showinfo("Users", txt or "No users")

    def search_students(self):
        q = self.search_var.get().strip().lower()
        for i in self.tree_students.get_children(): self.tree_students.delete(i)
        rows = students_all()
        for s in rows:
            hay = f"{s['first_name']} {s['last_name']} {s['roll']} {s['grade']} {s['phone']}".lower()
            if q in hay:
                self.tree_students.insert("", END, values=(s["id"], s["first_name"], s["last_name"], s["roll"], s["grade"], s["phone"]))

    def api_send(self):
        import urllib.request, urllib.error
        method = self.api_method.get()
        url = self.api_endpoint.get()
        headers = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}
        body = None
        # for POST allow user to input JSON in api_result? For brevity, we'll use empty body
        req = urllib.request.Request(url, method=method, headers=headers, data=body.encode() if body else None)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                out = resp.read().decode()
                self.api_result.delete(1.0, END)
                self.api_result.insert(END, out)
        except Exception as e:
            self.api_result.delete(1.0, END); self.api_result.insert(END, str(e))

    def backup_db(self):
        # simple file copy
        src = DB_FILE
        ts = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        dst = f"backup_{ts}.db"
        try:
            with open(src, "rb") as fr, open(dst, "wb") as fw:
                fw.write(fr.read())
            messagebox.showinfo("Backup", f"Backup saved as {dst}")
        except Exception as e:
            messagebox.showerror("Backup failed", str(e))

    # ---------- charts ----------
    def redraw_charts(self):
        # fees - last 12 fee entries - line chart
        fees = fees_list()[:12]
        self.canvas_fees.delete("all")
        if fees:
            w = int(self.canvas_fees.winfo_width() or 800)
            h = int(self.canvas_fees.winfo_height() or 220)
            maxv = max((f["amount"] for f in fees), default=1)
            pad = 30
            stepx = (w - 2*pad) / max(1, len(fees)-1)
            points = []
            for i,f in enumerate(reversed(fees)):
                x = pad + i * stepx
                y = h - pad - (f["amount"]/maxv)*(h - 2*pad)
                points.append((x,y,f["amount"]))
            # lines
            for i in range(len(points)-1):
                x1,y1,_ = points[i]; x2,y2,_ = points[i+1]
                self.canvas_fees.create_line(x1,y1,x2,y2, fill="#3b82f6", width=3, smooth=True)
            # dots
            for x,y,val in points:
                self.canvas_fees.create_oval(x-4,y-4,x+4,y+4, fill="#06b6d4", outline="")
                self.canvas_fees.create_text(x,y-10, text=f"{val:.0f}", font=("Segoe UI",8))
        else:
            self.canvas_fees.create_text(200,100,text="No fees data", font=("Segoe UI",12), fill="#777")

        # attendance donut-ish (present vs absent)
        att = attendance_list(date.today().isoformat())
        total = max(1, len(att))
        present = sum(1 for a in att if a["status"] == "present")
        absent = total - present
        self.canvas_att.delete("all")
        w = int(self.canvas_att.winfo_width() or 600)
        h = int(self.canvas_att.winfo_height() or 220)
        cx, cy, r = w//2, h//2, min(w,h)//3
        ang1 = 0
        if present:
            angp = int(360 * present / total)
            self.canvas_att.create_arc(cx-r, cy-r, cx+r, cy+r, start=ang1, extent=angp, fill="#10b981", outline="")
            ang1 += angp
        if absent:
            self.canvas_att.create_arc(cx-r, cy-r, cx+r, cy+r, start=ang1, extent=360-ang1, fill="#ef4444", outline="")
        self.canvas_att.create_text(cx, cy, text=f"P {present} / T {total}", font=("Segoe UI", 14, "bold"))

# ---------- startup ----------
def start_ui():
    # login dialog
    root = Tk()
    root.withdraw()
    ld = LoginDialog(root)
    creds = ld.result
    if not creds:
        root.destroy(); return
    username, password = creds
    ok, role = verify_user(username, password)
    if not ok:
        messagebox.showerror("Login failed", "Invalid credentials")
        root.destroy(); return
    token = token_for_user(username, role)
    root.deiconify()
    app = MaterialApp(root, username, role, token)
    root.mainloop()

# ---------- Login dialog ----------
class LoginDialog(simpledialog.Dialog):
    def body(self, master):
        self.title("Login — Material School")
        Label(master, text="Username").grid(row=0, column=0, pady=6)
        Label(master, text="Password").grid(row=1, column=0, pady=6)
        self.e_user = Entry(master)
        self.e_pass = Entry(master, show="*")
        self.e_user.grid(row=0, column=1, padx=6)
        self.e_pass.grid(row=1, column=1, padx=6)
        return self.e_user
    def apply(self):
        self.result = (self.e_user.get().strip(), self.e_pass.get())

# ---------- main ----------
if __name__ == "__main__":
    # init DB + start API thread + UI
    init_db()
    t = threading.Thread(target=start_api_server, daemon=True)
    t.start()
    start_ui()
