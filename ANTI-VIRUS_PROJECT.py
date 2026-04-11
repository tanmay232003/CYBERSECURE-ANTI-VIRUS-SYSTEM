#!/usr/bin/env python3


import os
import sqlite3
import hashlib
import json
import time
from datetime import datetime, date
from flask import Flask, g, render_template_string, request, redirect, url_for, session, jsonify, Response
from werkzeug.security import generate_password_hash, check_password_hash

# -------------------- Config --------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, 'antivirus.db')
SECRET_KEY = os.environ.get('ANTIVIRUS_SECRET') or 'dev-secret-key-please-change'

app = Flask(__name__)
app.secret_key = SECRET_KEY

# -------------------- DB helpers --------------------
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = sqlite3.connect(DATABASE, check_same_thread=False)
        db.row_factory = sqlite3.Row
        g._database = db
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        try:
            db.close()
        except Exception:
            pass

def ensure_schema_compatibility(db_conn):
    try:
        c = db_conn.cursor()
        c.execute("PRAGMA table_info(users)")
        cols = [row[1] for row in c.fetchall()]
        if 'email' not in cols:
            c.execute("ALTER TABLE users ADD COLUMN email TEXT")
        if 'auto_update' not in cols:
            c.execute("ALTER TABLE users ADD COLUMN auto_update INTEGER DEFAULT 1")
        if 'notifications' not in cols:
            c.execute("ALTER TABLE users ADD COLUMN notifications INTEGER DEFAULT 1")
        if 'theme' not in cols:
            c.execute("ALTER TABLE users ADD COLUMN theme TEXT")
        if 'reminder_days' not in cols:
            c.execute("ALTER TABLE users ADD COLUMN reminder_days INTEGER DEFAULT 7")
        c.execute("PRAGMA table_info(user_meta)")
        cols_meta = [row[1] for row in c.fetchall()]
        if 'threats_day_date' not in cols_meta:
            c.execute("ALTER TABLE user_meta ADD COLUMN threats_day_date TEXT")
        if 'threats_today' not in cols_meta:
            c.execute("ALTER TABLE user_meta ADD COLUMN threats_today INTEGER DEFAULT 0")
        db_conn.commit()
    except Exception:
        db_conn.rollback()

def init_db():
    with app.app_context():
        db = get_db()
        c = db.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            auto_update INTEGER DEFAULT 1,
            notifications INTEGER DEFAULT 1,
            theme TEXT,
            reminder_days INTEGER DEFAULT 7
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS user_meta (
            user_id INTEGER PRIMARY KEY,
            last_scan TEXT,
            threats_day_date TEXT,
            threats_today INTEGER DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS quarantine (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            filename TEXT,
            date TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS signatures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sha256 TEXT UNIQUE,
            note TEXT
        )''')
        db.commit()
        ensure_schema_compatibility(db)

init_db()

# -------------------- Utility --------------------
def sha256_file(path, block_size=65536):
    h = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            for b in iter(lambda: f.read(block_size), b''):
                h.update(b)
        return h.hexdigest()
    except Exception:
        return None

def row_to_dict(row):
    return dict(row) if row is not None else None

# -------------------- Auth helpers --------------------
def create_user(username, password, email=None):
    db = get_db(); c = db.cursor()
    try:
        c.execute('INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)',
                  (username, generate_password_hash(password), email))
        user_id = c.lastrowid
        c.execute('INSERT OR REPLACE INTO user_meta (user_id, threats_day_date, threats_today) VALUES (?, ?, ?)',
                  (user_id, date.today().isoformat(), 0))
        db.commit()
        return True, None
    except sqlite3.IntegrityError:
        return False, 'Username already taken.'
    except Exception as e:
        db.rollback()
        return False, str(e)

def get_user_by_username(username):
    db = get_db(); c = db.cursor()
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    return row_to_dict(c.fetchone())

def get_user_by_id(uid):
    db = get_db(); c = db.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (uid,))
    return row_to_dict(c.fetchone())

# -------------------- Templates --------------------
# Cyber neon login page (Option A) with hacker grid
LOGIN_TEMPLATE = '''
<!doctype html>
<html>
<head>
<title>Login - CyberSecure Antivirus</title>
<style>
  body{
      margin:0;
      font-family: Arial, sans-serif;
      background:#05070e;
      color:#ffffff;
      display:flex;
      justify-content:center;
      align-items:center;
      height:100vh;
      overflow:hidden;
  }
  .grid{
      position:fixed;
      top:0; left:0;
      width:100%; height:100%;
      background:
        linear-gradient(0deg, rgba(0,255,255,0.12) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0,255,255,0.1) 1px, transparent 1px);
      background-size:40px 40px;
      animation:gridmove 12s linear infinite;
      opacity:0.28;
      z-index:-1;
  }
  @keyframes gridmove{
      from{ background-position:0 0; }
      to{ background-position:0 80px; }
  }
  .card{
      background: rgba(9,15,32,0.9);
      padding: 32px 34px;
      border-radius: 16px;
      width: 360px;
      backdrop-filter: blur(10px);
      box-shadow: 0 0 30px rgba(0,255,255,0.18);
      border: 1px solid rgba(0,255,255,0.25);
  }
  h2{
      text-align:center;
      margin-bottom:22px;
      font-size:26px;
      letter-spacing:1px;
  }
  .icon-lock{
      font-size:34px;
      text-align:center;
      margin-bottom:6px;
      color:#00eaff;
  }
  label{
      font-size:14px;
  }
  input{
      width:100%;
      padding:10px;
      margin:6px 0 18px;
      border-radius:6px;
      border:1px solid #00eaff;
      background:#07101f;
      color:#ffffff;
      outline:none;
  }
  input:focus{
      box-shadow:0 0 10px #00eaff;
  }
  button{
      width:100%;
      padding:12px;
      border:none;
      background:#00eaff;
      color:#000;
      border-radius:6px;
      font-weight:bold;
      cursor:pointer;
      transition:0.25s;
  }
  button:hover{
      background:#00bcd4;
      box-shadow:0 0 14px #00eaff;
  }
  a{
      color:#00eaff;
      text-decoration:none;
  }
  a:hover{
      text-decoration:underline;
  }
  .error{
      color:#ff6b6b;
      margin-top:12px;
      text-align:center;
      font-size:14px;
  }
  .bottom-text{
      margin-top:12px;
      text-align:center;
      font-size:14px;
      color:#a7b7c9;
  }
</style>
</head>
<body>
<div class="grid"></div>
<div class="card">
    <div class="icon-lock">🔐</div>
    <h2>CyberSecure Login</h2>
    <form method="post">
        <label>Username</label>
        <input name="username" required>

        <label>Password</label>
        <input type="password" name="password" required>

        <button type="submit">Login</button>
    </form>
    <div class="bottom-text">
        Don't have an account?
        <a href="{{ url_for('signup') }}">Sign up</a>
    </div>
    {% if error %}
    <div class="error">{{ error }}</div>
    {% endif %}
</div>
</body>
</html>
'''

# Cyber neon signup page (Option A) with hacker grid
SIGNUP_TEMPLATE = '''
<!doctype html>
<html>
<head>
<title>Signup - CyberSecure Antivirus</title>
<style>
  body{
      margin:0;
      font-family: Arial, sans-serif;
      background:#05070e;
      color:#ffffff;
      display:flex;
      justify-content:center;
      align-items:center;
      height:100vh;
      overflow:hidden;
  }
  .grid{
      position:fixed;
      top:0; left:0;
      width:100%; height:100%;
      background:
        linear-gradient(0deg, rgba(0,255,255,0.12) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0,255,255,0.1) 1px, transparent 1px);
      background-size:40px 40px;
      animation:gridmove 12s linear infinite;
      opacity:0.28;
      z-index:-1;
  }
  @keyframes gridmove{
      from{ background-position:0 0; }
      to{ background-position:0 80px; }
  }
  .card{
      background: rgba(9,15,32,0.9);
      padding: 32px 34px;
      border-radius: 16px;
      width: 380px;
      backdrop-filter: blur(10px);
      box-shadow: 0 0 30px rgba(0,255,255,0.18);
      border: 1px solid rgba(0,255,255,0.25);
  }
  h2{
      text-align:center;
      margin-bottom:22px;
      font-size:26px;
      letter-spacing:1px;
  }
  .icon-shield{
      font-size:34px;
      text-align:center;
      margin-bottom:6px;
      color:#00eaff;
  }
  label{
      font-size:14px;
  }
  input{
      width:100%;
      padding:10px;
      margin:6px 0 18px;
      border-radius:6px;
      border:1px solid #00eaff;
      background:#07101f;
      color:#ffffff;
      outline:none;
  }
  input:focus{
      box-shadow:0 0 10px #00eaff;
  }
  button{
      width:100%;
      padding:12px;
      border:none;
      background:#00eaff;
      color:#000;
      border-radius:6px;
      font-weight:bold;
      cursor:pointer;
      transition:0.25s;
  }
  button:hover{
      background:#00bcd4;
      box-shadow:0 0 14px #00eaff;
  }
  a{
      color:#00eaff;
      text-decoration:none;
  }
  a:hover{
      text-decoration:underline;
  }
  .error{
      color:#ff6b6b;
      margin-top:12px;
      text-align:center;
      font-size:14px;
  }
  .bottom-text{
      margin-top:12px;
      text-align:center;
      font-size:14px;
      color:#a7b7c9;
  }
</style>
</head>
<body>
<div class="grid"></div>
<div class="card">
    <div class="icon-shield">🛡️</div>
    <h2>Create Cyber Account</h2>
    <form method="post">
        <label>Username</label>
        <input name="username" required>

        <label>Email</label>
        <input name="email" type="email" required>

        <label>Password</label>
        <input type="password" name="password" required>

        <label>Confirm Password</label>
        <input type="password" name="confirm" required>

        <button type="submit">Sign Up</button>
    </form>
    <div class="bottom-text">
        Already have an account?
        <a href="{{ url_for('login') }}">Login</a>
    </div>
    {% if error %}
    <div class="error">{{ error }}</div>
    {% endif %}
</div>
</body>
</html>
'''

# Main app template with hacker grid + radar loader + animations
APP_TEMPLATE = '''
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Antivirus</title>
  <style>
    :root { --bg:#05070e; --card:#0a101c; --text:#dff9ff; --nav:#0f1620; --accent:#00eaff; }
    body.light { --bg:#05070e; --card:#0a101c; --text:#dff9ff; --nav:#0f1620; --accent:#00eaff; }
    body.dark  { --bg:#05070e; --card:#0a101c; --text:#dff9ff; --nav:#0f1620; --accent:#00eaff; }

    /* NEW THEMES */

    body.purple {
        --bg: #0d0014;
        --card: #1a0026;
        --text: #e6ccff;
        --nav: #240033;
        --accent: #b300ff;
    }

    body.green {
        --bg: #001a08;
        --card: #003311;
        --text: #ccffdd;
        --nav: #004d1a;
        --accent: #00ff66;
    }

    body.gold {
        --bg: #1f1500;
        --card: #332000;
        --text: #ffe6b3;
        --nav: #4d3000;
        --accent: #ffcc00;
    }

    body{
      font-family:Arial,Helvetica,sans-serif;
      background:var(--bg);
      color:var(--text);
      margin:0;
    }

    header{
      background:var(--nav);
      color:#fff;
      padding:1rem;
      text-align:center;
      position:relative;
      box-shadow:0 0 18px rgba(0,0,0,0.7);
    }
    .top-right{
      position:absolute;
      right:1rem;
      top:1rem;
      font-size:0.9rem;
    }

    nav{
      display:flex;
      background:var(--nav);
      box-shadow:0 4px 18px rgba(0,0,0,0.8);
      position:relative;
      z-index:2;
    }
    nav a{
      flex:1;
      padding:0.9rem;
      text-align:center;
      color:#00eaff;
      font-weight:bold;
      text-decoration:none;
      border-right:1px solid rgba(0,255,255,0.15);
      transition:0.3s;
      position:relative;
      overflow:hidden;
    }
    nav a:last-child{
      border-right:none;
    }
    nav a:hover{
      background:rgba(0,255,255,0.12);
    }
    nav a.active{
      background:rgba(0,255,255,0.22);
      box-shadow:0 0 14px #00eaff;
    }
    nav a::after{
      content:"";
      position:absolute;
      left:50%;
      bottom:0;
      width:0%;
      height:3px;
      background:var(--accent);
      transform:translateX(-50%);
      transition:0.35s;
    }
    nav a:hover::after,
    nav a.active::after{
      width:80%;
      box-shadow:0 0 15px var(--accent);
    }

    main{
      padding:1.2rem;
      position:relative;
      z-index:1;
    }

    /* Page transition animation */
    .page{
      opacity:0;
      transform:translateY(12px);
      transition:opacity .45s ease, transform .45s ease;
    }
    .page.activePage{
      opacity:1 !important;
      transform:translateY(0) !important;
    }

    .card{
      background: rgba(9,15,32,0.92);
      border-radius: 12px;
      padding: 1rem;
      box-shadow: 0 0 22px rgba(0,255,255,0.18);
      border: 1px solid rgba(0,255,255,0.2);
      backdrop-filter: blur(8px);
      margin-bottom: 1rem;
      animation: cardFade 0.6s ease forwards;
    }

    @keyframes cardFade{
      from { opacity:0; transform:translateY(14px); }
      to   { opacity:1; transform:translateY(0); }
    }

    input[type=text], input[type=email], input[type=number], input[type=file]{
      width:100%;
      padding:0.6rem;
      margin:0.4rem 0;
      border:1px solid rgba(0,255,255,0.7);
      border-radius:4px;
      background:#07101f;
      color:var(--text);
      outline:none;
    }
    input[type=text]:focus,
    input[type=email]:focus,
    input[type=number]:focus{
      box-shadow:0 0 10px #00eaff;
    }

    select{
      padding:0.45rem;
      border-radius:4px;
      border:1px solid rgba(0,255,255,0.7);
      background:#07101f;
      color:var(--text);
      outline:none;
    }

    button{
      padding:0.5rem 0.8rem;
      border:0;
      background:var(--accent);
      color:#000;
      border-radius:6px;
      cursor:pointer;
      font-weight:bold;
      transition:0.25s;
      position:relative;
      overflow:hidden;
    }
    button:hover{
      background:#00bcd4;
      box-shadow:0 0 12px #00eaff;
    }
    /* Button ripple effect */
    button::after{
      content:"";
      position:absolute;
      width:8px;
      height:8px;
      border-radius:50%;
      background:rgba(255,255,255,0.6);
      transform:scale(0);
      opacity:0;
      pointer-events:none;
      transition:transform 0.5s ease, opacity 0.5s ease;
      left:var(--x);
      top:var(--y);
    }
    button:active::after{
      transform:scale(16);
      opacity:0;
    }

    .progress{
      height:18px;
      background:#050b14;
      border-radius:9px;
      overflow:hidden;
      margin-top:12px;
      border:1px solid rgba(0,255,255,0.25);
    }
    .progress-bar{
      height:100%;
      width:0%;
      background:linear-gradient(to right,#00eaff,#00ff9d);
      transition:width .2s;
    }

    pre.log{
      background:#02060d;
      border-radius:6px;
      padding:0.7rem;
      height:160px;
      overflow:auto;
      border:1px solid rgba(0,255,255,0.22);
      color:#b9eaff;
      font-size:0.86rem;
    }
    .small { font-size:0.9rem; color: #8fa3b7 }

    /* quarantine list styling + aligned buttons */
    #quarantineList ul{list-style:none;padding:0;margin:0}
    #quarantineList li{
      display:flex;
      align-items:center;
      justify-content:space-between;
      padding:0.45rem 0;
      border-bottom:1px solid rgba(0,255,255,0.15)
    }
    .q-left{flex:1;overflow:hidden;padding-right:1rem}
    .q-actions{display:flex;gap:8px;align-items:center}
    .q-actions button{padding:0.35rem 0.6rem;border-radius:6px}

    /* popup container + glass effect */
    #popupContainer{
      position:fixed;
      right:18px;
      top:18px;
      z-index:9999;
      display:flex;
      flex-direction:column;
      gap:10px;
      max-width:360px
    }
    .popup{
      background: rgba(9,15,32,0.9);
      color: white;
      padding: 0.9rem 1rem;
      border-radius: 12px;
      box-shadow: 0 8px 30px rgba(0,0,0,0.65);
      backdrop-filter: blur(8px) saturate(120%);
      -webkit-backdrop-filter: blur(8px) saturate(120%);
      border: 1px solid rgba(0,255,255,0.3);
      font-weight: 600;
      transition: opacity .25s, transform .25s;
      transform: translateY(0);
      display:flex;
      align-items:center;
      gap:0.7rem;
      font-size: 0.98rem;
    }
    .popup .emoji { font-size: 1.35rem; line-height:1; }
    .popup.hide{ opacity: 0; transform: translateY(-6px); }

    /* radar loader during scan */
    #scanLoader{
      text-align:center;
      margin-top:40px;
    }
    .radar{
      width:180px;
      height:180px;
      border-radius:50%;
      border:3px solid rgba(0,255,255,0.4);
      margin:0 auto;
      position:relative;
      box-shadow:0 0 18px #00eaff;
    }
    .radar::before{
      content:"";
      position:absolute;
      width:100%;
      height:100%;
      border-radius:50%;
      border:3px solid rgba(0,255,255,0.2);
      animation:pulse 2s infinite;
    }
    .radar::after{
      content:"";
      position:absolute;
      width:50%;
      height:3px;
      background:#00eaff;
      top:50%;
      left:50%;
      transform-origin:left center;
      animation:rotate 2s linear infinite;
    }

    @keyframes rotate{
      from{ transform:rotate(0deg); }
      to{ transform:rotate(360deg); }
    }
    @keyframes pulse{
      0%{ transform:scale(1); opacity:1; }
      100%{ transform:scale(1.8); opacity:0; }
    }

    /* Hacker Grid Background Animation + click fix */
    .grid {
        position:fixed;
        top:0;
        left:0;
        width:100%;
        height:100%;
        background:
            linear-gradient(0deg, rgba(0,255,255,0.12) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0,255,255,0.1) 1px, transparent 1px);
        background-size:40px 40px;
        animation:gridMove 12s linear infinite;
        opacity:0.22;
        z-index:-1;
        pointer-events:none;
    }

    header, nav {
        position: relative;
        z-index: 9999;
    }

    main, .page, #scanLoader {
        position: relative;
        z-index: 5;
    }

    @keyframes gridMove {
        from { background-position: 0 0; }
        to   { background-position: 0 80px; }
    }
  </style>
</head>
<body class="{{ theme }}">
  <div class="grid"></div>
  <header>
    <h1>CyberSecure Antivirus</h1>
    <div class="top-right">Logged in as <strong>{{ username }}</strong> | <a href="{{ url_for('logout') }}" style="color:#00eaff">Logout</a></div>
  </header>
  <nav>
    <a href="#" class="active" data-page="dashboard">Dashboard</a>
    <a href="#" data-page="scan">Scan</a>
    <a href="#" data-page="quarantine">Quarantine</a>
    <a href="#" data-page="settings">Settings</a>
  </nav>
  <main>
    <section id="dashboard" class="page activePage">
      <h2>Dashboard</h2>
      <div class="card">Last Scan: <span id="lastScan">{{ last_scan or 'Never' }}</span></div>
      <div class="card">Threats Today: <span id="threatsToday">{{ threats_today }}</span></div>
      <div class="card">Quarantined Items: <span id="quarantineCount">{{ quarantine_count }}</span></div>
    </section>

    <!-- Scan page: normal UI + radar loader (Option A) -->
    <section id="scan" class="page" style="display:none">
      <h2>Scan</h2>

      <!-- Normal scan UI -->
      <div id="scanNormalUI">
        <div class="card">
          <label>Folder path to scan (absolute, server machine):</label>
          <input type="text" id="folderPath" placeholder="Enter server path or upload file" />
          <div style="margin:0.5rem 0">
            <button id="startScanBtn">Start Scan</button>
          </div>
          <div class="progress"><div id="progressBar" class="progress-bar"></div></div>
          <div style="margin-top:0.8rem">
            <pre class="log" id="scanLog"></pre>
          </div>
          <div style="margin-top:0.6rem">
            <label>Also you can upload a single file to scan:</label>
            <form id="uploadForm" enctype="multipart/form-data">
              <input type="file" id="uploadFile" name="file" />
              <button type="submit">Upload & Scan File</button>
            </form>
            <div id="uploadResult"></div>
          </div>
        </div>
      </div>

      <!-- Cyber radar loader (visible only while scan running) -->
      <div id="scanLoader" style="display:none;">
        <div class="radar"></div>
        <h2 style="color:#00eaff; margin-top:20px;">SCANNING…</h2>
        <p class="small">Please wait while your system is being scanned.</p>
      </div>
    </section>

    <section id="quarantine" class="page" style="display:none">
      <h2>Quarantine</h2>
      <div class="card" id="quarantineList"></div>
    </section>

    <!-- SETTINGS -->
    <section id="settings" class="page" style="display:none">
      <h2>Settings</h2>
      <div class="card">

        <!-- Line 1 → Theme -->
        <div style="display:flex; align-items:center; gap:15px;">
          <label style="white-space:nowrap; width:240px;">Theme:</label>
          <select id="theme" style="flex:1;">
            <option value="">-- Select Theme --</option>
            <option value="purple">Purple Hacker</option>
            <option value="green">Windows Defender Green</option>
            <option value="gold">Gold Royal</option>
          </select>
        </div>

        <!-- Line 2 → Reminder -->
        <div style="display:flex; align-items:center; gap:15px; margin-top:12px;">
          <label style="white-space:nowrap; width:240px;">Scan reminder interval (days):</label>
          <input type="number" id="reminderDays" min="1" value="{{ reminder_days or 7 }}" style="flex:1; max-width:200px;" />
        </div>

        <!-- Line 3 → Email -->
        <div style="display:flex; align-items:center; gap:15px; margin-top:12px;">
          <label style="white-space:nowrap; width:240px;">Email (not used):</label>
          <input type="email" id="email" value="{{ email or '' }}" style="flex:1;" />
        </div>

        <div style="margin-top:0.6rem">
          <label><input type="checkbox" id="notifications" {{ 'checked' if notifications else '' }}> In-app notifications enabled</label>
        </div>
        <div style="margin-top:0.6rem">
          <label><input type="checkbox" id="autoUpdate" {{ 'checked' if auto_update else '' }}> Auto-update (no-op demo)</label>
        </div>
        <div style="margin-top:0.6rem">
          <button id="saveSettings">Save Settings</button>
          <p class="small">Note: Signatures are still in DB for detection but the settings page no longer lets you add signatures from UI.</p>
        </div>
      </div>
    </section>
  </main>

  <!-- Popup container (glass effect) -->
  <div id="popupContainer" aria-live="polite"></div>

<script>
  // nav with page animation
  document.querySelectorAll('nav a').forEach(a=>{
    a.addEventListener('click', e=>{
      e.preventDefault();
      document.querySelectorAll('nav a').forEach(x=>x.classList.remove('active'));
      e.currentTarget.classList.add('active');

      document.querySelectorAll('.page').forEach(p=>{
        p.style.display='none';
        p.classList.remove('activePage');
      });

      const targetId = e.currentTarget.dataset.page;
      const page = document.getElementById(targetId);
      if(page){
        page.style.display='block';
        setTimeout(()=> page.classList.add('activePage'), 10);
      }

      refreshDashboard();
      renderQuarantine();
    });
  });

  function appendLog(txt){
    const el=document.getElementById('scanLog');
    el.textContent += txt + "\\n";
    el.scrollTop = el.scrollHeight;
  }

  // Simple WebAudio beep player.
  function playBeep(isAlert){
    try {
      const ctx = new (window.AudioContext || window.webkitAudioContext)();
      const now = ctx.currentTime;
      const createBeep = (start, duration, freq, gainVal=0.06) => {
        const o = ctx.createOscillator();
        const g = ctx.createGain();
        o.type = 'sine';
        o.frequency.value = freq;
        g.gain.value = 0;
        o.connect(g);
        g.connect(ctx.destination);
        o.start(start);
        g.gain.setValueAtTime(gainVal, start + 0.002);
        g.gain.exponentialRampToValueAtTime(0.0001, start + duration);
        o.stop(start + duration + 0.02);
      };
      if(isAlert){
        createBeep(now, 0.14, 880, 0.08);
        createBeep(now + 0.18, 0.16, 660, 0.09);
      } else {
        createBeep(now, 0.12, 880, 0.05);
      }
    } catch(e){
      console.warn('Beep failed', e);
    }
  }

  function emojiForCount(n){
    n = Number(n) || 0;
    if(n === 0) return '✅';
    if(n === 1 || n === 2) return '⚠️';
    return '💀';
  }

  function showPopup(message){
    let match = message.match(/(\\d+)/);
    let n = match ? parseInt(match[1], 10) : null;
    const emoji = (n === null) ? '🔔' : emojiForCount(n);
    const container = document.getElementById('popupContainer');
    const p = document.createElement('div');
    p.className = 'popup';
    const emSpan = document.createElement('span');
    emSpan.className = 'emoji';
    emSpan.textContent = emoji;
    const textSpan = document.createElement('span');
    textSpan.textContent = ' ' + message;
    p.appendChild(emSpan);
    p.appendChild(textSpan);
    container.appendChild(p);
    if(n !== null && n > 0) playBeep(true); else playBeep(false);
    setTimeout(()=>{
      p.classList.add('hide');
      setTimeout(()=>{ try{ container.removeChild(p); }catch(e){} }, 300);
    }, 5000);
  }

  // start scan -> open EventSource to /scan_stream?path=...
  document.getElementById('startScanBtn').addEventListener('click', ()=>{
    const path = document.getElementById('folderPath').value.trim();
    if(!path){ alert('Enter folder path to scan'); return; }

    // Show loader, hide normal UI
    document.getElementById('scanLoader').style.display = 'block';
    document.getElementById('scanNormalUI').style.display = 'none';

    document.getElementById('scanLog').textContent='';
    updateProgress(0);
    const url = '/scan_stream?path=' + encodeURIComponent(path);
    if(window._scanSource && window._scanSource.close) window._scanSource.close();
    const es = new EventSource(url);
    window._scanSource = es;

    es.onmessage = function(e){
      let d = {};
      try{ d = JSON.parse(e.data); }catch(err){ d={msg:e.data}; }
      if(d.type === 'progress'){
        updateProgress(d.percent);
      } else if(d.type === 'log'){
        appendLog(d.msg);
      } else if(d.type === 'notification'){
        showPopup(d.message);
      } else if(d.type === 'done'){
        updateProgress(100);
        appendLog('--- Scan complete ---');
        refreshDashboard();
        renderQuarantine();
        document.getElementById('scanLoader').style.display = 'none';
        document.getElementById('scanNormalUI').style.display = 'block';
        es.close();
      } else if(d.type === 'error'){
        appendLog('ERROR: ' + d.msg);
        document.getElementById('scanLoader').style.display = 'none';
        document.getElementById('scanNormalUI').style.display = 'block';
        es.close();
      }
    };

    es.onerror = function(ev){
      // Ignore normal close event (scan completed successfully)
      if (es.readyState === EventSource.CLOSED) {
          return;
      }
      appendLog('Connection lost.');
      document.getElementById('scanLoader').style.display = 'none';
      document.getElementById('scanNormalUI').style.display = 'block';
      es.close();
    };
  });

  function updateProgress(pct){
    document.getElementById('progressBar').style.width = Math.min(100,Math.max(0,pct)) + '%';
  }

  // Upload file scanning
  document.getElementById('uploadForm').addEventListener('submit', (ev)=>{
    ev.preventDefault();
    const fileInput = document.getElementById('uploadFile');
    if(!fileInput.files.length){ alert('Pick a file'); return; }
    const fd = new FormData();
    fd.append('file', fileInput.files[0]);
    fetch('/upload_scan', {method:'POST', body: fd})
      .then(r=>r.json())
      .then(j=>{
        document.getElementById('uploadResult').textContent = j.message || JSON.stringify(j);
        refreshDashboard(); renderQuarantine();
      })
      .catch(e=>{ document.getElementById('uploadResult').textContent = 'Upload error'; });
  });

  // save settings
  document.getElementById('saveSettings').addEventListener('click', ()=>{
    const payload = {
      email: document.getElementById('email').value.trim(),
      theme: document.getElementById('theme').value,
      reminder_days: parseInt(document.getElementById('reminderDays').value || 7, 10),
      notifications: document.getElementById('notifications').checked ? 1 : 0,
      auto_update: document.getElementById('autoUpdate').checked ? 1 : 0
    };
    fetch('/api/save_settings', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify(payload)
    }).then(r=>r.json()).then(j=>{ alert(j.message || 'Settings saved'); location.reload(); });
  });

  function refreshDashboard(){
    fetch('/api/dashboard').then(r=>r.json()).then(d=>{
      document.getElementById('lastScan').textContent = d.last_scan || 'Never';
      document.getElementById('threatsToday').textContent = d.threats_today || 0;
      document.getElementById('quarantineCount').textContent = d.quarantine_count || 0;
    });
  }

  function renderQuarantine(){
    fetch('/api/quarantine').then(r=>r.json()).then(items=>{
      const container = document.getElementById('quarantineList');
      if(!items || items.length===0){ container.innerHTML = '<p>No quarantined items.</p>'; return; }
      let html = '<ul>';
      items.forEach(it => {
        html += `<li><div class="q-left">${escapeHtml(it.filename)} <div class="small">${it.date}</div></div><div class="q-actions"><button data-id="${it.id}" class="restore">Restore</button><button data-id="${it.id}" class="delete">Delete</button></div></li>`;
      });
      html += '</ul>';
      container.innerHTML = html;
      container.querySelectorAll('.restore').forEach(b=>b.addEventListener('click', e=>{
        fetch('/api/restore/' + e.target.dataset.id, {method:'POST'}).then(()=>{ renderQuarantine(); refreshDashboard(); });
      }));
      container.querySelectorAll('.delete').forEach(b=>b.addEventListener('click', e=>{
        fetch('/api/delete/' + e.target.dataset.id, {method:'POST'}).then(()=>{ renderQuarantine(); refreshDashboard(); });
      }));
    });
  }

  function escapeHtml(s){
    if(!s) return '';
    return s.replace(/[&<>"']/g, function(m){ return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":"&#39;"}[m]); });
  }

  // button ripple effect JS
  document.querySelectorAll('button').forEach(btn=>{
    btn.addEventListener('click', function(e){
      const rect = this.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      this.style.setProperty('--x', x + 'px');
      this.style.setProperty('--y', y + 'px');
    });
  });

  // init
  refreshDashboard();
  renderQuarantine();
</script>
</body>
</html>
'''

# -------------------- Routes: auth --------------------
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        email = request.form.get('email','').strip()
        password = request.form.get('password','')
        confirm = request.form.get('confirm','')
        if not username or not password or not email:
            error = 'Username, email and password required.'
        elif password != confirm:
            error = 'Passwords do not match.'
        else:
            ok, msg = create_user(username, password, email)
            if ok:
                return redirect(url_for('login'))
            else:
                error = msg
    return render_template_string(SIGNUP_TEMPLATE, error=error)

@app.route('/login', methods=['GET','POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        user = get_user_by_username(username)
        if user and user.get('password_hash') and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            return redirect(url_for('index'))
        else:
            error = 'Invalid username or password.'
    return render_template_string(LOGIN_TEMPLATE, error=error)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

# -------------------- Main page --------------------
def get_meta(user_id):
    db = get_db(); c = db.cursor()
    c.execute('SELECT * FROM user_meta WHERE user_id = ?', (user_id,))
    meta = row_to_dict(c.fetchone())
    if not meta:
        c.execute('INSERT OR REPLACE INTO user_meta (user_id, threats_day_date, threats_today) VALUES (?, ?, ?)',
                  (user_id, date.today().isoformat(), 0))
        db.commit()
        c.execute('SELECT * FROM user_meta WHERE user_id = ?', (user_id,))
        meta = row_to_dict(c.fetchone())
    return {
        'last_scan': meta.get('last_scan') if meta else None,
        'threats_day_date': meta.get('threats_day_date') if meta else None,
        'threats_today': meta.get('threats_today', 0) if meta else 0
    }

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = get_user_by_id(session['user_id'])

    if not user:
        return redirect(url_for('login'))

    meta = get_meta(user['id'])
    db = get_db()
    c = db.cursor()
    
    c.execute('SELECT COUNT(*) as cnt FROM quarantine WHERE user_id = ?', (user['id'],))
    qcount = c.fetchone()['cnt']
    return render_template_string(
        APP_TEMPLATE,
        username=user['username'],
        user_id=user['id'],
        last_scan=meta.get('last_scan'),
        threats_today=meta.get('threats_today', 0),
        quarantine_count=qcount,
        email=user.get('email'),
        theme=user.get('theme'),  # NO DEFAULT, user must choose
        reminder_days=user.get('reminder_days',7),
        notifications=int(user.get('notifications',1)),
        auto_update=int(user.get('auto_update',1))
    )

# -------------------- API endpoints --------------------
@app.route('/api/dashboard')
def api_dashboard():
    if 'user_id' not in session:
        return jsonify({'error':'unauthenticated'}), 401
    uid = session['user_id']
    user = get_user_by_id(uid)
    meta = get_meta(uid)
    db = get_db(); c = db.cursor()
    c.execute('SELECT COUNT(*) as cnt FROM quarantine WHERE user_id = ?', (uid,))
    qcount = c.fetchone()['cnt']
    return jsonify({
        'last_scan': meta.get('last_scan'),
        'threats_today': meta.get('threats_today', 0),
        'quarantine_count': qcount,
        'auto_update': int(user.get('auto_update', 1)),
        'notifications': int(user.get('notifications', 1))
    })

@app.route('/api/quarantine')
def api_quarantine():
    if 'user_id' not in session:
        return jsonify([])
    uid = session['user_id']
    db = get_db(); c = db.cursor()
    c.execute('SELECT id, filename, date FROM quarantine WHERE user_id = ? ORDER BY id DESC', (uid,))
    rows = c.fetchall()
    return jsonify([{'id':r['id'],'filename':r['filename'],'date':r['date']} for r in rows])

@app.route('/api/restore/<int:item_id>', methods=['POST'])
def api_restore(item_id):
    if 'user_id' not in session:
        return jsonify({'error':'unauthenticated'}), 401
    uid = session['user_id']
    db = get_db(); c = db.cursor()
    c.execute('DELETE FROM quarantine WHERE id = ? AND user_id = ?', (item_id, uid))
    db.commit()
    return jsonify({'status':'ok'})

@app.route('/api/delete/<int:item_id>', methods=['POST'])
def api_delete(item_id):
    if 'user_id' not in session:
        return jsonify({'error':'unauthenticated'}), 401
    uid = session['user_id']
    db = get_db(); c = db.cursor()
    c.execute('DELETE FROM quarantine WHERE id = ? AND user_id = ?', (item_id, uid))
    db.commit()
    return jsonify({'status':'ok'})

@app.route('/api/save_settings', methods=['POST'])
def api_save_settings():
    if 'user_id' not in session:
        return jsonify({'error':'unauthenticated'}), 401
    uid = session['user_id']
    data = request.get_json() or {}
    email = data.get('email')
    theme = data.get('theme') or None
    reminder_days = int(data.get('reminder_days',7))
    notifications = int(data.get('notifications',1))
    auto_update = int(data.get('auto_update',1))
    db = get_db(); c = db.cursor()
    c.execute('UPDATE users SET email = ?, theme = ?, reminder_days = ?, notifications = ?, auto_update = ? WHERE id = ?',
              (email, theme, reminder_days, notifications, auto_update, uid))
    db.commit()
    return jsonify({'status':'ok','message':'Settings saved'})

# -------------------- Upload & single-file scan --------------------
@app.route('/upload_scan', methods=['POST'])
def upload_scan():
    if 'user_id' not in session:
        return jsonify({'error':'unauthenticated'}), 401
    if 'file' not in request.files or request.files['file'].filename == '':
        return jsonify({'error':'no file provided'}), 400
    f = request.files['file']
    uploads_dir = os.path.join(BASE_DIR, 'uploads')
    os.makedirs(uploads_dir, exist_ok=True)
    saved_path = os.path.join(uploads_dir, f.filename)
    f.save(saved_path)
    h = sha256_file(saved_path)
    found, reason = check_signature_and_heuristic(saved_path, h)
    if found:
        db = get_db(); c = db.cursor()
        c.execute('INSERT INTO quarantine (user_id, filename, date) VALUES (?,?,?)',
                  (session['user_id'], saved_path, datetime.now().isoformat()))
        db.commit()
        return jsonify({'status':'ok','message': f'File flagged and quarantined: {reason}'})
    else:
        return jsonify({'status':'ok','message':'File appears clean (heuristic). SHA256: ' + (h or 'n/a')})

# -------------------- Check logic used during scan --------------------
def check_signature_and_heuristic(filepath, filehash):
    db = get_db(); c = db.cursor()
    if filehash:
        c.execute('SELECT 1 FROM signatures WHERE sha256 = ?', (filehash,))
        if c.fetchone():
            return True, 'Signature match (sha256)'
    suspicious_exts = {'.exe', '.dll', '.scr', '.bat'}
    try:
        _, ext = os.path.splitext(filepath.lower())
        if ext in suspicious_exts:
            return True, f'Heuristic: suspicious extension {ext}'
    except Exception:
        pass
    return False, 'No match'

# -------------------- Scan stream (SSE) --------------------
@app.route('/scan_stream')
def scan_stream():
    if 'user_id' not in session:
        return Response(json.dumps({'error':'unauthenticated'}), mimetype='application/json', status=401)
    path = request.args.get('path','').strip()
    if not path:
        return Response('data: ' + json.dumps({'type':'error','msg':'No path provided'}) + "\n\n",
                        content_type='text/event-stream')
    path = os.path.abspath(path)
    if not os.path.exists(path):
        return Response('data: ' + json.dumps({'type':'error','msg':'Path not found: ' + path}) + "\n\n",
                        content_type='text/event-stream')
    user_id = session['user_id']
    file_list = []
    for root, dirs, files in os.walk(path):
        for name in files:
            file_list.append(os.path.join(root, name))
    total = len(file_list)
    if total == 0:
        def empty_gen():
            yield f"data: {json.dumps({'type':'log','msg':'No files found in folder.'})}\n\n"
            yield f"data: {json.dumps({'type':'notification','message':'Scan complete — threats found: 0'})}\n\n"
            yield f"data: {json.dumps({'type':'done'})}\n\n"
        return Response(empty_gen(), mimetype='text/event-stream')

    known_hashes = set()
    try:
        db_local = sqlite3.connect(DATABASE, check_same_thread=False)
        cur = db_local.cursor()
        cur.execute('SELECT sha256 FROM signatures')
        for r in cur.fetchall():
            sha = r[0] if isinstance(r, (list, tuple)) else r
            if sha:
                known_hashes.add(sha)
    finally:
        try:
            db_local.close()
        except Exception:
            pass

    def generate():
        scanned = 0
        threats_found = 0
        yield f"data: {json.dumps({'type':'log','msg':f'Starting scan of {total} files.'})}\n\n"
        db_conn = None
        try:
            db_conn = sqlite3.connect(DATABASE, check_same_thread=False)
            db_conn.row_factory = sqlite3.Row
            cur = db_conn.cursor()
            for fp in file_list:
                scanned += 1
                h = sha256_file(fp)
                is_threat = False
                reason = None
                if h and h in known_hashes:
                    is_threat = True
                    reason = 'signature match'
                else:
                    _, ext = os.path.splitext(fp.lower())
                    if ext in {'.exe', '.dll', '.scr', '.bat'}:
                        is_threat = True
                        reason = f'heuristic suspicious extension {ext}'
                if is_threat:
                    threats_found += 1
                    try:
                        cur.execute('INSERT INTO quarantine (user_id, filename, date) VALUES (?,?,?)',
                                    (user_id, fp, datetime.now().isoformat()))
                        db_conn.commit()
                        yield f"data: {json.dumps({'type':'log','msg':f'QUARANTINED: {fp} ({reason})'})}\n\n"
                    except Exception as e:
                        yield f"data: {json.dumps({'type':'log','msg':f'QUARANTINE FAILED: {fp} ({str(e)})'})}\n\n"
                else:
                    yield f"data: {json.dumps({'type':'log','msg':f'OK: {fp}'})}\n\n"
                percent = int((scanned / total) * 100)
                yield f"data: {json.dumps({'type':'progress','percent':percent})}\n\n"
                time.sleep(0.05)

            now = datetime.now().isoformat()
            cur.execute('SELECT threats_day_date, threats_today FROM user_meta WHERE user_id = ?', (user_id,))
            row = cur.fetchone()
            today_iso = date.today().isoformat()
            if row is None:
                cur.execute('INSERT OR REPLACE INTO user_meta (user_id, last_scan, threats_day_date, threats_today) VALUES (?,?,?,?)',
                            (user_id, now, today_iso, threats_found))
            else:
                cur.execute('UPDATE user_meta SET last_scan = ? WHERE user_id = ?', (now, user_id))
                if row['threats_day_date'] != today_iso:
                    cur.execute('UPDATE user_meta SET threats_day_date = ?, threats_today = ? WHERE user_id = ?',
                                (today_iso, threats_found, user_id))
                else:
                    cur.execute('UPDATE user_meta SET threats_today = threats_today + ? WHERE user_id = ?',
                                (threats_found, user_id))
            db_conn.commit()
            yield f"data: {json.dumps({'type':'log','msg':f'Scan finished. Threats found: {threats_found}'})}\n\n"
            yield f"data: {json.dumps({'type':'notification','message':f'Scan complete — threats found: {threats_found}'})}\n\n"
            yield f"data: {json.dumps({'type':'done'})}\n\n"
        except Exception as e:
            try:
                yield f"data: {json.dumps({'type':'error','msg':str(e)})}\n\n"
            except Exception:
                pass
        finally:
            if db_conn:
                try:
                    db_conn.close()
                except Exception:
                    pass
    return Response(generate(), mimetype='text/event-stream')

# -------------------- Run --------------------
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, threaded=True, host='0.0.0.0', port=port)
