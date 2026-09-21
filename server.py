import asyncio, json, threading, base64, pathlib, sqlite3, hashlib, secrets
from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
import websockets

BASE = pathlib.Path(__file__).parent
HTML = (BASE / "chat.html").read_text(encoding="utf-8")
BG_FILE = BASE / "bg.jpg"
DB_FILE = BASE / "chat.db"
AVATAR_DIR = BASE / "avatars"
UPLOAD_DIR = BASE / "uploads"
STICKER_DIR = BASE / "stickers"
for d in (AVATAR_DIR, UPLOAD_DIR, STICKER_DIR):
    d.mkdir(exist_ok=True)

BJ_TZ = timezone(timedelta(hours=8))
MAX_UPLOAD = 20 * 1024 * 1024

db = sqlite3.connect(DB_FILE, check_same_thread=False)
db.executescript("""
CREATE TABLE IF NOT EXISTS users(
  username TEXT PRIMARY KEY,
  salt TEXT,
  pw_hash TEXT
);
CREATE TABLE IF NOT EXISTS messages(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT,
  text TEXT,
  ts TEXT,
  msg_type TEXT DEFAULT 'text',
  file_url TEXT,
  file_name TEXT,
  file_size INTEGER,
  recalled INTEGER DEFAULT 0
);
""")
for col, typ in [("msg_type", "TEXT DEFAULT 'text'"),
                 ("file_url", "TEXT"),
                 ("file_name", "TEXT"),
                 ("file_size", "INTEGER"),
                 ("recalled", "INTEGER DEFAULT 0")]:
    try:
        db.execute(f"ALTER TABLE messages ADD COLUMN {col} {typ}")
    except sqlite3.OperationalError:
        pass

def hash_pw(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(),
                               bytes.fromhex(salt), 100_000).hex()

def avatar_filename(username):
    return hashlib.md5(username.encode("utf-8")).hexdigest() + ".jpg"

MIME = {
    ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png",
    ".gif": "image/gif", ".webp": "image/webp", ".bmp": "image/bmp",
    ".svg": "image/svg+xml", ".pdf": "application/pdf",
    ".txt": "text/plain; charset=utf-8", ".mp4": "video/mp4",
    ".mp3": "audio/mpeg", ".zip": "application/zip",
}
IMG_EXT = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp")

tokens = {}
current_bg = None
if BG_FILE.exists():
    current_bg = "data:image/jpeg;base64," + base64.b64encode(BG_FILE.read_bytes()).decode()

def run_http():
    class Handler(BaseHTTPRequestHandler):
        def _json(self, obj, code=200):
            body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_file(self, f: pathlib.Path):
            body = f.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type",
                             MIME.get(f.suffix.lower(), "application/octet-stream"))
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "public, max-age=31536000")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path == "/":
                body = HTML.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif path == "/stickers_list":
                files = sorted([
                    f.name for f in STICKER_DIR.iterdir()
                    if f.is_file() and f.suffix.lower() in IMG_EXT
                ])
                return self._json({"list": ["/stickers/" + f for f in files]})
            elif path.startswith("/stickers/"):
                f = STICKER_DIR / pathlib.Path(path).name
                if f.exists() and f.is_file():
                    self._send_file(f)
                else:
                    self.send_response(404); self.end_headers()
            elif path.startswith("/uploads/"):
                f = UPLOAD_DIR / pathlib.Path(path).name
                if f.exists() and f.is_file():
                    self._send_file(f)
                else:
                    self.send_response(404); self.end_headers()
            elif path == "/favicon.ico":
                self.send_response(204); self.end_headers()
            else:
                self.send_response(404); self.end_headers()

        def do_POST(self):
            path = self.path.split("?", 1)[0]
            length = int(self.headers.get("Content-Length", 0))
            if length > MAX_UPLOAD * 1.5:
                return self._json({"error": "文件过大（上限 20MB）"}, 413)
            try:
                data = json.loads(self.rfile.read(length) or b"{}")
            except Exception:
                return self._json({"error": "请求格式错误"}, 400)

            if path == "/upload":
                data_url = data.get("data", "")
                filename = (data.get("filename") or "file").strip()[:120]
                if "," not in data_url:
                    return self._json({"error": "数据格式错误"}, 400)
                try:
                    _, b64 = data_url.split(",", 1)
                    raw = base64.b64decode(b64)
                except Exception:
                    return self._json({"error": "解码失败"}, 400)
                if len(raw) > MAX_UPLOAD:
                    return self._json({"error": "文件过大"}, 413)
                ext = pathlib.Path(filename).suffix.lower()
                if not ext or len(ext) > 8:
                    ext = ".bin"
                stored = secrets.token_hex(8) + ext
                (UPLOAD_DIR / stored).write_bytes(raw)
                return self._json({
                    "url": "/uploads/" + stored,
                    "name": filename,
                    "size": len(raw),
                })

            u = data.get("username", "").strip()
            p = data.get("password", "")

            if path == "/register":
                if not u or not p:
                    return self._json({"error": "用户名和密码不能为空"}, 400)
                if len(p) < 6:
                    return self._json({"error": "密码至少6位"}, 400)
                if db.execute("SELECT 1 FROM users WHERE username=?", (u,)).fetchone():
                    return self._json({"error": "用户名已存在"}, 400)
                salt = secrets.token_hex(16)
                db.execute("INSERT INTO users VALUES(?,?,?)", (u, salt, hash_pw(p, salt)))
                db.commit()
            elif path == "/login":
                row = db.execute("SELECT salt, pw_hash FROM users WHERE username=?", (u,)).fetchone()
                if not row or hash_pw(p, row[0]) != row[1]:
                    return self._json({"error": "用户名或密码错误"}, 400)
            else:
                self.send_response(404); self.end_headers()
                return

            token = secrets.token_hex(16)
            tokens[token] = u
            self._json({"token": token, "username": u})

        def log_message(self, *a):
            pass

    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()

clients = set()

async def handler(ws):
    global current_bg
    raw_path = ws.request.path if hasattr(ws, "request") else ws.path
    token = parse_qs(urlparse(raw_path).query).get("token", [""])[0]
    username = tokens.get(token)
    if not username:
        await ws.send(json.dumps({"type": "auth_fail"}))
        await ws.close()
        return

    clients.add((ws, username))
    if current_bg:
        await ws.send(json.dumps({"type": "bg", "data": current_bg}))

    av_list = []
    for (u,) in db.execute("SELECT username FROM users").fetchall():
        f = AVATAR_DIR / avatar_filename(u)
        if f.exists():
            av_list.append({
                "username": u,
                "data": "data:image/jpeg;base64," +
                        base64.b64encode(f.read_bytes()).decode()
            })
    await ws.send(json.dumps({"type": "avatars", "data": av_list},
                             ensure_ascii=False))

    # ★ 历史消息带上 id 和 recalled
    rows = db.execute(
        "SELECT id, username, text, ts, msg_type, file_url, file_name, file_size, recalled "
        "FROM messages ORDER BY id DESC LIMIT 300"
    ).fetchall()
    history = [{
        "id": r[0],
        "user": r[1], "text": r[2], "time": r[3],
        "type": r[4] or "text",
        "url": r[5], "name": r[6], "size": r[7],
        "recalled": bool(r[8]),
    } for r in reversed(rows)]
    await ws.send(json.dumps({"type": "history", "data": history}, ensure_ascii=False))

    try:
        async for msg in ws:
            data = json.loads(msg)

            # ---------- 背景 ----------
            if data.get("type") == "bg":
                header, b64 = data["data"].split(",", 1)
                BG_FILE.write_bytes(base64.b64decode(b64))
                current_bg = data["data"]
                payload = json.dumps({"type": "bg", "data": current_bg})

            # ---------- 头像 ----------
            elif data.get("type") == "avatar":
                header, b64 = data["data"].split(",", 1)
                (AVATAR_DIR / avatar_filename(username)).write_bytes(base64.b64decode(b64))
                payload = json.dumps({"type": "avatar",
                                      "user": username,
                                      "data": data["data"]})

            # ---------- ★ 撤回 ----------
            elif data.get("type") == "recall":
                mid = data.get("id")
                row = db.execute(
                    "SELECT username, recalled FROM messages WHERE id=?", (mid,)
                ).fetchone()
                if row and row[0] == username and not row[1]:
                    db.execute("UPDATE messages SET recalled=1 WHERE id=?", (mid,))
                    db.commit()
                    payload = json.dumps({"type": "recall", "id": mid},
                                         ensure_ascii=False)
                else:
                    continue   # 无权/已撤回 → 忽略，不广播

            # ---------- ★ 添加为表情包 ----------
            elif data.get("type") == "add_sticker":
                url = data.get("url", "")
                src = None
                if url.startswith("/uploads/"):
                    src = UPLOAD_DIR / pathlib.Path(url).name
                elif url.startswith("/stickers/"):
                    src = STICKER_DIR / pathlib.Path(url).name
                if src and src.exists() and src.suffix.lower() in IMG_EXT:
                    dst = STICKER_DIR / src.name
                    if src != dst:
                        dst.write_bytes(src.read_bytes())
                    payload = json.dumps({"type": "stickers_changed"},
                                         ensure_ascii=False)
                else:
                    continue

            # ---------- 普通消息 ----------
            else:
                mtype = data.get("type", "text")
                if mtype not in ("text", "image", "file", "sticker"):
                    mtype = "text"
                text = (data.get("text") or "").strip()
                if mtype == "text" and not text:
                    continue
                if mtype in ("image", "file", "sticker") and not data.get("url"):
                    continue
                data["type"] = mtype
                data["text"] = text
                data["time"] = datetime.now(BJ_TZ).strftime("%H:%M:%S")
                data["user"] = username
                cur = db.execute(
                    "INSERT INTO messages(username, text, ts, msg_type, "
                    "file_url, file_name, file_size) VALUES(?,?,?,?,?,?,?)",
                    (username, text, data["time"], mtype,
                     data.get("url"), data.get("name"), data.get("size")))
                db.commit()
                data["id"] = cur.lastrowid   # ★ 广播时带上 id
                payload = json.dumps(data, ensure_ascii=False)

            for c, _u in list(clients):
                try:
                    await c.send(payload)
                except Exception:
                    clients.discard((c, _u))
    except Exception:
        import traceback
        traceback.print_exc()
    finally:
        clients.discard((ws, username))

async def main():
    threading.Thread(target=run_http, daemon=True).start()
    print("网页:  http://<服务器IP>:8000")
    print(f"表情包目录: {STICKER_DIR}")
    async with websockets.serve(handler, "0.0.0.0", 8765, max_size=10*1024*1024):
        await asyncio.Future()

asyncio.run(main())