import os
import re
import secrets
import sqlite3
import threading
import time
import io
import mimetypes
import sys
from collections import defaultdict, deque
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, abort, g, jsonify, request, send_file, session
from flask_socketio import SocketIO, emit, join_room
from PIL import Image, ImageOps, UnidentifiedImageError
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

ROOT = Path(__file__).resolve().parent
DEFAULT_DATA = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "Loop" if getattr(sys, "frozen", False) else ROOT / "instance"
INSTANCE = Path(os.environ.get("LOOP_DATA_DIR", str(DEFAULT_DATA)))
UPLOADS = Path(os.environ.get("LOOP_UPLOAD_DIR", str(INSTANCE / "uploads")))
FILE_STORAGE = INSTANCE / "files"
INSTANCE.mkdir(exist_ok=True)
UPLOADS.mkdir(parents=True, exist_ok=True)
FILE_STORAGE.mkdir(parents=True, exist_ok=True)
DB_PATH = Path(os.environ.get("LOOP_DB_PATH", str(INSTANCE / "loop.sqlite3")))
SECRET_PATH = INSTANCE / "secret.key"
USER_RE = re.compile(r"^[a-zA-Z0-9_]{3,24}$")
ALLOWED_BANNERS = {"mint", "coral", "amber", "sky", "orchid"}
MAX_MESSAGE_LENGTH = 2000
MAX_UPLOAD_BYTES = 130 * 1024 * 1024
MAX_SINGLE_UPLOAD_BYTES = 25 * 1024 * 1024


def load_secret():
    if SECRET_PATH.exists():
        return SECRET_PATH.read_text(encoding="ascii").strip()
    value = secrets.token_urlsafe(48)
    SECRET_PATH.write_text(value, encoding="ascii")
    try:
        SECRET_PATH.chmod(0o600)
    except OSError:
        pass
    return value


app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("LOOP_SECRET_KEY") or load_secret(),
    MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("LOOP_HTTPS", "0") == "1",
)
socketio = SocketIO(app, async_mode="threading")
presence_lock = threading.Lock()
active_sids = defaultdict(set)
message_times = defaultdict(deque)


def db():
    if "db" not in g:
        connection = sqlite3.connect(DB_PATH, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        g.db = connection
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def initialize_database():
    connection = sqlite3.connect(DB_PATH)
    connection.execute("PRAGMA foreign_keys = ON")
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL COLLATE NOCASE UNIQUE,
            display_name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            banner TEXT NOT NULL DEFAULT 'mint',
            avatar_path TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            invite_code TEXT NOT NULL UNIQUE,
            owner_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS server_members (
            server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            role TEXT NOT NULL DEFAULT 'member',
            joined_at TEXT NOT NULL,
            PRIMARY KEY(server_id, user_id)
        );
        CREATE TABLE IF NOT EXISTS channels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
            name TEXT NOT NULL COLLATE NOCASE,
            topic TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            UNIQUE(server_id, name)
        );
        CREATE TABLE IF NOT EXISTS dms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_a INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            user_b INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(user_a, user_b), CHECK(user_a < user_b)
        );
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            conversation_type TEXT NOT NULL CHECK(conversation_type IN ('channel', 'dm')),
            conversation_id INTEGER NOT NULL,
            sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            body TEXT NOT NULL CHECK(length(body) BETWEEN 0 AND 2000),
            created_at TEXT NOT NULL,
            edited_at TEXT
        );
        CREATE INDEX IF NOT EXISTS messages_conversation
            ON messages(conversation_type, conversation_id, id);
        CREATE TABLE IF NOT EXISTS uploads (
            id TEXT PRIMARY KEY,
            uploader_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            conversation_type TEXT NOT NULL CHECK(conversation_type IN ('channel', 'dm')),
            conversation_id INTEGER NOT NULL,
            message_id INTEGER REFERENCES messages(id) ON DELETE SET NULL,
            original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL UNIQUE,
            mime_type TEXT NOT NULL,
            byte_size INTEGER NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS message_uploads (
            message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
            upload_id TEXT NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
            PRIMARY KEY(message_id, upload_id)
        );
        """
    )
    now = datetime.now(timezone.utc).isoformat()
    server_columns = {row[1] for row in connection.execute("PRAGMA table_info(servers)").fetchall()}
    if "invite_code" not in server_columns:
        connection.execute("ALTER TABLE servers ADD COLUMN invite_code TEXT")
    channel_columns = {row[1] for row in connection.execute("PRAGMA table_info(channels)").fetchall()}
    if "server_id" not in channel_columns:
        connection.execute("ALTER TABLE channels ADD COLUMN server_id INTEGER REFERENCES servers(id)")
    default_server_row = connection.execute(
        "SELECT id FROM servers WHERE name = ? AND owner_id IS NULL ORDER BY id LIMIT 1",
        ("Loop Community",),
    ).fetchone()
    if default_server_row is None:
        connection.execute(
            "INSERT INTO servers(name, invite_code, created_at) VALUES (?, ?, ?)",
            ("Loop Community", secrets.token_urlsafe(7), now),
        )
        default_server_row = connection.execute("SELECT last_insert_rowid()").fetchone()
    default_server = default_server_row[0]
    old_servers = connection.execute("SELECT id FROM servers WHERE invite_code IS NULL OR invite_code = ''").fetchall()
    for old_server in old_servers:
        connection.execute("UPDATE servers SET invite_code = ? WHERE id = ?", (secrets.token_urlsafe(7), old_server[0]))
    connection.execute("UPDATE channels SET server_id = ? WHERE server_id IS NULL", (default_server,))
    connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS channels_server_name ON channels(server_id, name COLLATE NOCASE)")
    connection.execute("INSERT OR IGNORE INTO server_members(server_id, user_id, role, joined_at) SELECT ?, id, 'member', ? FROM users", (default_server, now))
    for name, topic in (("general", "The main room. Say hello."),
                        ("introductions", "Meet the people in Loop."),
                        ("gaming", "Games, finds, and party invites."),
                        ("music", "What are you listening to?")):
        connection.execute(
            "INSERT OR IGNORE INTO channels(server_id, name, topic, created_at) VALUES (?, ?, ?, ?)",
            (default_server, name, topic, now),
        )
    connection.commit()
    connection.close()


def user_payload(user):
    with presence_lock:
        online = bool(active_sids.get(user["id"]))
    return {"id": user["id"], "username": user["username"],
            "display_name": user["display_name"], "banner": user["banner"],
            "avatar": ("/api/profile-assets/" + user["avatar_path"]) if user["avatar_path"] else None,
            "online": online}


def message_payload(row):
    attachments = db().execute(
        """SELECT u.id, u.original_name, u.mime_type, u.byte_size
           FROM message_uploads mu JOIN uploads u ON u.id = mu.upload_id
           WHERE mu.message_id = ? ORDER BY u.original_name COLLATE NOCASE""",
        (row["id"],),
    ).fetchall()
    return {
        "id": row["id"], "conversation_type": row["conversation_type"],
        "conversation_id": row["conversation_id"], "body": row["body"],
        "created_at": row["created_at"], "edited": row["edited_at"] is not None,
        "sender": {"id": row["sender_id"], "username": row["username"],
                   "display_name": row["display_name"],
                   "avatar": ("/api/profile-assets/" + row["avatar_path"]) if row["avatar_path"] else None,
                   "banner": row["banner"]},
        "attachments": [{"id": item["id"], "name": item["original_name"],
                 "mime_type": item["mime_type"], "size": item["byte_size"],
                 "url": "/api/files/" + item["id"]} for item in attachments],
    }


def login_required(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return jsonify(error="Sign in to continue."), 401
        return function(*args, **kwargs)
    return wrapped


def csrf_required():
    expected = session.get("csrf_token")
    received = request.headers.get("X-CSRF-Token", "")
    if not expected or not secrets.compare_digest(expected, received):
        abort(403, description="Refresh the page and try again.")


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def may_access_dm(user_id, dm_id):
    return db().execute(
        "SELECT 1 FROM dms WHERE id = ? AND (user_a = ? OR user_b = ?)",
        (dm_id, user_id, user_id),
    ).fetchone() is not None


def may_access_channel(user_id, channel_id):
    return db().execute(
        """SELECT 1 FROM channels c JOIN server_members sm ON sm.server_id = c.server_id
           WHERE c.id = ? AND sm.user_id = ?""",
        (channel_id, user_id),
    ).fetchone() is not None


def conversation_room(kind, conversation_id):
    return "conversation:" + kind + ":" + str(conversation_id)


@app.route("/")
def index():
    return jsonify(app="Loop", status="ready", version="1.0.0")


@app.get("/api/csrf")
def csrf_token():
    session.setdefault("csrf_token", secrets.token_urlsafe(32))
    return jsonify(token=session["csrf_token"])


@app.post("/api/register")
def register():
    csrf_required()
    payload = request.get_json(silent=True) or {}
    username = str(payload.get("username", "")).strip()
    display_name = str(payload.get("display_name", username)).strip()
    password = str(payload.get("password", ""))
    if not USER_RE.fullmatch(username):
        return jsonify(error="Username must be 3-24 letters, numbers, or underscores."), 400
    if not 1 <= len(display_name) <= 32:
        return jsonify(error="Display name must be 1-32 characters."), 400
    if len(password) < 8 or len(password) > 128:
        return jsonify(error="Use a password from 8 to 128 characters."), 400
    try:
        cursor = db().execute(
            "INSERT INTO users(username, display_name, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (username, display_name, generate_password_hash(password, method="scrypt"), datetime.now(timezone.utc).isoformat()),
        )
        db().commit()
    except sqlite3.IntegrityError:
        return jsonify(error="That username is already taken."), 409
    session.clear()
    session["user_id"] = cursor.lastrowid
    session["csrf_token"] = secrets.token_urlsafe(32)
    default_server = db().execute("SELECT id FROM servers ORDER BY id LIMIT 1").fetchone()
    if default_server:
        db().execute("INSERT OR IGNORE INTO server_members(server_id, user_id, role, joined_at) VALUES (?, ?, 'member', ?)",
                     (default_server["id"], cursor.lastrowid, datetime.now(timezone.utc).isoformat()))
        db().commit()
    return jsonify(user=user_payload(current_user()), csrf_token=session["csrf_token"]), 201


@app.post("/api/login")
def login():
    csrf_required()
    payload = request.get_json(silent=True) or {}
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", ""))
    user = db().execute("SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,)).fetchone()
    if user is None or not check_password_hash(user["password_hash"], password):
        return jsonify(error="Username or password is incorrect."), 401
    session.clear()
    session["user_id"] = user["id"]
    session["csrf_token"] = secrets.token_urlsafe(32)
    return jsonify(user=user_payload(user), csrf_token=session["csrf_token"])


@app.post("/api/logout")
@login_required
def logout():
    csrf_required()
    session.clear()
    return jsonify(ok=True)


@app.get("/api/bootstrap")
@login_required
def bootstrap():
    user = current_user()
    servers = db().execute(
        """SELECT s.id, s.name, s.invite_code, sm.role,
                  (SELECT COUNT(*) FROM server_members all_members WHERE all_members.server_id = s.id) AS member_count
           FROM servers s JOIN server_members sm ON sm.server_id = s.id
           WHERE sm.user_id = ? ORDER BY s.id""",
        (user["id"],),
    ).fetchall()
    if not servers:
        return jsonify(error="You have not joined a server yet."), 403
    try:
        requested_server = int(request.args.get("server_id", servers[0]["id"]))
    except (ValueError, TypeError):
        requested_server = servers[0]["id"]
    if not any(server["id"] == requested_server for server in servers):
        return jsonify(error="You are not a member of that server."), 403
    channels = db().execute("SELECT id, server_id, name, topic FROM channels WHERE server_id = ? ORDER BY id", (requested_server,)).fetchall()
    people = db().execute(
        """SELECT u.* FROM users u JOIN server_members sm ON sm.user_id = u.id
              WHERE sm.server_id = ? AND u.id != ? ORDER BY u.display_name COLLATE NOCASE""",
          (requested_server, user["id"]),
    ).fetchall()
    dm_rows = db().execute(
        """SELECT d.id, u.id AS other_id, u.username, u.display_name, u.banner, u.avatar_path
           FROM dms d JOIN users u ON u.id = CASE WHEN d.user_a = ? THEN d.user_b ELSE d.user_a END
           WHERE d.user_a = ? OR d.user_b = ? ORDER BY d.id DESC""",
        (user["id"], user["id"], user["id"]),
    ).fetchall()
    dms = [{"id": row["id"], "user": {"id": row["other_id"],
            "username": row["username"], "display_name": row["display_name"],
            "banner": row["banner"],
            "avatar": ("/api/profile-assets/" + row["avatar_path"]) if row["avatar_path"] else None}} for row in dm_rows]
    return jsonify(me=user_payload(user), servers=[dict(row) for row in servers], active_server_id=requested_server,
                   channels=[dict(row) for row in channels],
                   people=[user_payload(person) for person in people], dms=dms,
                   csrf_token=session["csrf_token"])


@app.post("/api/servers")
@login_required
def create_server():
    csrf_required()
    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name", "")).strip()[:48]
    if not 2 <= len(name) <= 48:
        return jsonify(error="Server name must be 2-48 characters."), 400
    invite_code = secrets.token_urlsafe(9)
    now = datetime.now(timezone.utc).isoformat()
    cursor = db().execute("INSERT INTO servers(name, invite_code, owner_id, created_at) VALUES (?, ?, ?, ?)",
                          (name, invite_code, session["user_id"], now))
    server_id = cursor.lastrowid
    db().execute("INSERT INTO server_members(server_id, user_id, role, joined_at) VALUES (?, ?, 'owner', ?)",
                 (server_id, session["user_id"], now))
    db().execute("INSERT INTO channels(server_id, name, topic, created_at) VALUES (?, 'general', ?, ?)",
                 (server_id, "The main room. Say hello.", now))
    db().commit()
    server = db().execute(
        "SELECT id, name, invite_code, 'owner' AS role, 1 AS member_count FROM servers WHERE id = ?",
        (server_id,),
    ).fetchone()
    socketio.emit("server_created", {"id": server_id, "name": name}, broadcast=True)
    return jsonify(server=dict(server), active_server_id=server_id), 201


@app.post("/api/servers/join")
@login_required
def join_server():
    csrf_required()
    invite_code = str((request.get_json(silent=True) or {}).get("invite_code", "")).strip()
    server = db().execute("SELECT id, name, invite_code FROM servers WHERE invite_code = ?", (invite_code,)).fetchone()
    if server is None:
        return jsonify(error="That invite code is invalid."), 404
    db().execute("INSERT OR IGNORE INTO server_members(server_id, user_id, role, joined_at) VALUES (?, ?, 'member', ?)",
                 (server["id"], session["user_id"], datetime.now(timezone.utc).isoformat()))
    db().commit()
    count = db().execute("SELECT COUNT(*) FROM server_members WHERE server_id = ?", (server["id"],)).fetchone()[0]
    return jsonify(server={"id": server["id"], "name": server["name"], "invite_code": server["invite_code"],
                           "role": "member", "member_count": count}, active_server_id=server["id"]), 200


@app.get("/api/messages")
@login_required
def get_messages():
    kind = request.args.get("type", "")
    try:
        conversation_id = int(request.args.get("id", ""))
        before = int(request.args.get("before", "9223372036854775807"))
    except ValueError:
        return jsonify(error="Invalid conversation."), 400
    if kind == "channel":
        exists = may_access_channel(session["user_id"], conversation_id)
    elif kind == "dm" and may_access_dm(session["user_id"], conversation_id):
        exists = True
    else:
        exists = None
    if not exists:
        return jsonify(error="Conversation not found."), 404
    rows = db().execute(
        """SELECT m.*, u.username, u.display_name, u.banner, u.avatar_path
           FROM messages m JOIN users u ON u.id = m.sender_id
           WHERE m.conversation_type = ? AND m.conversation_id = ? AND m.id < ?
           ORDER BY m.id DESC LIMIT 60""",
        (kind, conversation_id, before),
    ).fetchall()
    return jsonify(messages=[message_payload(row) for row in reversed(rows)])


@app.post("/api/dms")
@login_required
def create_dm():
    csrf_required()
    username = str((request.get_json(silent=True) or {}).get("username", "")).strip()
    other = db().execute("SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,)).fetchone()
    if other is None or other["id"] == session["user_id"]:
        return jsonify(error="Choose another existing user."), 404
    user_a, user_b = sorted((session["user_id"], other["id"]))
    db().execute("INSERT OR IGNORE INTO dms(user_a, user_b) VALUES (?, ?)", (user_a, user_b))
    db().commit()
    dm = db().execute("SELECT id FROM dms WHERE user_a = ? AND user_b = ?", (user_a, user_b)).fetchone()
    socketio.emit("dm_created", {"id": dm["id"], "user": user_payload(current_user())}, room="user:" + str(other["id"]))
    return jsonify(id=dm["id"], user=user_payload(other)), 201


@app.post("/api/channels")
@login_required
def create_channel():
    csrf_required()
    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name", "")).strip().lower()
    topic = str(payload.get("topic", "")).strip()[:120]
    try:
        server_id = int(payload.get("server_id", ""))
    except (TypeError, ValueError):
        return jsonify(error="Choose a server first."), 400
    if not db().execute("SELECT 1 FROM server_members WHERE server_id = ? AND user_id = ?", (server_id, session["user_id"])).fetchone():
        return jsonify(error="You are not a member of that server."), 403
    if not re.fullmatch(r"[a-z0-9-]{2,32}", name):
        return jsonify(error="Channel names use 2-32 lowercase letters, numbers, or hyphens."), 400
    try:
        cursor = db().execute(
            "INSERT INTO channels(server_id, name, topic, created_at) VALUES (?, ?, ?, ?)",
            (server_id, name, topic, datetime.now(timezone.utc).isoformat()),
        )
        db().commit()
    except sqlite3.IntegrityError:
        return jsonify(error="That channel already exists on this server."), 409
    channel = {"id": cursor.lastrowid, "server_id": server_id, "name": name, "topic": topic}
    for member in db().execute("SELECT user_id FROM server_members WHERE server_id = ?", (server_id,)).fetchall():
        socketio.emit("channel_created", channel, room="user:" + str(member["user_id"]))
    return jsonify(channel=channel), 201


@app.patch("/api/profile")
@login_required
def update_profile():
    csrf_required()
    user = current_user()
    display_name = request.form.get("display_name", user["display_name"]).strip()
    banner = request.form.get("banner", user["banner"])
    if not 1 <= len(display_name) <= 32:
        return jsonify(error="Display name must be 1-32 characters."), 400
    if banner not in ALLOWED_BANNERS and not re.fullmatch(r"/api/profile-assets/banner-[a-f0-9]{32}\.webp", banner):
        banner = user["banner"]
    avatar_path = user["avatar_path"]
    for field, size, prefix in (("banner_image", (1600, 600), "banner"),
                                ("avatar_image", (512, 512), "avatar")):
        upload = request.files.get(field)
        if not upload or not upload.filename:
            continue
        try:
            image = Image.open(upload.stream)
            image.verify()
            upload.stream.seek(0)
            image = Image.open(upload.stream).convert("RGB")
            image = ImageOps.fit(image, size, method=Image.Resampling.LANCZOS)
            filename = prefix + "-" + secrets.token_hex(16) + ".webp"
            image.save(UPLOADS / filename, "WEBP", quality=84, method=5)
        except (UnidentifiedImageError, OSError, ValueError):
            return jsonify(error="Choose a valid PNG, JPEG, or WebP image."), 400
        if field == "avatar_image":
            avatar_path = filename
        else:
            banner = "/api/profile-assets/" + filename
    db().execute("UPDATE users SET display_name = ?, banner = ?, avatar_path = ? WHERE id = ?",
                 (display_name, banner, avatar_path, user["id"]))
    db().commit()
    return jsonify(user=user_payload(current_user()))


@app.get("/api/profile-assets/<path:filename>")
@login_required
def get_profile_asset(filename):
    if not re.fullmatch(r"(?:avatar|banner)-[a-f0-9]{32}\.webp", filename):
        abort(404)
    return send_file(UPLOADS / filename, mimetype="image/webp", conditional=True)


@app.post("/api/upload")
@login_required
def upload_file():
    csrf_required()
    user_id = session["user_id"]
    kind = request.form.get("type", "")
    try:
        conversation_id = int(request.form.get("id", ""))
    except ValueError:
        return jsonify(error="Choose a conversation first."), 400
    if kind == "channel":
        allowed = may_access_channel(user["id"], conversation_id)
    elif kind == "dm":
        allowed = may_access_dm(user_id, conversation_id)
    else:
        allowed = False
    if not allowed:
        return jsonify(error="Conversation not found."), 404
    incoming = request.files.get("file")
    if incoming is None or not incoming.filename:
        return jsonify(error="Choose a file to upload."), 400
    original_name = secure_filename(incoming.filename)[:180]
    suffix = Path(original_name).suffix.lower()
    if not original_name:
        return jsonify(error="That filename cannot be used. Rename the file and try again."), 400
    data = incoming.stream.read(MAX_SINGLE_UPLOAD_BYTES + 1)
    if not data or len(data) > MAX_SINGLE_UPLOAD_BYTES:
        return jsonify(error="Files must be between 1 byte and 25 MB."), 413
    mime_type = mimetypes.guess_type(original_name)[0] or "application/octet-stream"
    if suffix in {".png", ".jpg", ".jpeg", ".webp", ".gif"}:
        try:
            image = Image.open(io.BytesIO(data))
            image.verify()
            mime_type = Image.MIME.get(image.format, mime_type)
        except (UnidentifiedImageError, OSError, ValueError):
            return jsonify(error="That image file is invalid."), 400
    upload_id = secrets.token_hex(16)
    stored_name = upload_id + suffix
    created_at = datetime.now(timezone.utc).isoformat()
    target = FILE_STORAGE / stored_name
    try:
        target.write_bytes(data)
        db().execute(
            """INSERT INTO uploads(id, uploader_id, conversation_type, conversation_id,
               original_name, stored_name, mime_type, byte_size, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (upload_id, user_id, kind, conversation_id, original_name, stored_name,
             mime_type, len(data), created_at),
        )
        db().commit()
    except Exception:
        if target.exists():
            target.unlink()
        raise
    return jsonify(attachment={"id": upload_id, "name": original_name,
                               "mime_type": mime_type, "size": len(data)}), 201


@app.get("/api/files/<upload_id>")
@login_required
def download_file(upload_id):
    if not re.fullmatch(r"[a-f0-9]{32}", upload_id):
        abort(404)
    item = db().execute("SELECT * FROM uploads WHERE id = ?", (upload_id,)).fetchone()
    if item is None:
        abort(404)
    user_id = session["user_id"]
    if item["conversation_type"] == "dm":
        permitted = may_access_dm(user_id, item["conversation_id"])
    else:
        permitted = db().execute(
            """SELECT 1 FROM message_uploads mu JOIN messages m ON m.id = mu.message_id
               WHERE mu.upload_id = ? AND m.conversation_id = ? AND m.conversation_type = 'channel'""",
            (upload_id, item["conversation_id"]),
        ).fetchone() is not None or item["uploader_id"] == user_id
    if not permitted:
        abort(403)
    path = FILE_STORAGE / item["stored_name"]
    if not path.is_file():
        abort(404)
    return send_file(path, mimetype=item["mime_type"], as_attachment=True,
                     download_name=item["original_name"], conditional=True)


@app.get("/api/health")
def health():
    return jsonify(status="ok", app="Loop")


@socketio.on("connect")
def socket_connect(_auth=None):
    user = current_user()
    if user is None:
        return False
    with presence_lock:
        was_online = bool(active_sids[user["id"]])
        active_sids[user["id"]].add(request.sid)
    join_room("user:" + str(user["id"]))
    if not was_online:
        emit("presence", {"user_id": user["id"], "online": True}, broadcast=True)


@socketio.on("disconnect")
def socket_disconnect(_reason=None):
    user = current_user()
    if user is None:
        return
    with presence_lock:
        active_sids[user["id"]].discard(request.sid)
        online = bool(active_sids[user["id"]])
        if not online:
            active_sids.pop(user["id"], None)
    message_times.pop(request.sid, None)
    if not online:
        emit("presence", {"user_id": user["id"], "online": False}, broadcast=True)


@socketio.on("join_conversation")
def socket_join_conversation(payload):
    user = current_user()
    if user is None:
        return
    kind = (payload or {}).get("type")
    try:
        conversation_id = int((payload or {}).get("id"))
    except (TypeError, ValueError):
        emit("notice", {"error": "That conversation is invalid."})
        return
    if kind == "channel":
        allowed = may_access_channel(user["id"], conversation_id)
    elif kind == "dm":
        allowed = may_access_dm(user["id"], conversation_id)
    else:
        allowed = False
    if not allowed:
        emit("notice", {"error": "You do not have access to that conversation."})
        return
    join_room(conversation_room(kind, conversation_id))


@socketio.on("send_message")
def socket_send_message(payload):
    user = current_user()
    if user is None:
        emit("notice", {"error": "Sign in again to send messages."})
        return
    now = time.monotonic()
    recent = message_times[request.sid]
    while recent and now - recent[0] > 5:
        recent.popleft()
    if len(recent) >= 8:
        emit("notice", {"error": "Slow down for a moment."})
        return
    body = str((payload or {}).get("body", "")).strip()
    kind = (payload or {}).get("type")
    attachment_ids = (payload or {}).get("attachment_ids", [])
    if not isinstance(attachment_ids, list) or len(attachment_ids) > 5:
        emit("notice", {"error": "Attach up to five files per message."})
        return
    try:
        conversation_id = int((payload or {}).get("id"))
    except (TypeError, ValueError):
        emit("notice", {"error": "Choose a conversation first."})
        return
    if (not body and not attachment_ids) or len(body) > MAX_MESSAGE_LENGTH:
        emit("notice", {"error": "Write a message or attach a file."})
        return
    if kind == "channel":
        allowed = may_access_channel(user["id"], conversation_id)
    elif kind == "dm":
        allowed = may_access_dm(user["id"], conversation_id)
    else:
        allowed = False
    if not allowed:
        emit("notice", {"error": "Conversation not found."})
        return
    uploads = []
    for upload_id in attachment_ids:
        if not isinstance(upload_id, str) or not re.fullmatch(r"[a-f0-9]{32}", upload_id):
            emit("notice", {"error": "An attachment reference is invalid."})
            return
        upload = db().execute(
            """SELECT id FROM uploads WHERE id = ? AND uploader_id = ?
               AND conversation_type = ? AND conversation_id = ? AND message_id IS NULL""",
            (upload_id, user["id"], kind, conversation_id),
        ).fetchone()
        if upload is None:
            emit("notice", {"error": "An attachment expired or belongs to another conversation."})
            return
        uploads.append(upload_id)
    recent.append(now)
    created = datetime.now(timezone.utc).isoformat()
    cursor = db().execute(
        "INSERT INTO messages(conversation_type, conversation_id, sender_id, body, created_at) VALUES (?, ?, ?, ?, ?)",
        (kind, conversation_id, user["id"], body, created),
    )
    for upload_id in uploads:
        db().execute("INSERT INTO message_uploads(message_id, upload_id) VALUES (?, ?)", (cursor.lastrowid, upload_id))
        db().execute("UPDATE uploads SET message_id = ? WHERE id = ?", (cursor.lastrowid, upload_id))
    db().commit()
    row = db().execute(
        """SELECT m.*, u.username, u.display_name, u.banner, u.avatar_path
           FROM messages m JOIN users u ON u.id = m.sender_id WHERE m.id = ?""",
        (cursor.lastrowid,),
    ).fetchone()
    emit("new_message", message_payload(row), room=conversation_room(kind, conversation_id))


@socketio.on("typing")
def socket_typing(payload):
    user = current_user()
    if user is None:
        return
    kind = (payload or {}).get("type")
    try:
        conversation_id = int((payload or {}).get("id"))
    except (TypeError, ValueError):
        return
    if kind == "channel":
        allowed = db().execute("SELECT 1 FROM channels WHERE id = ?", (conversation_id,)).fetchone() is not None
    elif kind == "dm":
        allowed = may_access_dm(user["id"], conversation_id)
    else:
        allowed = False
    if allowed:
        emit("typing", {"user_id": user["id"], "display_name": user["display_name"]},
             room=conversation_room(kind, conversation_id), include_self=False)


@socketio.on("edit_message")
def socket_edit_message(payload):
    user = current_user()
    if user is None:
        return
    try:
        message_id = int((payload or {}).get("message_id"))
    except (TypeError, ValueError):
        return
    body = str((payload or {}).get("body", "")).strip()
    if not body or len(body) > MAX_MESSAGE_LENGTH:
        emit("notice", {"error": "Edited messages must be 1-2000 characters."})
        return
    row = db().execute("SELECT * FROM messages WHERE id = ? AND sender_id = ?", (message_id, user["id"])).fetchone()
    if row is None:
        emit("notice", {"error": "Only your own messages can be edited."})
        return
    db().execute("UPDATE messages SET body = ?, edited_at = ? WHERE id = ?",
                 (body, datetime.now(timezone.utc).isoformat(), message_id))
    db().commit()
    updated = db().execute(
        """SELECT m.*, u.username, u.display_name, u.banner, u.avatar_path
           FROM messages m JOIN users u ON u.id = m.sender_id WHERE m.id = ?""",
        (message_id,),
    ).fetchone()
    emit("message_updated", message_payload(updated),
         room=conversation_room(row["conversation_type"], row["conversation_id"]))


@socketio.on("delete_message")
def socket_delete_message(payload):
    user = current_user()
    if user is None:
        return
    try:
        message_id = int((payload or {}).get("message_id"))
    except (TypeError, ValueError):
        return
    row = db().execute("SELECT * FROM messages WHERE id = ? AND sender_id = ?", (message_id, user["id"])).fetchone()
    if row is None:
        emit("notice", {"error": "Only your own messages can be deleted."})
        return
    db().execute("DELETE FROM messages WHERE id = ?", (message_id,))
    db().commit()
    emit("message_deleted", {"id": message_id},
         room=conversation_room(row["conversation_type"], row["conversation_id"]))


@app.errorhandler(413)
def upload_too_large(_error):
    return jsonify(error="Upload is too large. Images must be 3 MB or smaller."), 413


initialize_database()


if __name__ == "__main__":
    host = os.environ.get("LOOP_HOST", "0.0.0.0")
    port = int(os.environ.get("LOOP_PORT", "5000"))
    print("Loop is running on http://127.0.0.1:" + str(port))
    print("For another device on your Wi-Fi, use this PC's local IP address and port " + str(port) + ".")
    socketio.run(app, host=host, port=port, debug=False, allow_unsafe_werkzeug=True)