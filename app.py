import os
import re
import time
import uuid
import secrets
import sqlite3
import functools
from datetime import datetime, timedelta

from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, g, abort)
from flask_socketio import SocketIO, emit, join_room
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import RequestEntityTooLarge

# ---------------------------------------------------------------------------
# 경로/설정 (테스트를 위해 환경변수로 오버라이드 가능)
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.environ.get('INSTANCE_DIR', os.path.join(BASE_DIR, 'instance'))
UPLOAD_DIR = os.environ.get('UPLOAD_DIR', os.path.join(BASE_DIR, 'static', 'uploads'))
DATABASE = os.environ.get('DATABASE', os.path.join(BASE_DIR, 'market.db'))
os.makedirs(INSTANCE_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

# 정책 상수
REPORT_THRESHOLD = 3       # 서로 다른 신고자 수가 이 값 이상이면 자동 제재
STARTING_BALANCE = 10000   # 신규 가입 지급 포인트
CHAT_MIN_INTERVAL = 0.5    # 채팅 도배 방지: 메시지 간 최소 간격(초)
MAX_UPLOAD = 2 * 1024 * 1024


def load_secret_key():
    """SECRET_KEY는 환경변수 우선, 없으면 instance/에 랜덤 생성 후 재사용.
    (하드코딩된 키는 세션 위조로 이어지므로 코드에 두지 않는다)"""
    env_key = os.environ.get('SECRET_KEY')
    if env_key:
        return env_key
    key_path = os.path.join(INSTANCE_DIR, 'secret_key')
    if os.path.exists(key_path):
        with open(key_path) as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    with open(key_path, 'w') as f:
        f.write(key)
    return key


app = Flask(__name__)
app.config.update(
    SECRET_KEY=load_secret_key(),
    DATABASE=DATABASE,
    UPLOAD_DIR=UPLOAD_DIR,
    MAX_CONTENT_LENGTH=MAX_UPLOAD,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE', '0') == '1',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    RATELIMIT_ENABLED=os.environ.get('RATELIMIT_ENABLED', '1') != '0',
)

csrf = CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app, storage_uri='memory://')

# 로컬 개발 기준 허용 origin (Cross-Site WebSocket Hijacking 방지)
ALLOWED_ORIGINS = os.environ.get(
    'ALLOWED_ORIGINS',
    'http://localhost:5000,http://127.0.0.1:5000'
).split(',')
socketio = SocketIO(app, cors_allowed_origins=ALLOWED_ORIGINS)

# 인메모리 상태(개발용): 로그인 실패 잠금 / 채팅 속도 제한
_login_failures = {}
_last_chat_at = {}


# ---------------------------------------------------------------------------
# 데이터베이스
# ---------------------------------------------------------------------------
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys = ON')
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def now_str():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def init_db():
    with app.app_context():
        db = get_db()
        db.executescript("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                bio TEXT NOT NULL DEFAULT '',
                is_admin INTEGER NOT NULL DEFAULT 0,
                is_dormant INTEGER NOT NULL DEFAULT 0,
                balance INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price INTEGER NOT NULL,
                image_path TEXT,
                seller_id TEXT NOT NULL REFERENCES user(id),
                is_blocked INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL REFERENCES user(id),
                target_type TEXT NOT NULL CHECK (target_type IN ('user', 'product')),
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL,
                UNIQUE (reporter_id, target_type, target_id)
            );
            CREATE TABLE IF NOT EXISTS message (
                id TEXT PRIMARY KEY,
                room_id TEXT NOT NULL,
                sender_id TEXT NOT NULL REFERENCES user(id),
                receiver_id TEXT NOT NULL REFERENCES user(id),
                content TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS transfer (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL REFERENCES user(id),
                receiver_id TEXT NOT NULL REFERENCES user(id),
                amount INTEGER NOT NULL CHECK (amount > 0),
                created_at TEXT NOT NULL
            );
        """)
        # 관리자 계정 부트스트랩 (하드코딩 금지)
        if db.execute('SELECT 1 FROM user WHERE is_admin = 1 LIMIT 1').fetchone() is None:
            admin_pw = os.environ.get('ADMIN_PASSWORD')
            generated = admin_pw is None
            if generated:
                admin_pw = secrets.token_urlsafe(9)
            db.execute(
                'INSERT INTO user (id, username, password_hash, bio, is_admin, balance, created_at) '
                'VALUES (?, ?, ?, ?, 1, ?, ?)',
                (str(uuid.uuid4()), 'admin', generate_password_hash(admin_pw),
                 '플랫폼 관리자', STARTING_BALANCE, now_str()))
            if generated:
                print(f'[init] admin 계정 생성 — 비밀번호: {admin_pw} (최초 1회만 출력)')
        db.commit()


# ---------------------------------------------------------------------------
# 입력 검증 헬퍼
# ---------------------------------------------------------------------------
USERNAME_RE = re.compile(r'^[A-Za-z0-9_]{4,20}$')


def valid_username(v):
    return bool(USERNAME_RE.fullmatch(v or ''))


def valid_password(v):
    if not v or not (8 <= len(v) <= 72):
        return False
    return bool(re.search(r'[A-Za-z]', v)) and bool(re.search(r'\d', v))


def parse_price(v):
    try:
        price = int(str(v).strip())
    except (TypeError, ValueError):
        return None
    return price if 0 < price <= 100_000_000 else None


def clean_text(v, max_len):
    v = (v or '').strip()
    return v if v and len(v) <= max_len else None


# ---------------------------------------------------------------------------
# 인증/권한
# ---------------------------------------------------------------------------
@app.before_request
def load_current_user():
    g.user = None
    user_id = session.get('user_id')
    if user_id:
        row = get_db().execute('SELECT * FROM user WHERE id = ?', (user_id,)).fetchone()
        if row is None or row['is_dormant']:
            # 삭제되었거나 휴면 전환된 계정은 즉시 세션 무효화
            session.clear()
            if row is not None:
                flash('휴면 계정으로 전환되어 로그아웃되었습니다.')
        else:
            g.user = row


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            flash('로그인이 필요합니다.')
            return redirect(url_for('login'))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            flash('로그인이 필요합니다.')
            return redirect(url_for('login'))
        if not g.user['is_admin']:
            abort(403)
        return view(*args, **kwargs)
    return wrapped


# ---------------------------------------------------------------------------
# 보안 헤더 / 오류 처리
# ---------------------------------------------------------------------------
@app.after_request
def set_security_headers(resp):
    resp.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.socket.io; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self' ws: wss:; "
        "frame-ancestors 'none'; "
        "form-action 'self'"
    )
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['Referrer-Policy'] = 'same-origin'
    return resp


@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', code=403, message='접근 권한이 없습니다.'), 403


@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', code=404, message='페이지를 찾을 수 없습니다.'), 404


@app.errorhandler(500)
def server_error(e):
    # 스택트레이스 등 내부 정보를 사용자에게 노출하지 않는다
    return render_template('error.html', code=500, message='서버 오류가 발생했습니다.'), 500


@app.errorhandler(CSRFError)
def csrf_error(e):
    flash('보안 토큰이 유효하지 않습니다. 다시 시도해주세요.')
    return redirect(request.referrer or url_for('index'))


@app.errorhandler(RequestEntityTooLarge)
def too_large(e):
    flash('업로드 파일이 너무 큽니다. (최대 2MB)')
    return redirect(request.referrer or url_for('index'))


# ---------------------------------------------------------------------------
# 기본 / 인증 라우트
# ---------------------------------------------------------------------------
@app.route('/')
def index():
    if g.user:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit('20 per hour', methods=['POST'])
def register():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        password2 = request.form.get('password2') or ''
        if not valid_username(username):
            flash('사용자명은 영문/숫자/_ 4~20자여야 합니다.')
            return redirect(url_for('register'))
        if not valid_password(password):
            flash('비밀번호는 8~72자이며 영문과 숫자를 모두 포함해야 합니다.')
            return redirect(url_for('register'))
        if password != password2:
            flash('비밀번호 확인이 일치하지 않습니다.')
            return redirect(url_for('register'))
        db = get_db()
        try:
            db.execute(
                'INSERT INTO user (id, username, password_hash, balance, created_at) '
                'VALUES (?, ?, ?, ?, ?)',
                (str(uuid.uuid4()), username, generate_password_hash(password),
                 STARTING_BALANCE, now_str()))
            db.commit()
        except sqlite3.IntegrityError:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit('10 per minute', methods=['POST'])
def login():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''

        # 계정 단위 잠금: 5회 연속 실패 시 5분 잠금 (브루트포스 방어)
        fails, locked_until = _login_failures.get(username, (0, 0))
        if time.time() < locked_until:
            flash('로그인 시도가 너무 많습니다. 잠시 후 다시 시도해주세요.')
            return redirect(url_for('login'))

        user = get_db().execute(
            'SELECT * FROM user WHERE username = ?', (username,)).fetchone()
        if user is None or not check_password_hash(user['password_hash'], password):
            fails += 1
            locked = time.time() + 300 if fails >= 5 else 0
            _login_failures[username] = (fails, locked)
            # 계정 존재 여부를 구분할 수 없는 동일한 오류 메시지
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))
        if user['is_dormant']:
            flash('신고 누적으로 휴면 처리된 계정입니다. 관리자에게 문의하세요.')
            return redirect(url_for('login'))

        _login_failures.pop(username, None)
        session.clear()  # 세션 고정(session fixation) 방지: 로그인 시 세션 재발급
        session['user_id'] = user['id']
        session.permanent = True
        flash('로그인 성공!')
        return redirect(url_for('dashboard'))
    return render_template('login.html')


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    session.clear()
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))


# ---------------------------------------------------------------------------
# 대시보드 (상품 목록 + 검색) — 검색 로직은 후속 단계에서 확장
# ---------------------------------------------------------------------------
@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    q = (request.args.get('q') or '').strip()
    sql = ('SELECT p.*, u.username AS seller_name FROM product p '
           'JOIN user u ON u.id = p.seller_id '
           'WHERE p.is_blocked = 0 AND u.is_dormant = 0')
    params = []
    if q:
        q = q[:100]
        escaped = q.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
        sql += " AND p.title LIKE ? ESCAPE '\\'"
        params.append(f'%{escaped}%')
    sql += ' ORDER BY p.created_at DESC'
    products = db.execute(sql, params).fetchall()
    return render_template('dashboard.html', products=products, q=q)


# ===== FEATURE ROUTES INSERTED BELOW =====


if __name__ == '__main__':
    init_db()
    debug = os.environ.get('FLASK_DEBUG', '0') == '1'  # 기본값: debug 비활성화
    socketio.run(app, host='127.0.0.1', port=5000, debug=debug)
