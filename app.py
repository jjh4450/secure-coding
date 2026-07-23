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


# ---------------------------------------------------------------------------
# 프로필 / 마이페이지 / 타 유저 조회
# ---------------------------------------------------------------------------
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    db = get_db()
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'bio':
            bio = (request.form.get('bio') or '').strip()
            if len(bio) > 500:
                flash('소개글은 500자 이내로 작성해주세요.')
                return redirect(url_for('profile'))
            db.execute('UPDATE user SET bio = ? WHERE id = ?', (bio, g.user['id']))
            db.commit()
            flash('소개글이 업데이트되었습니다.')
        elif action == 'password':
            current = request.form.get('current_password') or ''
            new = request.form.get('new_password') or ''
            # 민감 작업(비밀번호 변경)은 현재 비밀번호로 재인증
            if not check_password_hash(g.user['password_hash'], current):
                flash('현재 비밀번호가 올바르지 않습니다.')
                return redirect(url_for('profile'))
            if not valid_password(new):
                flash('새 비밀번호는 8~72자이며 영문과 숫자를 모두 포함해야 합니다.')
                return redirect(url_for('profile'))
            db.execute('UPDATE user SET password_hash = ? WHERE id = ?',
                       (generate_password_hash(new), g.user['id']))
            db.commit()
            flash('비밀번호가 변경되었습니다.')
        return redirect(url_for('profile'))

    my_products = db.execute(
        'SELECT * FROM product WHERE seller_id = ? ORDER BY created_at DESC',
        (g.user['id'],)).fetchall()
    return render_template('profile.html', user=g.user, my_products=my_products)


@app.route('/user/<user_id>')
@login_required
def view_user(user_id):
    db = get_db()
    target = db.execute('SELECT * FROM user WHERE id = ?', (user_id,)).fetchone()
    if target is None:
        abort(404)
    products = db.execute(
        'SELECT * FROM product WHERE seller_id = ? AND is_blocked = 0 '
        'ORDER BY created_at DESC', (user_id,)).fetchall()
    return render_template('user_view.html', target=target, products=products)


# ---------------------------------------------------------------------------
# 상품
# ---------------------------------------------------------------------------
ALLOWED_IMAGE = {
    'png': b'\x89PNG\r\n\x1a\n',
    'jpg': b'\xff\xd8\xff',
    'jpeg': b'\xff\xd8\xff',
    'gif': b'GIF8',
    'webp': None,  # RIFF....WEBP — 별도 검사
}


def save_image(file):
    """이미지 업로드 검증: 확장자 화이트리스트 + 매직바이트 확인 + 랜덤 파일명.
    반환값: (저장경로 또는 None, 오류메시지 또는 None)."""
    if not file or not file.filename:
        return None, None  # 이미지 미첨부는 허용
    ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
    if ext not in ALLOWED_IMAGE:
        return None, '허용되지 않는 이미지 형식입니다. (png/jpg/gif/webp)'
    head = file.stream.read(16)
    file.stream.seek(0)
    if ext == 'webp':
        ok = head[:4] == b'RIFF' and head[8:12] == b'WEBP'
    else:
        ok = head.startswith(ALLOWED_IMAGE[ext])
    if not ok:
        return None, '이미지 파일이 손상되었거나 형식이 올바르지 않습니다.'
    filename = f'{uuid.uuid4().hex}.{ext}'  # 사용자 입력 파일명은 신뢰하지 않는다
    file.save(os.path.join(app.config['UPLOAD_DIR'], filename))
    return f'uploads/{filename}', None


def get_product_or_404(product_id):
    product = get_db().execute(
        'SELECT * FROM product WHERE id = ?', (product_id,)).fetchone()
    if product is None:
        abort(404)
    return product


@app.route('/product/new', methods=['GET', 'POST'])
@login_required
def new_product():
    if request.method == 'POST':
        title = clean_text(request.form.get('title'), 100)
        description = clean_text(request.form.get('description'), 2000)
        price = parse_price(request.form.get('price'))
        if title is None or description is None:
            flash('상품명(100자 이내)과 설명(2000자 이내)을 입력해주세요.')
            return redirect(url_for('new_product'))
        if price is None:
            flash('가격은 1 이상 1억 이하의 정수여야 합니다.')
            return redirect(url_for('new_product'))
        image_path, err = save_image(request.files.get('image'))
        if err:
            flash(err)
            return redirect(url_for('new_product'))
        db = get_db()
        db.execute(
            'INSERT INTO product (id, title, description, price, image_path, seller_id, created_at) '
            'VALUES (?, ?, ?, ?, ?, ?, ?)',
            (str(uuid.uuid4()), title, description, price, image_path,
             g.user['id'], now_str()))
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')


@app.route('/product/<product_id>')
@login_required
def view_product(product_id):
    product = get_product_or_404(product_id)
    is_owner = product['seller_id'] == g.user['id']
    if product['is_blocked'] and not (is_owner or g.user['is_admin']):
        flash('신고 누적으로 차단된 상품입니다.')
        return redirect(url_for('dashboard'))
    seller = get_db().execute(
        'SELECT id, username, bio, is_dormant FROM user WHERE id = ?',
        (product['seller_id'],)).fetchone()
    return render_template('view_product.html', product=product, seller=seller,
                           is_owner=is_owner)


@app.route('/product/<product_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    product = get_product_or_404(product_id)
    # 소유자 검증: 본인 상품(또는 관리자)만 수정 가능 (IDOR 방지)
    if product['seller_id'] != g.user['id'] and not g.user['is_admin']:
        abort(403)
    if request.method == 'POST':
        title = clean_text(request.form.get('title'), 100)
        description = clean_text(request.form.get('description'), 2000)
        price = parse_price(request.form.get('price'))
        if title is None or description is None or price is None:
            flash('입력값을 확인해주세요.')
            return redirect(url_for('edit_product', product_id=product_id))
        image_path, err = save_image(request.files.get('image'))
        if err:
            flash(err)
            return redirect(url_for('edit_product', product_id=product_id))
        db = get_db()
        if image_path:
            db.execute('UPDATE product SET title=?, description=?, price=?, image_path=? WHERE id=?',
                       (title, description, price, image_path, product_id))
        else:
            db.execute('UPDATE product SET title=?, description=?, price=? WHERE id=?',
                       (title, description, price, product_id))
        db.commit()
        flash('상품이 수정되었습니다.')
        return redirect(url_for('view_product', product_id=product_id))
    return render_template('edit_product.html', product=product)


@app.route('/product/<product_id>/delete', methods=['POST'])
@login_required
def delete_product(product_id):
    product = get_product_or_404(product_id)
    if product['seller_id'] != g.user['id'] and not g.user['is_admin']:
        abort(403)
    db = get_db()
    db.execute('DELETE FROM product WHERE id = ?', (product_id,))
    db.commit()
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('dashboard'))


# ---------------------------------------------------------------------------
# 1:1 채팅 (HTTP)
# ---------------------------------------------------------------------------
def dm_room_id(a, b):
    """두 사용자 id를 정렬 조합해 결정적 방 id 생성(순서 무관)."""
    return '|'.join(sorted([a, b]))


@app.route('/chat')
@login_required
def chat_list():
    db = get_db()
    rooms = db.execute(
        """
        SELECT m.room_id,
               MAX(m.created_at) AS last_at,
               (SELECT content FROM message WHERE room_id = m.room_id
                ORDER BY created_at DESC LIMIT 1) AS last_content,
               CASE WHEN m.sender_id = ? THEN m.receiver_id ELSE m.sender_id END AS peer_id
        FROM message m
        WHERE m.sender_id = ? OR m.receiver_id = ?
        GROUP BY m.room_id
        ORDER BY last_at DESC
        """,
        (g.user['id'], g.user['id'], g.user['id'])).fetchall()
    peers = {}
    for r in rooms:
        row = db.execute('SELECT username FROM user WHERE id = ?',
                         (r['peer_id'],)).fetchone()
        peers[r['peer_id']] = row['username'] if row else '(탈퇴한 사용자)'
    return render_template('chat_list.html', rooms=rooms, peers=peers)


@app.route('/chat/<peer_id>')
@login_required
def chat_room(peer_id):
    db = get_db()
    peer = db.execute('SELECT id, username FROM user WHERE id = ?',
                      (peer_id,)).fetchone()
    if peer is None or peer['id'] == g.user['id']:
        abort(404)
    room = dm_room_id(g.user['id'], peer_id)
    messages = db.execute(
        'SELECT m.*, u.username AS sender_name FROM message m '
        'JOIN user u ON u.id = m.sender_id '
        'WHERE m.room_id = ? ORDER BY m.created_at ASC LIMIT 200',
        (room,)).fetchall()
    return render_template('chat_room.html', peer=peer, messages=messages)


# ===== FEATURE ROUTES INSERTED BELOW =====


# ---------------------------------------------------------------------------
# 실시간 채팅 (Socket.IO)
# ---------------------------------------------------------------------------
def socket_user():
    """소켓 이벤트마다 세션 기반 인증 확인. 미인증/휴면이면 None."""
    user_id = session.get('user_id')
    if not user_id:
        return None
    user = get_db().execute('SELECT * FROM user WHERE id = ?', (user_id,)).fetchone()
    if user is None or user['is_dormant']:
        return None
    return user


def chat_rate_limited(user_id):
    now = time.time()
    if now - _last_chat_at.get(user_id, 0) < CHAT_MIN_INTERVAL:
        return True
    _last_chat_at[user_id] = now
    return False


@socketio.on('send_message')
def handle_global_message(data):
    user = socket_user()
    if user is None:
        return  # 미인증 연결의 메시지는 무시(브로드캐스트 안 함)
    if chat_rate_limited(user['id']):
        emit('chat_error', {'message': '메시지를 너무 빠르게 보내고 있습니다.'})
        return
    msg = (data or {}).get('message')
    if not isinstance(msg, str):
        return
    msg = msg.strip()
    if not msg or len(msg) > 500:
        return
    # username은 클라이언트 입력이 아니라 서버 세션에서 결정한다(위조 방지)
    emit('message', {
        'message_id': str(uuid.uuid4()),
        'username': user['username'],
        'message': msg,
    }, broadcast=True)


@socketio.on('join_dm')
def handle_join_dm(data):
    user = socket_user()
    if user is None:
        return
    peer_id = (data or {}).get('peer_id')
    if not isinstance(peer_id, str) or peer_id == user['id']:
        return
    if get_db().execute('SELECT 1 FROM user WHERE id = ?', (peer_id,)).fetchone() is None:
        return
    # 방 id는 두 당사자 id로만 결정되므로, 제3자는 남의 방에 접근할 수 없다
    join_room(dm_room_id(user['id'], peer_id))


@socketio.on('send_dm')
def handle_send_dm(data):
    user = socket_user()
    if user is None:
        return
    if chat_rate_limited(user['id']):
        emit('chat_error', {'message': '메시지를 너무 빠르게 보내고 있습니다.'})
        return
    peer_id = (data or {}).get('peer_id')
    msg = (data or {}).get('message')
    if not isinstance(peer_id, str) or not isinstance(msg, str):
        return
    msg = msg.strip()
    if not msg or len(msg) > 500 or peer_id == user['id']:
        return
    db = get_db()
    if db.execute('SELECT 1 FROM user WHERE id = ?', (peer_id,)).fetchone() is None:
        return
    room = dm_room_id(user['id'], peer_id)
    created = now_str()
    db.execute(
        'INSERT INTO message (id, room_id, sender_id, receiver_id, content, created_at) '
        'VALUES (?, ?, ?, ?, ?, ?)',
        (str(uuid.uuid4()), room, user['id'], peer_id, msg, created))
    db.commit()
    emit('dm', {
        'sender_name': user['username'],
        'message': msg,
        'created_at': created,
    }, to=room)


if __name__ == '__main__':
    init_db()
    debug = os.environ.get('FLASK_DEBUG', '0') == '1'  # 기본값: debug 비활성화
    socketio.run(app, host='127.0.0.1', port=5000, debug=debug)
