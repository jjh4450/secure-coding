"""보안 회귀 테스트 — 헤더/세션/XSS/CSRF/접근 제어."""
from conftest import signup_and_login, register

PW = 'Password123'


# --- 보안 헤더 ---
def test_security_headers_present(client):
    resp = client.get('/')
    assert 'Content-Security-Policy' in resp.headers
    assert resp.headers['X-Frame-Options'] == 'DENY'
    assert resp.headers['X-Content-Type-Options'] == 'nosniff'
    assert resp.headers['Referrer-Policy'] == 'same-origin'


def test_csp_disallows_inline_scripts(client):
    csp = client.get('/').headers['Content-Security-Policy']
    assert "'unsafe-inline'" not in csp
    assert "script-src 'self'" in csp


# --- 세션 쿠키 ---
def test_session_cookie_flags(client):
    register(client, 'alice01', PW)
    resp = client.post('/login', data={'username': 'alice01', 'password': PW})
    cookie = resp.headers.get('Set-Cookie', '')
    assert 'HttpOnly' in cookie
    assert 'SameSite=Lax' in cookie


# --- XSS ---
def test_product_title_xss_escaped(client):
    signup_and_login(client, 'alice01', PW)
    payload = '<script>alert(1)</script>'
    client.post('/product/new', data={
        'title': payload, 'description': '설명', 'price': '1000',
    }, follow_redirects=True)
    body = client.get('/dashboard').get_data(as_text=True)
    assert '<script>alert(1)</script>' not in body       # 원문 그대로 노출 금지
    assert '&lt;script&gt;' in body                       # 이스케이프되어 렌더링


def test_bio_xss_escaped(client):
    signup_and_login(client, 'alice01', PW)
    client.post('/profile', data={
        'action': 'bio', 'bio': '<img src=x onerror=alert(1)>',
    }, follow_redirects=True)
    body = client.get('/profile').get_data(as_text=True)
    assert '<img src=x onerror=' not in body
    assert '&lt;img' in body


# --- CSRF ---
def test_csrf_blocks_post_without_token(app_module, client):
    register(client, 'alice01', PW)
    # CSRF를 실제로 켜고 토큰 없는 POST가 거부되는지 확인
    app_module.app.config['WTF_CSRF_ENABLED'] = True
    try:
        resp = client.post('/login', data={'username': 'alice01', 'password': PW})
        # CSRFError 핸들러가 리다이렉트 처리, 세션 로그인은 실패해야 함
        with client.session_transaction() as sess:
            assert 'user_id' not in sess
        assert resp.status_code in (302, 400)
    finally:
        app_module.app.config['WTF_CSRF_ENABLED'] = False


# --- 접근 제어 ---
def test_protected_routes_require_login(client):
    for path in ['/dashboard', '/profile', '/product/new', '/chat', '/wallet', '/report']:
        resp = client.get(path)
        assert resp.status_code == 302, path
        assert '/login' in resp.headers['Location'], path


def test_admin_routes_forbidden_for_normal_user(client):
    signup_and_login(client, 'alice01', PW)
    for path in ['/admin', '/admin/users', '/admin/products', '/admin/reports']:
        assert client.get(path).status_code == 403, path


# --- 차단/휴면 콘텐츠 노출 방지 ---
def test_blocked_product_hidden_from_dashboard(client, app_module):
    signup_and_login(client, 'seller01', PW)
    client.post('/product/new', data={
        'title': '차단될상품', 'description': '설명', 'price': '1000',
    }, follow_redirects=True)
    with app_module.app.app_context():
        db = app_module.get_db()
        db.execute('UPDATE product SET is_blocked = 1')
        db.commit()
    client.post('/logout')
    signup_and_login(client, 'buyer01', PW)
    body = client.get('/dashboard').get_data(as_text=True)
    assert '차단될상품' not in body


def test_blocked_product_detail_redirects_for_others(client, app_module):
    signup_and_login(client, 'seller01', PW)
    client.post('/product/new', data={
        'title': '차단될상품', 'description': '설명', 'price': '1000',
    }, follow_redirects=True)
    with app_module.app.app_context():
        db = app_module.get_db()
        pid = db.execute('SELECT id FROM product').fetchone()['id']
        db.execute('UPDATE product SET is_blocked = 1')
        db.commit()
    client.post('/logout')
    signup_and_login(client, 'buyer01', PW)
    resp = client.get(f'/product/{pid}', follow_redirects=True)
    assert '조회할 수 없는 상품' in resp.get_data(as_text=True)


def test_dormant_seller_products_hidden(client, app_module):
    signup_and_login(client, 'seller01', PW)
    client.post('/product/new', data={
        'title': '휴면판매자상품', 'description': '설명', 'price': '1000',
    }, follow_redirects=True)
    with app_module.app.app_context():
        db = app_module.get_db()
        db.execute("UPDATE user SET is_dormant = 1 WHERE username = 'seller01'")
        db.commit()
    client.post('/logout')
    signup_and_login(client, 'buyer01', PW)
    body = client.get('/dashboard').get_data(as_text=True)
    assert '휴면판매자상품' not in body


# --- 오류 처리 ---
def test_404_does_not_leak_internals(client):
    resp = client.get('/no-such-page')
    assert resp.status_code == 404
    body = resp.get_data(as_text=True)
    assert 'Traceback' not in body
    assert '페이지를 찾을 수 없습니다' in body
