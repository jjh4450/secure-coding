"""인증/세션 보안 테스트 (TDD)."""
from conftest import register, login, signup_and_login


def test_register_success_redirects_to_login(client):
    resp = register(client)
    assert resp.status_code == 200
    assert '로그인' in resp.get_data(as_text=True)


def test_register_stores_hashed_password(client, app_module):
    register(client, 'bob01', 'Password123')
    with app_module.app.app_context():
        row = app_module.get_db().execute(
            'SELECT password_hash FROM user WHERE username = ?', ('bob01',)
        ).fetchone()
    assert row is not None
    # 평문 저장 금지: 해시가 원문과 달라야 하고 pbkdf2 접두사를 가진다
    assert row['password_hash'] != 'Password123'
    assert row['password_hash'].startswith('pbkdf2:') or row['password_hash'].startswith('scrypt:')


def test_register_rejects_duplicate_username(client):
    register(client, 'carol01', 'Password123')
    resp = register(client, 'carol01', 'Password123')
    assert '이미 존재' in resp.get_data(as_text=True)


def test_register_rejects_short_username(client, app_module):
    register(client, 'ab', 'Password123')
    with app_module.app.app_context():
        row = app_module.get_db().execute(
            'SELECT * FROM user WHERE username = ?', ('ab',)).fetchone()
    assert row is None


def test_register_rejects_weak_password(client, app_module):
    register(client, 'dave01', 'short')          # 8자 미만
    register(client, 'dave02', 'allletters')     # 숫자 없음
    with app_module.app.app_context():
        rows = app_module.get_db().execute(
            "SELECT * FROM user WHERE username IN ('dave01','dave02')").fetchall()
    assert rows == []


def test_login_success_sets_session(client):
    register(client)
    resp = login(client)
    assert '로그인 성공' in resp.get_data(as_text=True)
    with client.session_transaction() as sess:
        assert 'user_id' in sess


def test_login_wrong_password_fails(client):
    register(client)
    resp = login(client, password='WrongPass999')
    assert '올바르지 않습니다' in resp.get_data(as_text=True)
    with client.session_transaction() as sess:
        assert 'user_id' not in sess


def test_login_nonexistent_user_fails(client):
    resp = login(client, 'ghost01', 'Password123')
    assert '올바르지 않습니다' in resp.get_data(as_text=True)


def test_logout_clears_session(client):
    signup_and_login(client)
    client.post('/logout')
    with client.session_transaction() as sess:
        assert 'user_id' not in sess


def test_logout_requires_post(client):
    # GET 로그아웃은 허용하지 않는다(CSRF 방지 목적)
    signup_and_login(client)
    resp = client.get('/logout')
    assert resp.status_code == 405


def test_dashboard_requires_login(client):
    resp = client.get('/dashboard')
    assert resp.status_code == 302
    assert '/login' in resp.headers['Location']


def test_login_lockout_after_repeated_failures(client, app_module):
    register(client, 'eve01', 'Password123')
    # rate limit은 테스트에서 꺼져 있으므로 계정 잠금(5회) 로직만 검증
    for _ in range(5):
        login(client, 'eve01', 'WrongPass999')
    resp = login(client, 'eve01', 'Password123')  # 올바른 비번이어도 잠금 상태
    assert '너무 많' in resp.get_data(as_text=True)


def test_dormant_user_cannot_login(client, app_module):
    register(client, 'frank01', 'Password123')
    with app_module.app.app_context():
        db = app_module.get_db()
        db.execute("UPDATE user SET is_dormant = 1 WHERE username = ?", ('frank01',))
        db.commit()
    resp = login(client, 'frank01', 'Password123')
    assert '휴면' in resp.get_data(as_text=True)
    with client.session_transaction() as sess:
        assert 'user_id' not in sess
