"""관리자 기능 테스트 (TDD)."""
from conftest import signup_and_login, register, login

PW = 'Password123'
ADMIN_PW = 'AdminPass123'  # conftest에서 ADMIN_PASSWORD 환경변수로 주입


def uid(app_module, username):
    with app_module.app.app_context():
        return app_module.get_db().execute(
            'SELECT id FROM user WHERE username = ?', (username,)).fetchone()['id']


def login_admin(client):
    return login(client, 'admin', ADMIN_PW)


def test_admin_home_requires_admin(client):
    # 비로그인 → 로그인으로 리다이렉트
    resp = client.get('/admin')
    assert resp.status_code == 302


def test_normal_user_forbidden_from_admin(client):
    signup_and_login(client, 'alice01', PW)
    resp = client.get('/admin')
    assert resp.status_code == 403


def test_admin_can_access_home(client):
    login_admin(client)
    resp = client.get('/admin')
    assert resp.status_code == 200


def test_admin_lists_users(client):
    register(client, 'alice01', PW)
    login_admin(client)
    resp = client.get('/admin/users')
    assert resp.status_code == 200
    assert 'alice01' in resp.get_data(as_text=True)


def test_admin_toggle_dormant(client, app_module):
    register(client, 'alice01', PW)
    alice_id = uid(app_module, 'alice01')
    login_admin(client)
    client.post(f'/admin/users/{alice_id}/dormant', data={'state': '1'},
                follow_redirects=True)
    with app_module.app.app_context():
        row = app_module.get_db().execute(
            'SELECT is_dormant FROM user WHERE id = ?', (alice_id,)).fetchone()
    assert row['is_dormant'] == 1


def test_admin_cannot_dormant_admin_account(client, app_module):
    login_admin(client)
    admin_id = uid(app_module, 'admin')
    client.post(f'/admin/users/{admin_id}/dormant', follow_redirects=True)
    with app_module.app.app_context():
        row = app_module.get_db().execute(
            'SELECT is_dormant FROM user WHERE id = ?', (admin_id,)).fetchone()
    assert row['is_dormant'] == 0


def test_admin_delete_user(client, app_module):
    register(client, 'alice01', PW)
    alice_id = uid(app_module, 'alice01')
    login_admin(client)
    client.post(f'/admin/users/{alice_id}/delete', follow_redirects=True)
    with app_module.app.app_context():
        row = app_module.get_db().execute(
            'SELECT * FROM user WHERE id = ?', (alice_id,)).fetchone()
    assert row is None


def test_admin_toggle_product_block(client, app_module):
    signup_and_login(client, 'alice01', PW)
    client.post('/product/new', data={
        'title': '상품', 'description': '설명', 'price': '1000'}, follow_redirects=True)
    with app_module.app.app_context():
        pid = app_module.get_db().execute('SELECT id FROM product').fetchone()['id']
    client.post('/logout')
    login_admin(client)
    client.post(f'/admin/products/{pid}/block', data={'state': '1'},
                follow_redirects=True)
    with app_module.app.app_context():
        row = app_module.get_db().execute(
            'SELECT is_blocked FROM product WHERE id = ?', (pid,)).fetchone()
    assert row['is_blocked'] == 1


def test_admin_can_view_reports(client, app_module):
    register(client, 'bad01', PW)
    bad_id = uid(app_module, 'bad01')
    signup_and_login(client, 'alice01', PW)
    client.post('/report', data={
        'target_type': 'user', 'target_id': bad_id, 'reason': '사기 행위 신고'},
        follow_redirects=True)
    client.post('/logout')
    login_admin(client)
    resp = client.get('/admin/reports')
    assert resp.status_code == 200
    assert '사기 행위 신고' in resp.get_data(as_text=True)


def test_normal_user_forbidden_from_admin_action(client, app_module):
    register(client, 'victim01', PW)
    victim_id = uid(app_module, 'victim01')
    signup_and_login(client, 'alice01', PW)
    resp = client.post(f'/admin/users/{victim_id}/dormant')
    assert resp.status_code == 403
    with app_module.app.app_context():
        row = app_module.get_db().execute(
            'SELECT is_dormant FROM user WHERE id = ?', (victim_id,)).fetchone()
    assert row['is_dormant'] == 0
