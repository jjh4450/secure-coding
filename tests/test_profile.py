"""프로필/마이페이지/타 유저 조회 테스트 (TDD)."""
from conftest import signup_and_login, register


def test_profile_requires_login(client):
    resp = client.get('/profile')
    assert resp.status_code == 302
    assert '/login' in resp.headers['Location']


def test_update_bio(client, app_module):
    signup_and_login(client, 'alice01', 'Password123')
    client.post('/profile', data={'action': 'bio', 'bio': '안녕하세요 앨리스입니다'},
                follow_redirects=True)
    with app_module.app.app_context():
        row = app_module.get_db().execute(
            'SELECT bio FROM user WHERE username = ?', ('alice01',)).fetchone()
    assert row['bio'] == '안녕하세요 앨리스입니다'


def test_bio_too_long_rejected(client, app_module):
    signup_and_login(client, 'alice01', 'Password123')
    client.post('/profile', data={'action': 'bio', 'bio': 'x' * 501},
                follow_redirects=True)
    with app_module.app.app_context():
        row = app_module.get_db().execute(
            'SELECT bio FROM user WHERE username = ?', ('alice01',)).fetchone()
    assert row['bio'] == ''


def test_change_password_requires_current(client, app_module):
    signup_and_login(client, 'alice01', 'Password123')
    # 현재 비밀번호가 틀리면 변경 실패
    client.post('/profile', data={
        'action': 'password',
        'current_password': 'WrongPass999',
        'new_password': 'NewPass456',
    }, follow_redirects=True)
    from werkzeug.security import check_password_hash
    with app_module.app.app_context():
        row = app_module.get_db().execute(
            'SELECT password_hash FROM user WHERE username = ?', ('alice01',)).fetchone()
    assert check_password_hash(row['password_hash'], 'Password123')
    assert not check_password_hash(row['password_hash'], 'NewPass456')


def test_change_password_success(client, app_module):
    signup_and_login(client, 'alice01', 'Password123')
    client.post('/profile', data={
        'action': 'password',
        'current_password': 'Password123',
        'new_password': 'NewPass456',
    }, follow_redirects=True)
    from werkzeug.security import check_password_hash
    with app_module.app.app_context():
        row = app_module.get_db().execute(
            'SELECT password_hash FROM user WHERE username = ?', ('alice01',)).fetchone()
    assert check_password_hash(row['password_hash'], 'NewPass456')


def test_change_password_weak_rejected(client, app_module):
    signup_and_login(client, 'alice01', 'Password123')
    client.post('/profile', data={
        'action': 'password',
        'current_password': 'Password123',
        'new_password': 'weak',
    }, follow_redirects=True)
    from werkzeug.security import check_password_hash
    with app_module.app.app_context():
        row = app_module.get_db().execute(
            'SELECT password_hash FROM user WHERE username = ?', ('alice01',)).fetchone()
    assert check_password_hash(row['password_hash'], 'Password123')


def test_view_other_user_profile(client, app_module):
    register(client, 'bob01', 'Password123')
    with app_module.app.app_context():
        bob = app_module.get_db().execute(
            'SELECT id FROM user WHERE username = ?', ('bob01',)).fetchone()
    signup_and_login(client, 'alice01', 'Password123')
    resp = client.get(f"/user/{bob['id']}")
    assert resp.status_code == 200
    assert 'bob01' in resp.get_data(as_text=True)


def test_view_nonexistent_user_404(client):
    signup_and_login(client, 'alice01', 'Password123')
    resp = client.get('/user/nonexistent-id')
    assert resp.status_code == 404
