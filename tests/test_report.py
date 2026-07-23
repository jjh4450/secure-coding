"""신고 + 자동 차단/휴면 테스트 (TDD)."""
from conftest import signup_and_login, register, login


def uid(app_module, username):
    with app_module.app.app_context():
        return app_module.get_db().execute(
            'SELECT id FROM user WHERE username = ?', (username,)).fetchone()['id']


def make_product(client, title='상품'):
    client.post('/product/new', data={
        'title': title, 'description': '설명', 'price': '1000',
    }, follow_redirects=True)


def only_product_id(app_module):
    with app_module.app.app_context():
        return app_module.get_db().execute('SELECT id FROM product').fetchone()['id']


def report_target(client, target_type, target_id, reason='부적절한 게시물입니다'):
    return client.post('/report', data={
        'target_type': target_type, 'target_id': target_id, 'reason': reason,
    }, follow_redirects=True)


def test_report_requires_login(client):
    resp = client.get('/report')
    assert resp.status_code == 302


def test_report_user_creates_record(client, app_module):
    register(client, 'bad01', 'Password123')
    bad_id = uid(app_module, 'bad01')
    signup_and_login(client, 'alice01', 'Password123')
    report_target(client, 'user', bad_id, '사기꾼입니다')
    with app_module.app.app_context():
        row = app_module.get_db().execute(
            'SELECT * FROM report WHERE target_id = ?', (bad_id,)).fetchone()
    assert row is not None
    assert row['reason'] == '사기꾼입니다'


def test_cannot_report_self(client, app_module):
    signup_and_login(client, 'alice01', 'Password123')
    report_target(client, 'user', uid(app_module, 'alice01'))
    with app_module.app.app_context():
        cnt = app_module.get_db().execute('SELECT COUNT(*) AS c FROM report').fetchone()['c']
    assert cnt == 0


def test_cannot_report_own_product(client, app_module):
    signup_and_login(client, 'alice01', 'Password123')
    make_product(client)
    report_target(client, 'product', only_product_id(app_module))
    with app_module.app.app_context():
        cnt = app_module.get_db().execute('SELECT COUNT(*) AS c FROM report').fetchone()['c']
    assert cnt == 0


def test_duplicate_report_rejected(client, app_module):
    register(client, 'bad01', 'Password123')
    bad_id = uid(app_module, 'bad01')
    signup_and_login(client, 'alice01', 'Password123')
    report_target(client, 'user', bad_id)
    report_target(client, 'user', bad_id)  # 같은 대상 재신고
    with app_module.app.app_context():
        cnt = app_module.get_db().execute(
            'SELECT COUNT(*) AS c FROM report WHERE target_id = ?', (bad_id,)).fetchone()['c']
    assert cnt == 1


def test_report_reason_too_short_rejected(client, app_module):
    register(client, 'bad01', 'Password123')
    bad_id = uid(app_module, 'bad01')
    signup_and_login(client, 'alice01', 'Password123')
    report_target(client, 'user', bad_id, 'x')  # 5자 미만
    with app_module.app.app_context():
        cnt = app_module.get_db().execute('SELECT COUNT(*) AS c FROM report').fetchone()['c']
    assert cnt == 0


def test_product_blocked_after_threshold(client, app_module):
    # seller가 상품 등록
    signup_and_login(client, 'seller01', 'Password123')
    make_product(client, '신고될상품')
    pid = only_product_id(app_module)
    client.post('/logout')
    # 서로 다른 3명이 신고 → 자동 차단
    for i in range(3):
        register(client, f'rep{i}', 'Password123')
        login(client, f'rep{i}', 'Password123')
        report_target(client, 'product', pid)
        client.post('/logout')
    with app_module.app.app_context():
        row = app_module.get_db().execute(
            'SELECT is_blocked FROM product WHERE id = ?', (pid,)).fetchone()
    assert row['is_blocked'] == 1


def test_user_dormant_after_threshold(client, app_module):
    register(client, 'target01', 'Password123')
    target_id = uid(app_module, 'target01')
    for i in range(3):
        register(client, f'rep{i}', 'Password123')
        login(client, f'rep{i}', 'Password123')
        report_target(client, 'user', target_id)
        client.post('/logout')
    with app_module.app.app_context():
        row = app_module.get_db().execute(
            'SELECT is_dormant FROM user WHERE id = ?', (target_id,)).fetchone()
    assert row['is_dormant'] == 1


def test_below_threshold_not_blocked(client, app_module):
    signup_and_login(client, 'seller01', 'Password123')
    make_product(client, '상품')
    pid = only_product_id(app_module)
    client.post('/logout')
    for i in range(2):  # 2명만 신고 (임계치 3 미만)
        register(client, f'rep{i}', 'Password123')
        login(client, f'rep{i}', 'Password123')
        report_target(client, 'product', pid)
        client.post('/logout')
    with app_module.app.app_context():
        row = app_module.get_db().execute(
            'SELECT is_blocked FROM product WHERE id = ?', (pid,)).fetchone()
    assert row['is_blocked'] == 0
