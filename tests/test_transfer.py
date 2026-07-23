"""포인트 송금 테스트 (TDD)."""
from conftest import signup_and_login, register

PW = 'Password123'


def balance(app_module, username):
    with app_module.app.app_context():
        return app_module.get_db().execute(
            'SELECT balance FROM user WHERE username = ?', (username,)).fetchone()['balance']


def do_transfer(client, to_username, amount, password=PW):
    return client.post('/transfer', data={
        'username': to_username, 'amount': str(amount), 'password': password,
    }, follow_redirects=True)


def test_wallet_requires_login(client):
    resp = client.get('/wallet')
    assert resp.status_code == 302


def test_transfer_moves_points(client, app_module):
    register(client, 'bob01', PW)
    signup_and_login(client, 'alice01', PW)
    before_alice = balance(app_module, 'alice01')
    before_bob = balance(app_module, 'bob01')
    do_transfer(client, 'bob01', 1000)
    assert balance(app_module, 'alice01') == before_alice - 1000
    assert balance(app_module, 'bob01') == before_bob + 1000


def test_transfer_records_history(client, app_module):
    register(client, 'bob01', PW)
    signup_and_login(client, 'alice01', PW)
    do_transfer(client, 'bob01', 500)
    with app_module.app.app_context():
        row = app_module.get_db().execute(
            'SELECT * FROM transfer WHERE amount = 500').fetchone()
    assert row is not None


def test_transfer_requires_correct_password(client, app_module):
    register(client, 'bob01', PW)
    signup_and_login(client, 'alice01', PW)
    before = balance(app_module, 'alice01')
    do_transfer(client, 'bob01', 1000, password='WrongPass999')
    assert balance(app_module, 'alice01') == before  # 변화 없음


def test_transfer_insufficient_balance_rejected(client, app_module):
    register(client, 'bob01', PW)
    signup_and_login(client, 'alice01', PW)
    before = balance(app_module, 'alice01')
    do_transfer(client, 'bob01', before + 1)  # 잔액 초과
    assert balance(app_module, 'alice01') == before


def test_transfer_negative_amount_rejected(client, app_module):
    register(client, 'bob01', PW)
    signup_and_login(client, 'alice01', PW)
    before_alice = balance(app_module, 'alice01')
    before_bob = balance(app_module, 'bob01')
    do_transfer(client, 'bob01', -1000)  # 음수 송금 시도
    assert balance(app_module, 'alice01') == before_alice
    assert balance(app_module, 'bob01') == before_bob


def test_transfer_zero_amount_rejected(client, app_module):
    register(client, 'bob01', PW)
    signup_and_login(client, 'alice01', PW)
    before = balance(app_module, 'alice01')
    do_transfer(client, 'bob01', 0)
    assert balance(app_module, 'alice01') == before


def test_cannot_transfer_to_self(client, app_module):
    signup_and_login(client, 'alice01', PW)
    before = balance(app_module, 'alice01')
    do_transfer(client, 'alice01', 1000)
    assert balance(app_module, 'alice01') == before


def test_transfer_to_nonexistent_user_rejected(client, app_module):
    signup_and_login(client, 'alice01', PW)
    before = balance(app_module, 'alice01')
    do_transfer(client, 'ghost99', 1000)
    assert balance(app_module, 'alice01') == before
