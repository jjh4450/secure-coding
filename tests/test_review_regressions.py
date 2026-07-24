"""보안 리뷰(2026-07-24)에서 지적된 A그룹 findings에 대한 회귀 테스트."""
from conftest import signup_and_login, register, login

PW = 'Password123'


def uid(app_module, username):
    with app_module.app.app_context():
        return app_module.get_db().execute(
            'SELECT id FROM user WHERE username = ?', (username,)).fetchone()['id']


def make_product(client, title='상품', price='1000'):
    client.post('/product/new', data={
        'title': title, 'description': '설명입니다', 'price': price},
        follow_redirects=True)


def only_product_id(app_module):
    with app_module.app.app_context():
        return app_module.get_db().execute('SELECT id FROM product').fetchone()['id']


# --- P2-6: CSRF 오류 오픈 리다이렉트 방지 ---
def test_csrf_error_does_not_redirect_offsite(client, app_module):
    register(client, 'alice01', PW)
    app_module.app.config['WTF_CSRF_ENABLED'] = True
    try:
        resp = client.post('/login',
                            data={'username': 'alice01', 'password': PW},
                            headers={'Referer': 'https://evil.example.com/attack'})
        loc = resp.headers.get('Location', '')
        # 외부 도메인으로 리다이렉트되면 안 된다
        assert 'evil.example.com' not in loc
    finally:
        app_module.app.config['WTF_CSRF_ENABLED'] = False


# --- P1-3: 로그인 실패 딕셔너리 메모리 남용 방지 ---
def test_login_oversized_username_not_stored(client, app_module):
    huge = 'x' * 5000
    client.post('/login', data={'username': huge, 'password': 'whatever'})
    # 20자 초과 사용자명은 실패 추적 딕셔너리에 저장되지 않는다
    assert huge not in app_module._login_failures


# --- P2-7: 1:1 채팅은 최신 200개를 보여준다 ---
def test_chat_room_shows_recent_messages(client, app_module):
    register(client, 'bob01', PW)
    bob_id = uid(app_module, 'bob01')
    signup_and_login(client, 'alice01', PW)
    alice_id = uid(app_module, 'alice01')
    room = '|'.join(sorted([alice_id, bob_id]))
    # 205개 메시지를 순서대로 삽입(마지막이 최신)
    with app_module.app.app_context():
        db = app_module.get_db()
        import uuid
        for i in range(205):
            db.execute(
                'INSERT INTO message (id, room_id, sender_id, receiver_id, content, created_at) '
                'VALUES (?, ?, ?, ?, ?, ?)',
                (str(uuid.uuid4()), room, alice_id, bob_id, f'메시지{i:03d}',
                 f'2026-07-24 10:{i // 60:02d}:{i % 60:02d}'))
        db.commit()
    body = client.get(f'/chat/{bob_id}').get_data(as_text=True)
    assert '메시지204' in body       # 최신 메시지 포함
    assert '메시지000' not in body   # 가장 오래된 메시지는 잘림


# --- P2-11: 송금 중 발신자 휴면 처리되면 송금 실패 ---
def test_transfer_blocked_when_sender_dormant(client, app_module):
    register(client, 'bob01', PW)
    signup_and_login(client, 'alice01', PW)
    with app_module.app.app_context():
        db = app_module.get_db()
        db.execute("UPDATE user SET is_dormant = 1 WHERE username = 'alice01'")
        db.commit()
    # 휴면 사용자는 before_request에서 세션이 정리되므로 송금 시 로그인 요구로 리다이렉트
    resp = client.post('/transfer',
                       data={'username': 'bob01', 'amount': '1000', 'password': PW},
                       follow_redirects=False)
    assert resp.status_code == 302
    with app_module.app.app_context():
        bob_bal = app_module.get_db().execute(
            "SELECT balance FROM user WHERE username = 'bob01'").fetchone()['balance']
    assert bob_bal == app_module.STARTING_BALANCE  # 입금되지 않음


# --- P2-5: 휴면 판매자의 상품은 직접 URL/프로필에서 숨겨진다 ---
def test_dormant_seller_product_hidden_on_detail(client, app_module):
    signup_and_login(client, 'seller01', PW)
    make_product(client, '휴면상품')
    pid = only_product_id(app_module)
    client.post('/logout')
    with app_module.app.app_context():
        db = app_module.get_db()
        db.execute("UPDATE user SET is_dormant = 1 WHERE username = 'seller01'")
        db.commit()
    signup_and_login(client, 'buyer01', PW)
    resp = client.get(f'/product/{pid}', follow_redirects=True)
    assert '조회할 수 없는 상품' in resp.get_data(as_text=True)


def test_dormant_seller_products_hidden_on_profile(client, app_module):
    signup_and_login(client, 'seller01', PW)
    make_product(client, '휴면판매자상품')
    seller_id = uid(app_module, 'seller01')
    client.post('/logout')
    with app_module.app.app_context():
        db = app_module.get_db()
        db.execute("UPDATE user SET is_dormant = 1 WHERE username = 'seller01'")
        db.commit()
    signup_and_login(client, 'buyer01', PW)
    body = client.get(f'/user/{seller_id}').get_data(as_text=True)
    assert '휴면판매자상품' not in body


# --- P2-10: 관리자 토글 멱등성 ---
def test_admin_dormant_toggle_idempotent(client, app_module):
    register(client, 'target01', PW)
    target_id = uid(app_module, 'target01')
    login(client, 'admin', 'AdminPass123')
    # 같은 최종 상태(state=1)를 두 번 요청해도 휴면 상태가 유지된다(멱등)
    client.post(f'/admin/users/{target_id}/dormant', data={'state': '1'},
                follow_redirects=True)
    client.post(f'/admin/users/{target_id}/dormant', data={'state': '1'},
                follow_redirects=True)
    with app_module.app.app_context():
        row = app_module.get_db().execute(
            'SELECT is_dormant FROM user WHERE id = ?', (target_id,)).fetchone()
    assert row['is_dormant'] == 1


def test_admin_block_toggle_idempotent(client, app_module):
    signup_and_login(client, 'seller01', PW)
    make_product(client, '상품')
    pid = only_product_id(app_module)
    client.post('/logout')
    login(client, 'admin', 'AdminPass123')
    client.post(f'/admin/products/{pid}/block', data={'state': '1'}, follow_redirects=True)
    client.post(f'/admin/products/{pid}/block', data={'state': '1'}, follow_redirects=True)
    with app_module.app.app_context():
        row = app_module.get_db().execute(
            'SELECT is_blocked FROM product WHERE id = ?', (pid,)).fetchone()
    assert row['is_blocked'] == 1


# --- P2-8: 삭제 폼이 인라인 핸들러 대신 data-confirm + 외부 스크립트 사용 ---
def test_delete_forms_use_external_confirm(client, app_module):
    signup_and_login(client, 'alice01', PW)
    make_product(client, '상품')
    pid = only_product_id(app_module)
    body = client.get(f'/product/{pid}').get_data(as_text=True)
    assert 'onsubmit=' not in body           # CSP가 차단하는 인라인 핸들러 없음
    assert 'data-confirm=' in body           # 외부 스크립트가 처리하는 속성 사용
    assert 'js/confirm.js' in body
