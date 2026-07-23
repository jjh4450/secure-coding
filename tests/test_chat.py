"""실시간 채팅(전체 + 1:1) 테스트 (TDD)."""
import time
from conftest import signup_and_login, register


def _uid(app_module, username):
    with app_module.app.app_context():
        return app_module.get_db().execute(
            'SELECT id FROM user WHERE username = ?', (username,)).fetchone()['id']


# --- HTTP 라우트 접근 제어 ---
def test_chat_list_requires_login(client):
    resp = client.get('/chat')
    assert resp.status_code == 302
    assert '/login' in resp.headers['Location']


def test_chat_room_with_self_404(client, app_module):
    signup_and_login(client, 'alice01', 'Password123')
    resp = client.get(f"/chat/{_uid(app_module, 'alice01')}")
    assert resp.status_code == 404


# --- 전체 채팅 ---
def test_global_chat_broadcast_uses_server_username(client, app_module):
    signup_and_login(client, 'alice01', 'Password123')
    sio = app_module.socketio.test_client(app_module.app, flask_test_client=client)
    assert sio.is_connected()
    # 클라이언트가 위조한 username은 무시되고 서버 세션의 username이 사용된다
    sio.emit('send_message', {'username': 'HACKER', 'message': '안녕하세요'})
    received = sio.get_received()
    msgs = [r for r in received if r['name'] == 'message']
    assert msgs
    args = msgs[0]['args']
    payload = args[0] if isinstance(args, list) else args
    assert payload['username'] == 'alice01'
    assert payload['message'] == '안녕하세요'
    sio.disconnect()


def test_global_chat_ignores_unauthenticated(client, app_module):
    # 로그인하지 않은 소켓 연결의 메시지는 브로드캐스트되지 않는다
    sio = app_module.socketio.test_client(app_module.app, flask_test_client=client)
    sio.emit('send_message', {'message': '침입 시도'})
    received = [r for r in sio.get_received() if r['name'] == 'message']
    assert received == []
    sio.disconnect()


def test_global_chat_rate_limited(client, app_module):
    signup_and_login(client, 'alice01', 'Password123')
    sio = app_module.socketio.test_client(app_module.app, flask_test_client=client)
    sio.emit('send_message', {'message': '첫번째'})
    sio.get_received()
    sio.emit('send_message', {'message': '두번째'})  # 0.5초 내 재전송
    received = sio.get_received()
    assert any(r['name'] == 'chat_error' for r in received)
    sio.disconnect()


def test_global_chat_rejects_too_long(client, app_module):
    signup_and_login(client, 'alice01', 'Password123')
    sio = app_module.socketio.test_client(app_module.app, flask_test_client=client)
    sio.emit('send_message', {'message': 'x' * 501})
    received = [r for r in sio.get_received() if r['name'] == 'message']
    assert received == []
    sio.disconnect()


# --- 1:1 채팅 ---
def test_dm_saved_and_delivered(client, app_module):
    register(client, 'bob01', 'Password123')
    bob_id = _uid(app_module, 'bob01')
    signup_and_login(client, 'alice01', 'Password123')
    sio = app_module.socketio.test_client(app_module.app, flask_test_client=client)
    sio.emit('join_dm', {'peer_id': bob_id})
    sio.emit('send_dm', {'peer_id': bob_id, 'message': '거래 가능한가요?'})
    received = [r for r in sio.get_received() if r['name'] == 'dm']
    assert received
    dm_args = received[0]['args']
    dm_payload = dm_args[0] if isinstance(dm_args, list) else dm_args
    assert dm_payload['message'] == '거래 가능한가요?'
    # DB 저장 확인
    with app_module.app.app_context():
        row = app_module.get_db().execute(
            'SELECT * FROM message WHERE content = ?', ('거래 가능한가요?',)).fetchone()
    assert row is not None
    assert row['sender_id'] == _uid(app_module, 'alice01')
    assert row['receiver_id'] == bob_id
    sio.disconnect()


def test_dm_unauthenticated_ignored(client, app_module):
    register(client, 'bob01', 'Password123')
    bob_id = _uid(app_module, 'bob01')
    sio = app_module.socketio.test_client(app_module.app, flask_test_client=client)
    sio.emit('send_dm', {'peer_id': bob_id, 'message': '무단 메시지'})
    with app_module.app.app_context():
        row = app_module.get_db().execute(
            'SELECT * FROM message WHERE content = ?', ('무단 메시지',)).fetchone()
    assert row is None
    sio.disconnect()
