"""pytest 공용 픽스처.

각 테스트는 임시 SQLite DB와 임시 업로드 폴더를 사용하는 격리된 앱 인스턴스에서
실행된다. CSRF와 rate-limit은 테스트 편의를 위해 비활성화한다(보안 로직 자체는
별도 보안 테스트에서 검증).
"""
import os
import tempfile
import importlib

import pytest


@pytest.fixture
def app_module(tmp_path, monkeypatch):
    db_path = tmp_path / 'test.db'
    upload_dir = tmp_path / 'uploads'
    upload_dir.mkdir()
    instance_dir = tmp_path / 'instance'
    instance_dir.mkdir()

    # 앱 임포트 전에 환경변수로 경로/키를 주입해 운영 파일과 격리
    monkeypatch.setenv('SECRET_KEY', 'test-secret-key')
    monkeypatch.setenv('DATABASE', str(db_path))
    monkeypatch.setenv('UPLOAD_DIR', str(upload_dir))
    monkeypatch.setenv('ADMIN_PASSWORD', 'AdminPass123')

    import app as app_mod
    importlib.reload(app_mod)

    app_mod.app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        RATELIMIT_ENABLED=False,
    )
    # 로그인 실패/채팅 속도 제한용 인메모리 상태 초기화
    app_mod._login_failures.clear()
    app_mod._last_chat_at.clear()
    app_mod.init_db()
    return app_mod


@pytest.fixture
def app(app_module):
    return app_module.app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def db(app_module):
    """앱 컨텍스트가 필요한 직접 DB 접근용."""
    with app_module.app.app_context():
        yield app_module.get_db()


def register(client, username='alice01', password='Password123'):
    return client.post('/register', data={
        'username': username,
        'password': password,
        'password2': password,
    }, follow_redirects=True)


def login(client, username='alice01', password='Password123'):
    return client.post('/login', data={
        'username': username,
        'password': password,
    }, follow_redirects=True)


def signup_and_login(client, username='alice01', password='Password123'):
    register(client, username, password)
    return login(client, username, password)
