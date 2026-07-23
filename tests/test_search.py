"""상품 검색 테스트 (TDD) — 기능 + SQLi/LIKE 이스케이프 안전성."""
from conftest import signup_and_login


def add(client, title, price='1000'):
    client.post('/product/new', data={
        'title': title, 'description': '설명입니다', 'price': price,
    }, follow_redirects=True)


def test_search_matches_title(client):
    signup_and_login(client, 'alice01', 'Password123')
    add(client, '맥북 프로 16')
    add(client, '아이폰 15 프로')
    add(client, '갤럭시 버즈')

    resp = client.get('/dashboard?q=프로')
    body = resp.get_data(as_text=True)
    assert '맥북 프로 16' in body
    assert '아이폰 15 프로' in body
    assert '갤럭시 버즈' not in body


def test_search_no_result(client):
    signup_and_login(client, 'alice01', 'Password123')
    add(client, '맥북')
    resp = client.get('/dashboard?q=존재하지않는상품명')
    assert '검색 결과가 없습니다' in resp.get_data(as_text=True)


def test_search_empty_shows_all(client):
    signup_and_login(client, 'alice01', 'Password123')
    add(client, '상품A')
    add(client, '상품B')
    body = client.get('/dashboard?q=').get_data(as_text=True)
    assert '상품A' in body and '상품B' in body


def test_search_like_wildcard_is_escaped(client):
    """'%'는 리터럴로 취급되어야 한다(모든 상품 매칭 방지)."""
    signup_and_login(client, 'alice01', 'Password123')
    add(client, '노트북')
    add(client, '마우스')
    # '%' 검색 시 이스케이프되어 실제 '%' 포함 제목만 매칭 → 결과 없음
    body = client.get('/dashboard?q=%25').get_data(as_text=True)  # %25 == '%'
    assert '노트북' not in body
    assert '마우스' not in body


def test_search_sql_injection_is_harmless(client):
    """SQLi 시도가 실행되지 않고 단순 문자열로 처리되어야 한다."""
    signup_and_login(client, 'alice01', 'Password123')
    add(client, '정상상품')
    payload = "' OR '1'='1"
    resp = client.get('/dashboard', query_string={'q': payload})
    assert resp.status_code == 200
    # 주입이 실행됐다면 정상상품이 노출되지만, 파라미터 바인딩으로 매칭 안 됨
    assert '정상상품' not in resp.get_data(as_text=True)
