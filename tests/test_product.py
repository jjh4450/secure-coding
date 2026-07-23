"""상품 CRUD + 업로드 테스트 (TDD)."""
import io
from conftest import signup_and_login, register


PNG_BYTES = b'\x89PNG\r\n\x1a\n' + b'\x00' * 64


def create_product(client, title='맥북 프로', description='상태 좋습니다', price='500000'):
    return client.post('/product/new', data={
        'title': title, 'description': description, 'price': price,
    }, follow_redirects=True)


def get_only_product(app_module):
    with app_module.app.app_context():
        return app_module.get_db().execute('SELECT * FROM product').fetchone()


def test_new_product_requires_login(client):
    resp = client.get('/product/new')
    assert resp.status_code == 302
    assert '/login' in resp.headers['Location']


def test_create_product(client, app_module):
    signup_and_login(client, 'alice01', 'Password123')
    create_product(client, '아이폰 15', '거의 새것', '900000')
    row = get_only_product(app_module)
    assert row['title'] == '아이폰 15'
    assert row['price'] == 900000


def test_create_product_rejects_invalid_price(client, app_module):
    signup_and_login(client, 'alice01', 'Password123')
    create_product(client, '테스트', '설명', 'not-a-number')
    assert get_only_product(app_module) is None


def test_create_product_rejects_negative_price(client, app_module):
    signup_and_login(client, 'alice01', 'Password123')
    create_product(client, '테스트', '설명', '-100')
    assert get_only_product(app_module) is None


def test_create_product_rejects_empty_title(client, app_module):
    signup_and_login(client, 'alice01', 'Password123')
    create_product(client, '   ', '설명', '1000')
    assert get_only_product(app_module) is None


def test_view_product(client, app_module):
    signup_and_login(client, 'alice01', 'Password123')
    create_product(client, '갤럭시 S24', '멀쩡함', '700000')
    pid = get_only_product(app_module)['id']
    resp = client.get(f'/product/{pid}')
    assert resp.status_code == 200
    assert '갤럭시 S24' in resp.get_data(as_text=True)


def test_view_nonexistent_product_404(client):
    signup_and_login(client, 'alice01', 'Password123')
    resp = client.get('/product/does-not-exist')
    assert resp.status_code == 404


def test_owner_can_edit_product(client, app_module):
    signup_and_login(client, 'alice01', 'Password123')
    create_product(client, '원제목', '원설명', '1000')
    pid = get_only_product(app_module)['id']
    client.post(f'/product/{pid}/edit', data={
        'title': '수정제목', 'description': '수정설명', 'price': '2000',
    }, follow_redirects=True)
    row = get_only_product(app_module)
    assert row['title'] == '수정제목'
    assert row['price'] == 2000


def test_non_owner_cannot_edit_product(client, app_module):
    # alice가 상품 등록
    signup_and_login(client, 'alice01', 'Password123')
    create_product(client, '앨리스상품', '설명', '1000')
    pid = get_only_product(app_module)['id']
    client.post('/logout')
    # bob이 수정 시도 → 403 (IDOR 방지)
    signup_and_login(client, 'bob01', 'Password123')
    resp = client.post(f'/product/{pid}/edit', data={
        'title': '탈취', 'description': 'x', 'price': '1',
    })
    assert resp.status_code == 403
    assert get_only_product(app_module)['title'] == '앨리스상품'


def test_non_owner_cannot_delete_product(client, app_module):
    signup_and_login(client, 'alice01', 'Password123')
    create_product(client, '앨리스상품', '설명', '1000')
    pid = get_only_product(app_module)['id']
    client.post('/logout')
    signup_and_login(client, 'bob01', 'Password123')
    resp = client.post(f'/product/{pid}/delete')
    assert resp.status_code == 403
    assert get_only_product(app_module) is not None


def test_owner_can_delete_product(client, app_module):
    signup_and_login(client, 'alice01', 'Password123')
    create_product(client, '삭제될상품', '설명', '1000')
    pid = get_only_product(app_module)['id']
    client.post(f'/product/{pid}/delete', follow_redirects=True)
    assert get_only_product(app_module) is None


def test_upload_rejects_non_image_extension(client, app_module):
    signup_and_login(client, 'alice01', 'Password123')
    data = {
        'title': '악성', 'description': '설명', 'price': '1000',
        'image': (io.BytesIO(b'print("hi")'), 'evil.py'),
    }
    client.post('/product/new', data=data, content_type='multipart/form-data',
                follow_redirects=True)
    assert get_only_product(app_module) is None


def test_upload_rejects_fake_extension(client, app_module):
    # 확장자는 png지만 내용은 이미지가 아님 → 매직바이트 검증에서 거부
    signup_and_login(client, 'alice01', 'Password123')
    data = {
        'title': '위조', 'description': '설명', 'price': '1000',
        'image': (io.BytesIO(b'not really an image'), 'fake.png'),
    }
    client.post('/product/new', data=data, content_type='multipart/form-data',
                follow_redirects=True)
    assert get_only_product(app_module) is None


def test_upload_accepts_valid_png(client, app_module):
    signup_and_login(client, 'alice01', 'Password123')
    data = {
        'title': '정상이미지상품', 'description': '설명', 'price': '1000',
        'image': (io.BytesIO(PNG_BYTES), 'photo.png'),
    }
    client.post('/product/new', data=data, content_type='multipart/form-data',
                follow_redirects=True)
    row = get_only_product(app_module)
    assert row is not None
    assert row['image_path'] and row['image_path'].startswith('uploads/')
