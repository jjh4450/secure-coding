# Tiny Market — Secure Second-hand Shopping Platform

[![CI & Security Scan](https://github.com/jjh4450/secure-coding/actions/workflows/ci.yml/badge.svg)](https://github.com/jjh4450/secure-coding/actions/workflows/ci.yml)

화이트햇 스쿨(WHS) 시큐어 코딩 과제로 개발한 중고거래 플랫폼입니다.
Flask + SQLite + Flask-SocketIO 기반으로, 전 기능을 **테스트 주도 개발(TDD)** 로 구현하고
보안 약점을 제거하는 데 중점을 두었습니다.

## 기능

| 영역 | 기능 |
|---|---|
| 유저 | 회원가입 / 로그인 / 로그아웃, 마이페이지(소개글·비밀번호 변경), 타 유저 프로필 조회 |
| 상품 | 등록(사진 업로드) / 목록 / 상세 / 수정 / 삭제, 상품명 검색 |
| 소통 | 실시간 전체 채팅, 1:1 채팅(대화 이력 저장) |
| 신고 | 유저·상품 신고, 서로 다른 3명 이상 신고 시 자동 차단(상품)/휴면(유저) |
| 송금 | 포인트 지갑, 유저 간 송금(비밀번호 재인증, 원자적 잔액 처리) |
| 관리자 | 유저(휴면/삭제)·상품(차단/삭제)·신고(처리) 전체 관리 |

## 보안 기능 요약

- **비밀번호**: pbkdf2 해시 저장(werkzeug), 정책 검증(8자+, 영문+숫자)
- **세션**: HttpOnly / SameSite=Lax 쿠키, 30분 만료, 로그인 시 세션 재발급(고정 방지)
- **CSRF**: Flask-WTF `CSRFProtect` 전 폼 적용
- **XSS**: Jinja2 autoescape + 채팅 클라이언트 `textContent` 렌더링, CSP로 인라인 스크립트 금지
- **SQL 인젝션**: 전 쿼리 파라미터 바인딩, 검색 LIKE 와일드카드 이스케이프
- **접근 제어**: `login_required` / 소유자 검증(IDOR 방지) / `admin_required`
- **업로드**: 확장자 화이트리스트 + 매직바이트 검증 + 랜덤 파일명 + 2MB 제한
- **브루트포스**: 로그인 실패 5회 → 5분 계정 잠금 + IP rate limit(Flask-Limiter)
- **실시간 채팅**: 소켓 이벤트마다 세션 인증 확인, username 서버 결정, 도배 방지, origin 화이트리스트
- **기타**: 보안 헤더(CSP, X-Frame-Options, nosniff), debug 기본 비활성화, 커스텀 에러 페이지, SECRET_KEY 랜덤 생성(하드코딩 금지)

CI(GitHub Actions)에서 push마다 **pytest(88개) + Bandit(SAST) + pip-audit(의존성 CVE) + CodeQL**이 실행됩니다.

## 환경 설정

### 방법 1 — conda

```bash
git clone https://github.com/jjh4450/secure-coding.git
cd secure-coding
conda env create -f enviroments.yaml
conda activate secure_coding
```

### 방법 2 — pip (Python 3.11+)

```bash
git clone https://github.com/jjh4450/secure-coding.git
cd secure-coding
python -m venv .venv
# Windows: .venv\Scripts\activate  /  Linux·macOS: source .venv/bin/activate
pip install -r requirements.txt
```

## 실행

```bash
python app.py
```

- 서버: http://127.0.0.1:5000
- **관리자 계정**: 최초 실행 시 `admin` 계정이 자동 생성됩니다.
  - `ADMIN_PASSWORD` 환경변수를 설정하면 해당 값으로 생성됩니다.
  - 미설정 시 랜덤 비밀번호가 생성되어 **콘솔에 1회 출력**됩니다.
- 유용한 환경변수:
  - `FLASK_DEBUG=1` — 디버그 모드(개발 시에만)
  - `COOKIE_SECURE=1` — HTTPS 배포 시 세션 쿠키 Secure 플래그
  - `ALLOWED_ORIGINS` — Socket.IO 허용 origin (기본: localhost:5000)

외부에서 테스트하려면 ngrok을 사용할 수 있습니다:

```bash
ngrok http 5000
```

> ngrok 등 별도 도메인으로 접속하는 경우 `ALLOWED_ORIGINS`에 해당 origin을 추가해야 실시간 채팅이 동작합니다.

## 테스트

```bash
pytest
```

기능 테스트와 보안 회귀 테스트(XSS/CSRF/IDOR/차단 노출/헤더 등) 88개가 실행됩니다.
