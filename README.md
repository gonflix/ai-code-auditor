# 🛡️ AI 코드 보안 감사 에이전트

AI가 생성한 코드(Cursor, Copilot 등)를 커밋 전에 자동으로 보안 감사하는 에이전틱 워크플로우.
OWASP Top 10 2025 기준 취약점 탐지 + 슬롭스쿼팅 방어 + 자기 수정 루프를 포함합니다.

## 아키텍처

```
PR/커밋 트리거
     │
     ▼
1. 코드 수집     ← GitHub MCP / local git diff
     │
     ▼
2. 의존성 검증   ← PyPI/npm 존재 확인 + OSV CVE 대조 (LLM 불필요)
     │
     ▼
3. LLM 보안 분석 ← OWASP Top 10 2025 체크리스트 프롬프트 (Ollama or Claude)
     │
     ▼
4. 자기 수정 루프 ← 오탐 필터링 / 경계값 재검토 (핵심 차별화)
     │
     ▼
5. 리포트 생성   ← GitHub PR 코멘트 / Issue / 터미널 출력
```

## 빠른 시작

### 1. 환경 설정
```bash
git clone <this-repo> && cd ai-code-auditor
pip install -r requirements.txt
cp .env.example .env
```

### 2. Ollama 로컬 모델 설치 (무료 테스트)
```bash
# Ollama 설치: https://ollama.ai
ollama pull gemma4:e4b   
# 또는
ollama pull codellama:13b   # 코드 분석 특화 (RAM 8GB+)
ollama pull llama3.1:8b     # 더 가벼운 옵션 (RAM 6GB+)
ollama serve                 # 백그라운드에서 실행
```

### 3. 실행

```bash
# 취약 샘플 파일로 즉시 테스트 (권장 첫 실행)
python main.py --mode sample

# 현재 git 저장소의 main 대비 변경사항 분석
python main.py --mode local --base-branch main

# GitHub PR 분석 (GITHUB_TOKEN 필요)
python main.py --mode pr --repo owner/repo --pr 42
```

### 4. Claude API로 전환 (데모/프로덕션)
`.env` 파일에서 한 줄만 수정:
```
LLM_BACKEND=claude
ANTHROPIC_API_KEY=your_key_here
```

## 탐지 항목 (OWASP Top 10 2025)

| 카테고리 | 예시 |
|---------|------|
| A01: 인증 누락 / 접근 제어 실패 | 관리자 엔드포인트에 데코레이터 없음, SSRF |
| A02: 보안 설정 오류 | 디버그 모드, 기본 자격증명, 과도한 CORS |
| A03: 소프트웨어 공급망 실패 | 슬롭스쿼팅 패키지(`torchvison`, `langchian`), CVE 포함 패키지 |
| A04: 암호화 실패 / 하드코딩 시크릿 | MD5/SHA1 비밀번호 해시, `API_KEY = "abc123"` |
| A05: 인젝션 | f-string으로 쿼리 조합, `subprocess(shell=True)` + 외부 입력 |
| A06: 안전하지 않은 설계 | 속도 제한 없음, 비즈니스 로직 결함 |
| A07: 인증 실패 | 취약한 세션 관리, 약한 패스워드 허용 |
| A08: 소프트웨어·데이터 무결성 실패 | 안전하지 않은 역직렬화, 신뢰되지 않은 코드 실행 |
| A09: 로깅 및 알림 부재 | 민감 작업에 로그 없음, 불충분한 감사 추적 |
| A10: 예외 조건 오처리 | 빈 `except:`, 예외 메시지로 내부 정보 노출 |

## 단위 테스트 (LLM 없이)

```bash
python -m pytest tests/ -v
```

## CI/CD 통합

`.github/workflows/security-audit.yml` 참고.
PR마다 자동 실행되며 Critical 발견 시 빌드를 실패 처리합니다.
