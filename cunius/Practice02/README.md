# Practice02
## FTPS vs SFTP
- FTP
    - https://cloudedi.tistory.com/9
- FTPS vs SFTP
    - https://cloudedi.tistory.com/17
- FTP
    - FTP
        - 인터넷을 통해 파일 송수신을 지원하기 위해 고안된 프로토콜
        - 양방향 시스템, 작업이 완료될 때까지 연결 지속
        - 대용량 서버에 각종 공개용 소프트웨어 및 문서를 저장해 사용자가 필요한 자료를 자신의 컴퓨터로 다운로드해서 사용 가능
        - 불특정 다수에게 파일 배포하기 위한 익명의 공개 FTP 서버도 존재, 대부분은 아이디/비번 인증받은 사용자만 접속 가능 → 비밀번호 평문 전송, 보안 취약
        - 파일 송수신만을 위해 고안되어 동작방식이 단순
        - 제어 포트 21: FTP Control(사용자 인증, 명령, 명령어 전달), 전송 포트 20: File Transfer
            - Active: server → client (port 20, 21)
            - Passive: client → server (임의 지정 port)
        - FTP server ip addr → ftp://

- FTPS (FTP + SSL)
    - File Transfer Protocol Secure
    - 비밀번호 평문 전송 FTP 취약점 보안 → SSL/TLS 사용 해 보안성 추가
    - HTTP 통신에 보안 추가
    - 개인정보 안전하게 통신
    - 뛰어난 호환성
    - FTP 기반 프로토콜 → port 20, 21
    - 방화벽 설정 문제로 작동 안 될 수 있음
- SFTP (FTP + SSH)
    - Secure File Transfer Protocol
    - 계정 정보 등 암호화해 해킹, 보안 문제를 사전 방지 가능
    - 보안 강화용 공개키, 개인 인증키 사용 → 안전한 데이터 송수신
    - 보안을 위한 암호화 복호화 과정을 거쳐 느림
    - runs over the SSH protocol → 보안성 강화
    - supports the full security and authentication functionality of SSH
    - more securely and more reliably, easier configuration
    - protects against passwrod sniffing, man-in-the-middle attacks
    - protects integrity of the data using encryption and cryptographic hash functions
    - authenticates both server and the user
    - Port number = SSH port 22
        - only once the user has logged in to the server usingSSH can the SFTP protocol be initiated
        - no separate SFTP port exposed on servers
        - no need to configure another hole into firewalls

**FTPS vs SFTP**

결국 다른 점은 FTPS=포트 21, SFTP=포트 22 사용한다????

- SFTP runs over SSH in the standard SSH port. Thus, no 
additional ports need to be opened on the server and no additional 
authentication needs to be maintained. This simplifies configuration and
 reduces the likelihood of configuration errors.
- FTPS needs complicated firewall configuration and may not work
 over NAT. Ports 989 and 990 need to be open. Furthermore, FTPS supports
 both active and passive modes (see [FTP](https://www.ssh.com/ssh/ftp/)), which further complicates firewall configurations and is prone to problems.
- FTPS requires an [X.509 certificate](https://www.ssh.com/pki)
 for the server, typically from a public certificate authority. SSH 
works without any centralized infrastructure. SFTP can utilize whatever 
host key distribution or certification method is in use for SSH, without
 needing additional work and ongoing maintenance.
- FTPS is basically FTP, which means it has ASCII mode, which 
can corrupt files if the mode is not properly set. Some implementations 
default to ASCII mode.
- FTPS cannot be used as a file system. (This does not improve security, as it can still read the same files.)
- FTPS requires an extra server software package to be installed and patched, whereas SFTP usually comes with SSH with the system.


## CSP
- CSP: Contents Security Policy
    - XSS 와 데이터 인젝션 공격을 등 특정 유형이 공격을 탐지하고 완화하는데 도움이 되는 추가 보안 계층
    - 데이터 절도, 사이트 훼손, 맬웨어 배포 등 모든 것에 사용됨
    - CSP 지원하지 않는 브라우저는 CSP 무시하고 평소와 같이 작동, 웹 컨텐츠에 대한 표준 동일 정책 사용
    - 사이트에서 CSP 제공하지 않는 경우 브라우저도 표준 동일 출처 정책 사용
- CSP 활성화
    - Content-Security-Policy HTTP 헤더를 반환하도록 웹 서버 구성
    - X-Content-Security-Policy → 이전 버전이므로 설정할 필요 없음
    - meta 요소를 사용해 정책 구성
        
        ```html
        <meta
          http-equiv="Content-Security-Policy"
          content="default-src 'self'; img-src https://*; child-src 'none';" />
        ```
        
        - CSP 위반 보고서 전송과 같은 일부 기능은 HTTP 헤더를 사용할 때만 사용 가능
- CSP 목표
    - XSS 완화, 보고
        - XSS: 서버에서 받은 컨텐츠를 브라우저가 신뢰하다는 점 악용 → 컨텐츠가 이상한 곳에서 오더라도 악성 스크립트를 피해자 브라우저에서 실행
        - 서버 관리자가 브라우저에서 실행 가능한 스크립트의 유효한 소스로 간주해야 하는 도메인을 지정해 XSS가 발생할 수 있는 벡터를 줄이거나 제거
        - CSP 호환 브라우저는 허용된 도메인에서 받은 소스 파일에서 로드된 스크립트만 실행하고 HTML 속성을 포함한 인라인 스크립트 및 이벤트 처리 등 다른 모든 스크립트 무시
        - 스크립트 실행을 허용하지 않으려는 사이트는 허용하지 않도록 선택 가능
    - 패킷 스니핑 공격 완화
        - 컨텐츠를 로드할 수 있는 도메인 제한 + 서버는 사용할 수 있는 프로토콜 지정 (모든 컨텐츠가 HTTPS를 사용해서 로드되게 지정)
        - 완전한 데이터 전송 보안 전략 → HTTPS 적용 + 쿠키에 secure 속성 표시 + HTTP는 HTTPS로 자동 리다이렉션 제공
        - 사이트는 Strict-Transport-Security HTTP 헤더를 사용해 브라우저가 암호화된 채널을 통해서만 사이트에 연결할 수 있게 함

---

- 정책 구성
    - Content-Security-Policy HTTP 헤더를 웹 페이지에 추가
    - 사용자 에이전트가 해당 페이지에 대해 로드할 수 있는 리소스를 제어하는 값 지정작업 반복
    - 적절하게 설계된 CSP는 XSS로부터 페이지를 보호함
- 정책 지정
    
    ```html
    Content-Security-Policy: policy
    ```
    
- 정책 작성
    - 일련의 정책 지시문 사용 (지시문: 특정 리소스 유형, 정책 영역에 대한 정책을 나타냄)
    - 자체 정책이 없을 때 다른 리소스 유형에 대한 폴백인 default-src 지시문 포함
    - default-src, script-src 지시문: 인라인 스크립트 실행 방지, eval() 사용 차단
    - default-src, style-src: 인라인 스타일이 <style> 요소 또는 style 속성에서 적용되는 것 제한
    - 다양한 유형의 항목에 대한 특정 지시문 있음 → 각 유형은 글꼴, 프레임, 이미지, 오디오 및 비디오 미디어, 스크립트 및 작업자 포함 자체 정책을 가질 수 있음
    
- CSP 시나리오
    - 웹 사이트 관리자가 모든 컨텐츠가  사이트 자체의 출처에서 오기를 원할 때 (하위 도메인 제외)
        
        ```html
        Content-Security-Policy: default-src 'self'
        ```
        
    - 웹 사이트 관리자가 신뢰할 수 있는 도메인 및 모든 하위 도메인의 컨텐츠를 허요하려고 할 때
        
        ```html
        Content-Security-Policy: default-src 'self' example.com *.example.com
        ```
        
    - 웹 사이트 관리자가 웹 앱 사용자가 자신의 컨텐츠에 모든 원본 이미지를 포함할 수 있도록 허용하지만 오디오 또는 비디오 미디어는 신뢰할 수 있는 공급자로 제한하고 모든 스크립트는 신뢰할 수 있는 코드를 호스팅하는  특정 서버로만 제한하려고 할 때
        
        ```html
        Content-Security-Policy: default-src 'self'; img-src *; media-src example.org example.net; script-src userscripts.example.co
        ```
        
        - 문서 원본의 컨텐츠만 허용됨
        - 예외
            - 이미지는 출처에 상관없이 로드할 수 있음 (”*” 와일드카드)
            - 미디어는 example.org, [example.net](http://example.net) 에서만 허용, 해당 사이트의 하위 도메인에서는 허용되지 않음
            - 실행 가능한 스크립트는 [userscripts.example.com](http://userscripts.example.com) 에서 온 것만 허용
    - 온라인 뱅킹 사이트의 웹 사이트 관리자가 공격자가 요청을 도청하는 것을 방지하기 위해 모든 컨텐츠가 TLS를 사용해 로드되었는지 확인하려고 할 때
        
        ```html
        Content-Security-Policy: default-src https://onlinebanking.example.com
        ```
        
        - 서버는 단일 출처인 [onlinebanking.example.com](http://onlinebanking.example.com) 에서 특별히 HTTPS 를 통해 로드되는 문서에 대한 액세스만 허용
    - 웹 메일 사이트의 웹 사이트 관리자가 전자 메일에 HTML을 허용하고 어디에서나 로드된 이미지를 허용하려고 하지만 JavaScript 또는 기타 잠재적으로 위험한 컨텐츠는 허용하지 않으려고 할 때
        
        ```html
        Content-Security-Policy: default-src 'self' *.example.com; img-src *
        ```
        
        - script-src 지정하지 않음, default-src 지시문 사용 → 원본 서버에서만 스크립트 로드 가능
- 정책 테스트
    - 쉬운 배포를 위해 보고 전용 모드로 배포될 수 있음
    - 정책이 시행되지는 않지만 모든 위반 사항은 제공된 URI 로 보고됨
    - 보고서 전용 헤더를 사용해 정책을 실제로 배포하지 않고 정책에 대한 향후 개정을 테스트 할 수 있음
    
    ```html
    Content-Security-Policy-Report-Only: policy
    ```
    
    Content-Security-Policy-Report-Only헤더, Content-Security-Policy 헤더가 동일한 응답에 있을 경우 두 정책 모두 적용 됨
    
    - Content-Security-Policy-Report-Only:
        
        보고서를 생성하지만 시행되지 않음
        
    - Content-Security-Policy:
        
        헤더에 지정된 정책은 시행 됨
        
- 위반 보고서
    - 기본적으로 위반 보고서는 전송되지 않음
    - 위반 보고서 활성화 하려면 보고서를 전달받을 하나 이상의 URI 를 report-to 정책 지시문에 지정
        
        ```html
        Content-Security-Policy: default-src 'self'; report-to http://reportcollector.example.com/collector.cgi
        ```
        
    - 보고서를 수신하도록 서버 설정 → 사용자가 적절하다고 판단하는 방식으로 데이터 저장, 처리


## CSRF
- Cross Site Request Forgery
    - 인증된 사용자가 웹 애플리케이션에 특정 요청을 보내도록 유도하는 공격
    - 생성된 요청이 사용자의 동의를 받았는지 확인할 수 없는 웹 애플리케이션의 CSRF의 취약점 이용
    - 공격자의 요청이 사용자의 요청인 것 처럼 속이는 공격
    - 관리자 계정이 공격당하면 공격자가 전체 서버 접근 권한을 탈취해 웹 애플리케이션과 API 등 서비스 전체를 마음대로 통제 가능
    - 사용자 정보 탈취 보다는 특정 작업을 무단으로 진행하기 위한 목적
    - 권한 탈취 당하면 개인정보도 그대로 노출 됨

- 공격 방식
    - 데이터의 값을 변경하는 요청을 대상으로 함 (제품 구입, 계정 설정, 기록 삭제, 비밀번호 변경, 문자 전송 등)
    - 자금 송금이나 로그인 정보 변경 등 원하는 요청 위조
    - 이메일이나 웹 사이트에 요청이 삽입된 하이퍼링크 심기
    - 사용자가 해당 하이퍼링크 클릭하면 요청이 자동으로 전송 됨

- XSS vs CSRF
    - 공통점
        - 사용자의 브라우저를 대상으로 공격
    - XSS
        - 인증 된 세션 없이도 공격 가능
        - 사용자가 특정 사이트를 신뢰하는 사실을 이용
        - 사용자로부터 스크립트가 실행 됨
        - 사용자 PC 에서 스크립트를 실핼해 사용자의 정보 탈취 목적
    - CSRF
        - 사용자의 인증된 세션을 악용하는 공격
        - 특정 사이트가 인증된 사용자의 요청을 신뢰하는 사실을 이용
        - 서버에서 스크립트가 실행 됨
        - 요청을 위조함으로써 사용자 몰래 송금, 제품 구입 등 특정 행위를 수행하는 목적

- 예방
    - 해당 사이트는 CSRF 토큰을 이용해 요청이 사용자가 전송한 것이 맞는지 확인 또는 재인증 요구
    - 사용하지 않는 웹 애플리케이션 로그아웃 → 자동 로그아웃  기능 + 2단계 인증 추가
    - 로그인 정보 안전하게 보관 → 동일한 비밀번호 사용 또는 유추하기 쉬운 비밀번호 사용 금지
    - 브라우저에 비밀번호 저장 금지 → 사용자의 브라우저를 대상으로 공격되므로 비밀번호 유출 가능
    - 여러 웹 동시 사용 금지 → 현재 화면에 표시되지 않는 웹 사이트에서 CSRF 가 발생할 수 있음, 하나씩 사용
    - VPN 사용 → 사용자 아이피를 가상 아이피로 대체해 보안 강화, Malware, Virus 방지


## CRLF
- CR: Carriage Return → 현재 줄에서 커서의 위치를 맨 처음으로 이동 (ASCII 13, \r)
- LF: Line Feed → 현재 커서 위치에서 위치 변화 없이 라인만 한 줄 아래로 이동 (ASCII 10, \n)
- EOF: End Of Line = CRLF → 줄 바꿈

---

### CRLF Injection

- CWE-93
    - CRLF를 특수요소로 사용하여 라인이나 레코드를 분리하지만 input 에서 CRLF 시퀀스를 중화하거나 잘못 중화하지 않음
- CRLF
    - 라인의 종료 기록
    - 윈도우즈: CR, LF 둘 다 라인의 끝을 기록해야 함
    - 리눅스/UNIX: LF 만 필요
    - HTTP Protocol: CR-LF 시퀀스는 항상 라인을 종료
- CRLF Injection
    - 사용자가 응용 프로그램에 CRLF를 제출할 때 발생
    - 일반적으로 HTTP 매개 변수 또는 URL 을 수정하여 수행 됨
    - 응용 프로그램이 개발되는 방법에 따라 사소한 문제가 될 수 있음
    - 파일을 일부 정렬/쓰기 데이터를 읽기/쓰기 위해 사용 됨
    - CRLF 를 배치 할 경우 파일을 파일로 주입하는 프로그램 읽기 방법 주입 가능 → 이 파일을 사용해 화면에 표시 가능

### Smuggling

메인 웹 서버의 과부하를 막기 위한 프론트 단에서의 리버스 프록시 서버 사용 또는 로드 밸런서 사용 시 CL, TE 의 처리를 Front-end, Back-end 에서 다르게 한다는 점을 이용한 공격

→ Front-end 의 보안을 우회하거나 다른 사용자의 패킷을 캡쳐하는 등 다양한 연계공격 가능

- HTTP Request Smuggling
    - HTTP 1.1 를 사용하는 Front-end server, Back-end server 로 이루어진 웹 애플리케이션을 대상으로 함
    - 변조된 패킷을 일반 사용자가 접근할 수 없는 Back-end server 로 직접 보내 중요 정보 획득, XSS 공격 유도, 서버 웹 캐시 포이즈닝 등의 공격 수행 가능
    - 패킷: Content-Length, Transfer-Encoding: chunked header 등을 변조해 Front-end server, Back-end server 가 패킷의 길이를 다르게 해석하게 함 → 하나의 패킷 안에 또 다른 패킷 포함 가능
    - Back-end server 에서 악의적으로 smuggling 된 패킷을 해석할 경우 공격이 수행 됨
- Content-Length
    - 직접적으로 나타냄
    
    ```html
    POST /blah HTTP/1.1
    Host: my-website.co.kr
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 11
    
    v=smuggling
    ```
    
- Transfer-Encoding: chunked
    - 이 헤더는 데이터를 분할해서 보냄
    - \r\n 를 제외한 문자의 길이, 데이터, 다음 라인의 데이터 크기가 반복해서 포함됨
    - 0 = 패킷의 끝
    
    ```html
    POST /blah HTTP/1.1
    Host: my-website.co.kr
    Content-Type: application/x-www-form-urlencoded
    Transfer-Encoding: chunked
    
    b
    v=smuggling
    0
    ```
    
    - 브라우저에서 보통 요청에서 chunked 인코딩을 사용하지 않고 응답에서 주로 사용함 → 요청에서 chunked 인코딩을 사용하는 것을 거의 볼 수 없음
    - Burp Suite 에서는 content-Length 를 자동으로 계산해 수정하므로 해당 기능을 꺼야 공격 수행 가능

- 공격 방법
    - CL.TE Vulnerability
        - Front-end server 에서 Content-Length를, Back-end server 에서 Transfer-Encoding 을 이용해 패킷 길이 계산을 할 경우
        
        ```html
        POST / HTTP/1.1
        Host: vuln-website.com
        Content-Length: 13
        Transfer-Encoding: chunked
        
        0
        
        SMUGGLED
        ```
        
        이 패킷을 Front-end server 에 전송해 공격 수행 가능
        
        → Front-end server 에서 패킷의 SMUGGLED 문자열 끝까지 읽어들여 Back-end server 로 전송
        
        - Bakce-end server 에서 Transfer-Encoding: chunked 헤더를 이용해 패킷을 읽어들이며 0을 만났으므로 패킷을 끝으로 인식
        - SMUGGLED 문자열은 다음 새로운 패킷의 시작으로 받아들임
        - 에러
            
            ![Screenshot 2023-09-20 at 21.27.57.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/816e432b-b772-4f85-add4-b7a9f06196f0/cd2e5c12-c079-49c4-8dfc-b0363422d397/Screenshot_2023-09-20_at_21.27.57.png)
            
        
        SMUGGLED 대신 G 입력, Content-Length 를 6 으로 변경해 전송 → Back-end 에서 G 가 패킷의 시작점으로 인식 됨, GPOST 메소드로 읽혀 에러 발생
        
    - [TE.CL](http://TE.CL) Vulnerability
        - Front-end server 에서 Transfer-Encoding, Back-end server 에서 Content-Length 를 이용해 패킷 길이를 계산 할 경우
        
        ```html
        POST / HTTP/1.1
        Host: vuln-website.com
        Content-Length: 3
        Transfer-Encoding: chunked
        
        8
        SMUGGLED
        0
        ```
        
        이 패킷을 Front-end server 에 전송해 공격 수행 가능
        
        마지막 0 이후에 \r\n\r\n 포함해야 함
        
        ![Screenshot 2023-09-20 at 21.31.21.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/816e432b-b772-4f85-add4-b7a9f06196f0/bbd47470-7f0d-4a94-9ce2-edf6e813e895/Screenshot_2023-09-20_at_21.31.21.png)
        
    - TE.TE Vulnerability (난독화 이용)
        - Front-end server, Back-end server 모두 Transfer-Encoding 헤더를 지원
        - 어떤 방식이든 헤더를 난독화 해 서버 중 하나가 헤더를 처리하지 않도록 함
        - 하나의 서버가 Transfer-Encoding 헤더를 처리하지 않게 되면 나머지 과정은 CL.TE / [TE.CL](http://TE.CL) 취약점과 같음
        
        ```html
        Transfer-Encoding: xchunked
        
        Transfer-Encoding : chunked
        
        Transfer-Encoding: chunked
        
        Transfer-Encoding: x
        
        Transfer-Encoding:[tab]chunked
        
        [space]Transfer-Encoding: chunked
        
        X: X[\n]Transfer-Encoding: chunked
        
        Transfer-Encoding
        : chunked
        ```
        
        ![Screenshot 2023-09-20 at 21.33.18.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/816e432b-b772-4f85-add4-b7a9f06196f0/8c7cf322-0565-4f75-a94b-cd600cc0027a/Screenshot_2023-09-20_at_21.33.18.png)
        

### Finding HTTP request smuggling vulnerabilities

- using timing techniques
    - time delay 를 발생시키는 request 요청
    - smuggling vulnerabilities 요청의 감지를 자동화하는 Burp Scanner 에 의해 사용 됨

- CE.TE vulnerabilities
    - 애플리케이션이 CL에 취약하다면 CLI 에 취약한 것
    - 요청 밀수량 변수와 같은 요청을 보내는 경우가 종종 발생
    - Front-end server 는 Content-Length 헤더를 사용하므로 X 를 제외한 이 요청의 일부만 전달
    - Back-end server 는 Transfer-Encoding 헤더를 사용하고 첫 번째 링크를 처리한 후 다음 청크가 도착할 때까지 기다림 → 시간 딜레이 발생
    
    ```html
    	POST / HTTP/1.1
    Host: vulnerable-website.com
    Transfer-Encoding: chunked
    Content-Length: 4
    
    1
    A
    X
    ```
    
- [TE.CL](http://TE.CL) vulnerabilities
    - 응용 프로그래이 TEM 에 취약할 때 발생
    - Front-end server 는 Transfer-Encoding 헤더를 사용하므로 X 를 제외한 이 요청의 일부만 전달
    - Back-end server 는 Content-Length 헤더를 사용하고 메세지 본문에 더 많은 내용이 있을 것으로 예상하고 나머지 내용이 도착하기를 기다림 → 시간 딜레이 발생
    
    ```html
    POST / HTTP/1.1
    Host: vulnerable-website.com
    Transfer-Encoding: chunked
    Content-Length: 6
    
    0
    
    X
    ```


## Cache Poisoning
**Web Cache Poisoning**

- 공격자가 웹 서버 및 캐시의 동작을 악용해 유해한 HTTP 응답을 다른 사용자에게 제공하는 고급 기술
- 위험한 페이로드를 포함하는 백엔드 서버로부터 응답을 이끌어내는 방법을 찾아야 함 → 성공한 후 응답이 캐시에 저장돼 의도된 피해자에게 제공되는지 확인하기
- 잠재적으로 XSS, JavaScript 주입, 개방형 redirection 등의 취약성을 이용해 다양한 공격을 분산시키는 치명적이 수단

---

**Web Cache 작동 원리**

- Caching
    - 서버가 개별적으로 새로운 응답을 보내야 할 때 서버 경험을 별도로 보내야만 하는 경우 지연시간 문제 및 poor user experience 에서 오류가 발생하는 문제를 줄임
    - 대기시간을 줄여 페이지 로드 속도를 높이고 애플리케이션 서버의 로드를 줄임
- Cache
    - 서버 및 사용자 간의 응답을 저장할 경우, 일반적으로 고정 금액에 대한 응답을 저장
    - 다른 사용자가 동일한 요청을 전송하면 백업 엔드포인트에서 직접 캐시된 응답 복사본이 아닌 사용자로 액세스 가능
    - 이 서버에 중복 요청을 처리해 서버에 로드해야 함
        
        ![Screenshot 2023-09-22 at 01.15.43.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/816e432b-b772-4f85-add4-b7a9f06196f0/6a722d3a-850b-4783-96d9-329254512ea5/Screenshot_2023-09-22_at_01.15.43.png)
        
- Cache Keys
    - 캐시가 HTTP 요청을 받을때, 액세스할 수 있는 캐시된 응답이 있는지 또는 백엔드 서버에 의해 핸들링 요청을 전달하는지 여부를 결정해야 함
    - 캐시 키라고 불리는 요청 요소를 비교함으로써 동일한 요청을 식별
    - request line 과 Host header 포함
    - unkeyed = 캐시 키에서 포함되지 않은 요청의 구성 요소
    - 수신 요청의 캐시 키가 이전의 요청 키와 일치하면 캐시가 동등하다고 간주 됨 → 오리지널 요청으로부터의 캐시된 응답으 복사본을 제공
    - 캐시 응답이 만료될때까지 캐시 키에 일치하는 모든 요청에 적용
    - 다른 요소들은 캐시에 의해 무시됨

---

**Impact of a Web Cache Poisoning Attack**

- What exactly the attacker can successfully get cached
    - poisoned cache 는 독립 실행형 공격보다 분산 수단 → 웹 캐시 독살의 영향은 주입된 페이로드의 유해성과 불가분의 관계
    - 다른 공격과 함께 사용되어 잠재적인 영향을 확대시킬 수 있음
- The amount of traffic on the affected page
    - poisoned response 는 독살되는 동안 영향을 받는 페이지를 방문한 사용자에게만 제공됨 → 페이지의 인기 여부에 따라 적은 수에서 대규모 사용자까지 다양
- 캐시 항목의 지속 시간이 반드시 웹 캐시 독살에 영향을 미치는 것은 아님
- 공격은 일반적으로 캐시를 무한정 재독하는 방식으로 스크립트화 될 수 있음

---

https://portswigger.net/web-security/web-cache-poisoning

---

---

---

**DNS Spoofing Attack (Sniffing)**

- DNS 쿼리와 응답 시 UDP protocol 특성을 이용한 공격
- DNS server 와 클라이언트 간 연결상태를 유지하지 않고 트랜잭션 ID, 출발지/목적지 IP(Port)만 일치하면 제일 먼저 수신한 응답을 신뢰하기 때문에 이후에 수신된 응답은 모두 폐기하는 특성을 이용
    
    ![Screenshot 2023-09-22 at 01.35.57.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/816e432b-b772-4f85-add4-b7a9f06196f0/0a703f02-d70d-4994-8e6f-35f94b7023de/Screenshot_2023-09-22_at_01.35.57.png)
    
- 공격자: 스니핑 하고있다가 클라이언트에서 DNS 쿼리 요청이 오면 DNS 서버 정상 응답보다 빠르게 조작된 사이트 IP 주소 정보를 클라이언트에게 DNS 응답을 전송
- 클라이언트: 먼저 수신된 조작된 DNS 응답을 신뢰, 이후에 도착한 정상적인 DNS 서버의 응답을 폐기
- 결과: 클라이언트는 조작된 IP 주소를 통해 클라이언트가 의도하지 않은 웹사이트 주소로 접속
- ipconfig/displaydns (로컬 DNS 캐시 정보 조회) → 도메인에 대한 IP 주소가 조작된 주소로 설정 돼 있다고 확인 가능

---

- Promiscuous Mode

자신의 MAC 주소와 상관없는 패킷이 들어와도 이를 분석할 수 있도록 메모리에 올려 처리할 수 있도록 해주는 모드

---

DNS Spoofind 대응책

- DNS Spoofing = Sniffing 기반 공격 → 스니핑 탐지, 차단
- 중요 사이트 경우 DNS 쿼리보다 우선순위가 높은 host.ics 파일에 등록해서 관리

---

**DNS Cache Poisoning Attack (스니핑 불가 환경)**

- DNS 서버의 캐시 정보를 조작해 공격하는 방법
- Recursive DNS server (Cache DNS server)에 빈번한 반복적 쿼리를 요청함으로써 발생하는 부하를 막기위해 캐시와 TTL 동안 유지하는데 공격자가 다수의 쿼리 요청과 에 따른 조작된 응답을 전송해 가짜 사이트로 유도
    
    ![Screenshot 2023-09-22 at 01.43.07.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/816e432b-b772-4f85-add4-b7a9f06196f0/35feffcc-7e90-4222-980c-c619813a36bf/Screenshot_2023-09-22_at_01.43.07.png)
    
- 공격자는 타깃의 Recursive DNS 서버에 가짜 사이트의 도메인 쿼리를 다수 전송하고 그에 따른 다수의 조작된 DNS 응답을 전송
    - 다수의 응답 보내는 이유: 클라이언트가 DNS 쿼리에 사용되는 트랜잭션 ID와 출발지 포트를 모르기 때문(스니핑 불가)에 무작위로 트랜잭션 ID 와 출발지 포트를 다수 생성해 응답 함
    - 생일 공격: 한 반에 같은 생일인 학생이 있을 확률이 50% 이상이라는 Birthday Paradox 기반 공격
- 클라이언트가 요청한 DNS 쿼리가 공격자 응답이 정상적인 DNS 응답보다 먼저 일치하는 경우: 타깃의 Recursive DNS 서버의 캐시에 조작된 DNS 주소 정보가 저장 되어있는 클라이언트는 조작된 주소의 사이트로 접속하게 됨

---

DNS Cache Poisoning Attack 대응

- Authoriative DNS 서버가 재귀적 쿼리를 허용하기 않도록 하거나 제한된 사용자만이 재귀적 쿼리를 사용하도록 제한 (/etc/named.conf 파일 설정)
    - 재귀적 쿼리 비활성: recursion no; / allow-recursion {none;};
    - 제한된 재귀적 쿼리: allow-recursion {127.0.0.1;192.168.70.0/24;};
- 기존 DNS에 공개키 암호화 방식을 추가한 보안 기능인 DNSSEC 기술 활용
- DNS 서버의 Bind 버전을 최신 버전으로 유지, 업뎃해 알려진 취약점 공격에 방어