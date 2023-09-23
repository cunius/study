# Practice01
## CORS
- Cross-Origin Resources Sharing
    
    동일 오리진 정책을 확장한 것
    
    외부의 third party와 승인 하에 리소스를 공유하려면 CORS가 필요
    
    - 공개되거나 승인된 외부 API에서 데이터를 가져오려는 경우
    - 권한이 있는 서드 파티가 서버 리소스에 액세스하는 것을 허용하려는 경우
    - 예) URL http://www.google.com/dir/page.html/
        - 같은 오리진 - 경로만 다름
            - http://www.google.com/dir2/page.html
            - http://www.google.com/dir/blah/blah.html
        - 다른 오리진
            - https://www.google.com/page.html - 프로토콜
            - http://www.google.com:82/dir/page.html - 포트
            - http://mail.google.com/dir/page.html - 호스트

- 코드
    - https://foo.example 웹 컨텐츠가 https://bar.other 도메인의 컨텐츠를 호출할 때
    - 클라이언트와 서버 간에 간단한 통신을 하고, CORS 헤더를 사용해 권한 처리
    - Origin: * or Origin: 127.0.0.1

```jsx
const xhr = new XMLHttpRequest();
const url = 'https://bar.other/resources/public-data/';

xhr.open('GET', url);
xhr.onreadystatechange = someHandler;
xhr.send();
```

- 브라우저가 서버로 전송하는 내용을 살펴보고, 서버의 응답 확인

```html
**GET /resources/public-data/ HTTP/1.1
Host: bar.other**
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:71.0) Gecko/20100101 Firefox/71.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-us,en;q=0.5
Accept-Encoding: gzip,deflate
Connection: keep-alive
**Origin: https://foo.example**
```

- 응답
- Access-Control-Allow-Origin 헤더 다시 전송
- 서버는 Access-Control-Allow-Origin: *, 로 응답 → 모든 도메인에서 접근 가능

```html
HTTP/1.1 200 OK
Date: Mon, 01 Dec 2008 00:23:53 GMT
Server: Apache/2
**Access-Control-Allow-Origin: * (127.0.0.1:8085 -> SSRF)**
Keep-Alive: timeout=2, max=100
Connection: Keep-Alive
Transfer-Encoding: chunked
Content-Type: application/xml

[…XML Data…]
```

- https://bar.other 리소스 소유자가 [https://foo.example](https://foo.example이) 의 요청만 접근 허용할 경우

```html
Access-Control-Allow-Origin:
https://foo.example
```

→ https://foo.example 이외의 도메인은 cross-site 방식으로 리소스에 접근할 수 없음

리소스에 대한 접근을 허용하려면, `Access-Control-Allow-Origin` 헤더에 요청의 `Origin` 헤더에서 전송된 값이 포함되어야 함

- dic
    - Third Party
        
        프로그래밍을 도와주는 plug_in 이나 library 등을 만드는 회사
        
        프로그래밍 개발과 개발자 사이에 플러그인,라이브러리,프레임워크를 서드파티로 볼 수 있는데, 이처럼 제 3자로써 중간다리 역할을 하는 것


## SQLi
- SQLi 취약점

SQL 구문에서 사용되는 특수문자를 이용하여 DB에 존재하는 중요 정보 탈취가 가능함

- 주요정보통신기반시설 대응방안
    - 쿼리 입력에 대한 검증 로직 구현 → 미검증 쿼리 요청 시 정상 페이지가 나오도록 필터링 처리
    - 웹 방화벽에 SQLi 관련 툴셋 적용해 공격 차단

![Screenshot 2023-09-13 at 23.07.10.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/816e432b-b772-4f85-add4-b7a9f06196f0/b07e7a21-83bb-4128-8e0f-4839b0acd13e/Screenshot_2023-09-13_at_23.07.10.png)

![Screenshot 2023-09-13 at 23.07.24.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/816e432b-b772-4f85-add4-b7a9f06196f0/a8bb6287-e0ae-4afb-b8df-656e1632f486/Screenshot_2023-09-13_at_23.07.24.png)

![Screenshot 2023-09-13 at 23.07.34.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/816e432b-b772-4f85-add4-b7a9f06196f0/7f5b5786-08b7-4f9c-8f1a-9b7b236be6fd/Screenshot_2023-09-13_at_23.07.34.png)

![Screenshot 2023-09-13 at 23.07.45.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/816e432b-b772-4f85-add4-b7a9f06196f0/32ae766e-ebf6-43fd-bc72-77327d9cb566/Screenshot_2023-09-13_at_23.07.45.png)

![Screenshot 2023-09-13 at 23.07.55.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/816e432b-b772-4f85-add4-b7a9f06196f0/b50f4a4b-315c-4306-a757-65708d35a4d5/Screenshot_2023-09-13_at_23.07.55.png)

![Screenshot 2023-09-13 at 23.08.08.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/816e432b-b772-4f85-add4-b7a9f06196f0/9801852d-178f-4bcd-81a1-8e53b1996a08/Screenshot_2023-09-13_at_23.08.08.png)

- Prepared Statement
    - What is Prepared Statement?
    
    쿼리가 준비 된 문장
    
    이미 쿼리실행계획 분석과 컴파일이 완료되어서 DBMS의 캐시에 준비되어있는 쿼리를 사용한다는 의미이다.
    
    - 비교
        - Statement
        
        DDL(CREATE, ALTER, DROP) 구문을 처리할 때 적합하다.
        매 실행시 Query를 다시 파싱하기 때문에 속도가 느리며, SQL Injection공격에 취약하다.
        
        - Prepared Statement
        
        DML(SELECT, INSERT, UPDATE, DELETE)구문 처리에 적합하다.
        그리고 캐시에 저장된 Query를 활용하기 때문에 실행이 빠르며 SQL Injection을 막기 위한 방법으로 활용된다.
        
    
    *Prepared Statement*
    
    - 장점
        - 1번 처리 구간을 건너 뛰고 2번부터 처리하기 때문에 SQL 처리가 빠르다. (Soft Parsing)
        - 1번 구간은 SQL을 분석하는 처리도 하고 있지만, 건너뛰기 때문에 대입된 값은 SQL로 인식하지 않는다. 즉 SQL Injection을 예방할 수 있다.
    - 단점
        - 쿼리에 오류가 생긴경우 분석하기 어렵다. 바인드변수 부분이 '?'로 나오므로 실제 실행된 쿼리를 확인하는것이 어렵다.
        - 바인드변수는 일부 허용된 위치에서만 사용할 수 있기 때문에 동적 쿼리 작성이 힘들다.한가지 예로 변수를 활용해 동적으로 테이블을 변경하는 쿼리를 작성해야 하는 경우 Prepared Statement로는 처리가 불가능하다.
    
    *Statement*
    
    - 장점
        - 테이블, 컬럼에 대한 동적 쿼리 작성이 가능하다. 즉 DDL 작성에 적합하다.
        - 쿼리실행문을 직접 확인 가능하므로 쿼리 분석이 쉽다.
    - 단점
        - 1번 처리구간을 매 요청마다 수행하므로 Query 처리비용이 더 들게된다.즉 캐시 활용을 하지 못한다는 얘기이다.
        - 위와는 반대로 SQL Injection으로 인한 공격에 노출된다.예를 들자면 비밀번호를 확인하는 Where 구문의 변수 부분에 '1234 OR 1 = 1' 같은 구문을 끼워넣을 경우 항상 참이 되어버리므로 악용이 가능하다.


## DOM XSS vs Reflected XSS
- XSS
웹 페이지에 악의적인 스크립트를 포함시켜 사용자 측에서 실행되게 유도하는 취약점, 모의해킹/소스코드 진단 시 가장 높은 비율로 탐지되는 취약점

공격하기 쉽고 완벽하게 방어하기 어려움

xss 는 서버 공격이 아님, 취약점이 있는지만 확인하고 끝

- Reflected XSS
공격자가 입력하는 정보가 별도로 저장되지 않고 같은 페이지에서 바로 출력되면서 피해가 발생하는 취약점

![Screenshot 2023-09-14 at 01.27.01.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/816e432b-b772-4f85-add4-b7a9f06196f0/6b42ce31-5e22-43a7-b40d-91d0756ea68c/Screenshot_2023-09-14_at_01.27.01.png)

<cvss3.1>

https://docs.fluidattacks.com/criteria/vulnerabilities/008/

- DOM XSS

공격 스크립트가 DOM의 일부로 실행됨으로써 브라우저 자체에 악성 스크립트가 실행되는 취약점

- 피해자의 브라우저에 악성 코드 주입 및 실행 가능
- 악성 사이트로 리다이렉트 처리 가능(피싱)
- 피해자의 인증 정보(쿠키 등) 탈취 가능 - 하이재킹

![Screenshot 2023-09-14 at 01.27.59.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/816e432b-b772-4f85-add4-b7a9f06196f0/097ace2f-7287-4031-bd58-d7546f69c0bf/Screenshot_2023-09-14_at_01.27.59.png)

<시나리오>

1. 아래와 같은 URL로 호출되는 페이지가 존재한다고 가정

http://www.test.com/page.html?default=English

---

2. Attacker에 의해 DOM Based XSS 공격 페이로드 전송

http://www.test.com/page.html?default=<script>alert(document.cookie);</script>

---

3. 피해자가 2번 링크를 클릭하면, 브라우저가 다음 요청을 전송

/page.html?default=<script>alert(document.cookie);</script>

---

4. 서버(www.test.com)에서 위 자바 스크립트 코드가 포함된 페이지로 응답/브라우저는 페이지에 대한 DOM 객체 생성

http://www.test.com/page.html?default=<script>alert(document.cookie);</script>

---

5. 브라우저에 의해 Attacker의 악성 스크립트 구문 실행

alert(document.cookie);

---

<cvss3.1>

https://docs.fluidattacks.com/criteria/vulnerabilities/371/


## TEST
1. CORS 점검 시 요청 패킷 해더에 어떠한 해더를 집어 넣어야 하나요?
간단한 요청이 아닐 경우 peflight request - OPTIONS
그러면 서버에서 응답헤더에 aceess-control-allow-origin 필드에 접근이 허용된 오리진을 담아서 보냄
2. Prepared Statement를 이용하면 좋은 점이 무엇인가요?
캐시에 저장된 쿼리를 활용하기 때문에 실행이 빠르며 SQLI를 막기위한 방법으로 활용된다. 소프트웨어 파싱?ᩚ
<단점> 동적 쿼리작성 어려움, 쿼리에 오류가 생긴경우 분석 어려움
3. ORM이나 Framework를 이용 시 SQLi가 발생할 수 있나요? 있거나 아니라면 해당 사유를 설명하시오.
4. DOM vs Reflcted의 CVSS 3.1 점수를 나타내고, 이유를 설명하세요
DOM - 6.1 / 미디엄 / AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N/
Reflected - 4.7 / 미디엄 /AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N/
5. SSH, FTP, Talnet에 대하여 비교하여 설명하시오. → **sftp ftps 차이**
ssh: 보안이 탄탄한 통신방법
secure shell 원격지 호스트 컴퓨터에 접속하기 위해 사용하는 인터넷 프로토콜
ftp: 파일 전송에 사용되는 통신방법 file transfer protocol
talnet: 보안이 안되는 통신방법
네트워크에 있는 컴퓨터를 자신의 컴퓨터처럼 파일 전송, 파일 생성, 디렉토리 생성 등 자유롭게 하지만 보안문제 있음