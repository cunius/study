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