# Practice03
## TTL
Time To Live: 목적지까지 갈 수 있는 hob(router) 의 수
             (OS에서 세팅 함)
- router 와 router 사이의 간격: hob
- router를 하나 건널 때 마다 TTL이 하나씩 줄어듦

- hobs가 3개까지 갔는데도 TTL이 0이 안되면 그 목적지는 없는 것
    - TTL이 너무 작으면 목적지까지 갈 수 없음
    - TTL이 너무 크면 목적지가 없음 -> 계속 돌아다님, 무한루프
    요즘은 TTL 값을 보고도 다 비슷해서 OS를 알 수 없음 (64)
- registory를 통해서 TTL 값 변경 가능
- netsh 이용해서 TTL 값 조절 가능

## TLS