# Log Analyzer

### 환경 설정

python -r requirements.txt

### 실행 방법

도움말

python main.py -h


실행 방법

usage: python main.py [-h] -p PATH -t {d,f} [-e {csv,txt}] -f {toCsv,byIp,byUri}

**주의사항**

1. toCsv 함수를 통해 CSV 파일로 만드는 것을 추천

    ex) python main.py -p test -t d -f toCsv

2. 만들어진 CSV 파일에 대해 byIP 혹은 byUri 함수를 실행할 것

    ex) python main.py -p csv/{filename} -t f -f byIp
    
        python main.py -p csv -t d -f byUri



## Class

- LogParser 
    로그를 파싱하는 객체

    메서드
    - __parse_access_log : access log 파일의 정규표현식에 맞춰 파싱하는 메서드
    - __read_csv : csv를 읽는 메서드
    - parse_to_csv : txt 파일을 csv로 파싱하는 메서드
    - parse_by_ip : csv 파일을 읽어들여 ip별로 분류해주는 메서드
    - parse_by_uri : csv 파일을 읽어들여 uri별로 분류해주는 메서드

- Analyzer
    파싱한 로그들을 분석하는 객체

- Accumulator
    분석결과를 수집하는 객체

- Extarctor
    수집한 최종 결과를 파일로 추출하는 객체