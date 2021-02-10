# Log Analyzer

### 환경 설정

python -r requirements.txt

### 실행 방법

도움말

python main.py -h


실행 방법

usage: python main.py [-h] -p PATH -t {d,f} [-e {csv,txt}] -f {toCsv,byIp,byUri,byStatus,bySize,byTag,byArg}

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
    - parse_by_status: 상태코드 별로 분류해주는 메서드
    - parse_by_size: 패킷 사이즈 크기(size)별로 분류해주는 메서드
    - parse_by_tag: Tag('../', '<', '>', ';')별로 분류해주는 메서드
    - parse_by_arg: Arg 별로 값을 저장하는 메서드


**parse_by_ip를 제외한 나머지 메서드들은 분석을 쉽게하기 위해 파일들을 분류하는 것**

**실제로 분석할 때는 아마도 IP별로 분류된 파일들을 위주로 분석되지 않을까 생각**


- Analyzer
    파싱한 로그들을 분석하는 객체

- Accumulator
    분석결과를 수집하는 객체

- Extarctor
    수집한 최종 결과를 파일로 추출하는 객체


### To Do

1. POST인데 파라미터가 있는 경우는?
2. tools - GET에 대해 정확한 방법
3. Params
    1. 특정 키에 대한 밸류 ex: cid인데 CT로 시작하지 않는 경우
    2. 키 중 파일확장자를 밸류로 가질 수 있는 키
    3. 파일 확장자에 대한 정보
