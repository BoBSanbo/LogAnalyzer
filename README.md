# Log Analyzer

### 환경 설정

python -r requirements.txt

### 실행 방법

도움말

python main.py -h


실행 방법

usage: python main.py [-h] -p PATH [-e {csv,txt}] -f {toCsv,byIp,byUri,byStatus,bySize,byTag,byArg, all}

**주의사항**

1. toCsv 함수를 통해 CSV 파일로 만드는 것을 추천

    ex) python main.py -p test -t d -f toCsv

2. 만들어진 CSV 파일에 대해 함수를 실행할 것

    ex) python main.py -p csv/{filename} -f byIp
    
        python main.py -p csv -f all



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


**parse_by_ip를 제외한 나머지 메서드들은 분석 인사이트를 얻기위해 만들어진 메서드**


- Analyzer
    파싱한 로그들을 분석하는 객체

    메서드
    - run
        IP별로 분류된 로그파일을 읽어들여 아래의 메서드들을 순차적으로 실행시키는 메서드
    - accumulate_by_uri
        로그파일을 URI 별로 재분류하는 메서드
    - filter_about_uri
        URI 별로 분류된 로그파일을 읽어들여 의심가는 URI에 대해 처리
    - filter_about_tools
        tool 사용이 의심가는 로그들(일정 시간동안 동일한 경로로 특정 수치이상 요청 등)에 대해 처리
    - filter_about_tools_post
        POST 메서드에 대해 처리
    - filter_about_tools_get
        이전 로그와 파라미터 유사도를 측정하여 GET 메서드 로그들에 대해 처리
    - filter_about_params
        파라미터의 키-밸류를 분석하여, 의심가는 로그들을 처리


- Accumulator
    분석결과를 수집하는 객체





