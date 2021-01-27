# Log Analyzer

### 환경 설정

python -r requirements.txt

### 실행 방법

python main.py [실행할 폴더 경로] [sort_type]

Sort type
- ip1
- time
- method
- uri
- protocol
- status 
- bytes

## Class

- LogParser 
    로그를 파싱하는 객체
    - def parseByDate()
    - def parseByIp()
    - def parseByUri()
    - def parseByExtension()
    - def parseByStatus()
    - def parseByMethod()

- Analyzer
    파싱한 로그들을 분석하는 객체

- Accumulator
    분석결과를 수집하는 객체

- Extarctor
    수집한 최종 결과를 파일로 추출하는 객체