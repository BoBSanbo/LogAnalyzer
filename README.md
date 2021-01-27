# Log Analyzer

### 환경 설정

python -r requirements.txt

## Class

- LogParser 
    로그를 파싱하는 객체
    - def parseByDate()
    - def parseByIp()
    - def parseByPath()
    - def parseByExtension()
    - def parseByStatus()
    - def parseByMethod()

- Analyzer
    파싱한 로그들을 분석하는 객체

- Accumulator
    분석결과를 수집하는 객체

- Extarctor
    수집한 최종 결과를 파일로 추출하는 객체