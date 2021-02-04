# parser를 통해 추출된 파일들을 통해 분석하는 클래스
class Analyzer():
    def run():
    # 1. read_csv() : return csv
    # 2.0. accumulate_by_uri() : return logs
    # 2.1. analyze_about_bruteforce(): return [True or False] 
    # 2.2. analyze_about_uri(): return [True or False]
    # 2.3. analyze_about_param(): return [True or False]
    """
    < 설명 >
    1. IP로 분류된 로그 파일을 읽어들인다.
    2. 브루트 포스인지를 확인하기 위해 URI 상으로 동일한 로그를 모은다.
    2.1. 메서드(POST)랑 상태코드를 체크하고, 시간을 확인하여, 브루트 포스인지를 확인한다.
    2.2. URI 상으로 중요한 파일 요청인지 확인한다.
    2.3. param 값에 대해 확인한다.(GET)

    """

    def read_csv():

    def accumulate_by_uri():

    def analyze_about_bruteforce():
    
    # 동일한 IP, 동일한 경로로 짧은 시간 내에 얼마나 시도를 했는 지를 분석
    # POST인 경우 브루트 포스로 볼 수 있다.
    # GET인 경우, 파라미터값이 어떻게 달라지는 지를 봐야한다.

    def analyze_about_uri():
    
    # uri 상으로 중요한 파일을 시도하였고(file.txt), 에러코드를 반환하는 경우

    def analyze_about_param():

    # key 분석
    # param의 key가 ),(와 같이 특수 문자인지도 확인

    # value 분석
    # "매개변수 - 타입" 파일을 읽고
    # 매개변수에 그 타입을 매칭 
    # if(숫자 or 알파벳 && type in json[arg])
    #   return 정상 로그
    # elif (special 인 경우)
    # {
    #   1. 태그가 있는 지(..%2F, %3B, %3E, %3C)
    #   2. 링크 값을 갖는 키가 아닌데, 링크 값을 갖는 경우 (ex: 'year=naver.com')
    #   3. 똑같은 특수문자를 여러개 사용한 경우? (ex : '))))))))))))))))')
    #   return 악성 로그
    # }
    # elif (json에 arg가 없는데 status 200인경우)
    #       그냥 정상
    # elif (json에 arg가 없고 status 에러인경우 ex 302)
    #       악성 로그

 



