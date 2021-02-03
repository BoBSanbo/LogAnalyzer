# parser를 통해 추출된 파일들을 통해 분석하는 클래스
class Analyzer():
    def read_csv():
    
    def analyze_by_arg_type():

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
    
