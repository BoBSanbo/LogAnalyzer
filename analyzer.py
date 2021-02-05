# parser를 통해 추출된 파일들을 통해 분석하는 클래스
import logparser
import pandas as pd
import os

class WebLog:
    def __init__(self, ip, dfData):
        self.ip         = ip
        self.time       = dfData["time"]
        self.method     = dfData["method"]
        self.uri        = dfData["uri"]
        self.protocol   = dfData["protocol"]
        self.uri        = dfData["status"]
        self.bytes      = dfData["bytes"]
            
    
    def __str__(self):
        return f"Class log {self.ip}: {self.time} {self.method} {self.uri} {self.protocol} {self.uri} {self.bytes}"


class Analyzer:
    """
    < 설명 >
    1. IP로 분류된 로그 파일을 읽어들인다.
    2. 브루트 포스인지를 확인하기 위해 URI 상으로 동일한 로그를 모은다.
    2.1. 메서드(POST)랑 상태코드를 체크하고, 시간을 확인하여, 브루트 포스인지를 확인한다.
    2.2. URI 상으로 중요한 파일 요청인지 확인한다.
    2.3. param 값에 대해 확인한다.(GET)

    """

    def run(self, logParser):
        # 1. read_csv() : return csv
        # 2.0. accumulate_by_uri() : return logs
        # 2.1. analyze_about_bruteforce(): return [True or False] 
        # 2.2. analyze_about_uri(): return [True or False]
        # 2.3. analyze_about_param(): return [True or False]

        for logfile in logParser.file_list:
            target = os.path.join(logParser.target_path, logfile)
            for log in self.read_csv(target, logfile):
                print(log)


    def read_csv(self, target, fileName):
        ip = fileName.replace('.csv', '')
        df = pd.read_csv(target, error_bad_lines=False)
        df = df.sort_values(by="time" ,ascending=True)

        for i in range(len(df)):
            data = WebLog(ip, df.iloc[i])
            yield data

    def accumulate_by_uri(self):
        return

    def analyze_about_bruteforce(self):
    # 동일한 IP, 동일한 경로로 짧은 시간 내에 얼마나 시도를 했는 지를 분석
    # POST인 경우 브루트 포스로 볼 수 있다.
    # GET인 경우, 파라미터값이 어떻게 달라지는 지를 봐야한다.
        return

    def analyze_about_uri(self):
    # uri 상으로 중요한 파일을 시도하였고(file.txt), 에러코드를 반환하는 경우
        return

    def analyze_about_param(self):
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
        return

def getParserFromArgs():
    
    parser = ArgumentParser()
    parser.add_argument('-p', '--path', type=str, default='ip', help='The path of thing to parse. Default value is ip')
    parser.add_argument('-e', '--extension', type=str, default='csv', choices=['csv', 'txt'], help='The type which is csv or txt. Default value is csv')

    args = parser.parse_args()
    args.path = args.path.replace('\\', '/')

    if os.path.isdir(args.path):
        logParser = logparser.LogParser(args.path, "dir", args.extension)
    elif os.path.isfile(args.path):
        logParser = logparser.LogParser(args.path, "file", args.extension)
    else:
        raise Exception('Invalid path')

    return logParser

if __name__=="__main__":
    from argparse import ArgumentParser

    # for debugging
    logParser = getParserFromArgs()
    Analyzer().run(logParser)

