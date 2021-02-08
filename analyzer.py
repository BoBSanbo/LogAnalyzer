# parser를 통해 추출된 파일들을 통해 분석하는 클래스
import logparser
import pandas as pd
import os
import shutil
import datetime

def createFolder(directory):
    try:
        if not os.path.exists(directory):
            os.makedirs(directory)
    except OSError:
        print ('Error: Creating directory. ' +  directory)

class WebLog:
    def __init__(self, ip, dfData):
        self.ip         = ip
        self.time       = dfData["time"]
        self.method     = dfData["method"]
        self.uri        = dfData["uri"]
        self.protocol   = dfData["protocol"]
        self.status     = dfData["status"]
        self.bytes      = dfData["bytes"]

        self.directory  = ""
        self.filename   = ""
        self.args = dict()

        self.parsing_uri(self.uri)

    def parsing_uri(self, uri):
        try:
            items = uri.split("?")
            idx = items[0].rfind('/')
            self.directory = items[0][:idx + 1]
            self.filename = items[0][idx + 1:]
            
            args = items[1].split("&")
            for arg in args:
                arg = arg.replace(" ", "")
                key = arg.split("=")[0]
                value = str(arg.split("=")[1])
                self.args[key] = value

        except IndexError: # args가 없는 경우
            self.args = '-'
        except AttributeError:
            print('AttributeError')
    
    def __str__(self):
        return f"Class log {self.ip}: {self.time} {self.method} {self.uri} {self.protocol} {self.bytes}\n \
                    dir: {self.directory} filename: {self.filename} args: {self.args}"

class Analyzer():
    """
    < 설명 >
    1. IP로 분류된 로그 파일을 읽어들인다.
    2. 브루트 포스인지를 확인하기 위해 URI 상으로 동일한 로그를 모은다.
    2.1. 메서드(POST)랑 상태코드를 체크하고, 시간을 확인하여, 브루트 포스인지를 확인한다.
    2.2. URI 상으로 중요한 파일 요청인지 확인한다.
    2.3. param 값에 대해 확인한다.(GET)

    """
    def __init__(self):
        self.status = dict()


    def run(self, logParser):
        # 1. read_csv() : return csv
        # 2.0. accumulate_by_uri() : return logs
        # 2.1. filter_about_uri(): return [True or False]
        # 2.2. filter_about_tools(): return [True or False] 이상행위에 대한 감지
        # 2.3. filter_about_param(): return [True or False] 공격 탐지 관점
        createFolder("malicious")
        for logfile in logParser.file_list:
            self.accumulate_by_uri(logParser, logfile)
            path = logfile.replace('.csv', '')
            createFolder(f"malicious/{path}")
            createFolder(f'malicious/{path}/tools')
            for urifile in os.listdir(path):
                if self.filter_about_uri(urifile):
                    shutil.move(f'{path}/{urifile}', f'malicious/{path}/{urifile}')
                    continue
                self.filter_about_tools(path, urifile, logParser)
            
            # target = os.path.join(logParser.target_path, logfile)
            # for log in self.read_csv(target, logfile):

            #     print(log)
            #     self.analyze_about_bruteforce(log)
            #     self.analyze_about_uri(log)

    def read_csv(self, target, fileName):
        ip = fileName.replace('.csv', '')
        df = pd.read_csv(target, error_bad_lines=False)

        for i in range(len(df)):
            try:
                yield WebLog(ip, df.iloc[i])
            except KeyError:
                continue

    def accumulate_by_uri(self, logParser, logfile):
        ip = logfile.replace('.csv', '')
        createFolder(ip)
        try:
            logParser.parse_by_uri(logfile, ip)
        except KeyError:
            return

    def filter_about_uri(self, logfile):
        # uri 상으로 한번 거르고(with file.txt), 에러코드를 반환하는 경우
        uri = logfile.replace('.csv', '').replace('#', '/')
        uri = uri[1:]   #파일명이 //어쩌구로 나와서 맨앞에 slash 없애줌
        with open("file.txt", 'r', encoding='UTF8') as file:
            lines = file.readlines()
            for line in lines:
                if (line[:-1] in uri):  #맨 뒤에 \n이 들어가서 \n소거
                    print(line + " Detected in file!")
                    return True
        return False

    def filter_about_tools(self, path, logfile, logParser):
    # 일정시간마다 작동하는 것과 특정 시간 내에 몇번의 시도가 있는 지를 통해 파악 가능
    # 동일한 IP, 동일한 경로로 짧은 시간 내에 얼마나 시도를 했는 지를 분석
    # POST인 경우 브루트 포스로 볼 수 있다.
    # GET인 경우, 파라미터값이 어떻게 달라지는 지를 봐야한다.
        df = pd.read_csv(f'{path}/{logfile}')
        df.set_index('time', inplace=True)
        print(f'{path}/{logfile}')

        timeIndex = list(set(df.index.tolist()))
        timeIndex.sort()
        previousTime = timeIndex[0]
        logs = df.loc[previousTime]
        if isinstance(logs, pd.Series):
            logs = pd.DataFrame(logs).transpose()
        dataQueue = logs

        previousTime = datetime.datetime.strptime(previousTime, '%Y-%m-%d %H:%M:%S')
        timeIndex.pop(0)

        for row in timeIndex:
            print(dataQueue)
            rowTime = datetime.datetime.strptime(row, '%Y-%m-%d %H:%M:%S')

            if rowTime != previousTime + datetime.timedelta(seconds=1):
                if len(dataQueue) > 5: # 피쳐 값을 제대로 수정하면 될 듯
                    logParser.save_to_csv(dataQueue, f'malicious/{path}/tools/{logfile}')
                    df.drop(row, inplace=True)
                dataQueue = pd.DataFrame()
                continue

            logs = df.loc[row]
            if isinstance(logs, pd.Series):
                logs = pd.DataFrame(logs).transpose()
            dataQueue = dataQueue.append(logs)
            previousTime = rowTime

        return

    def filter_about_param(self):
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

def get_parser_from_args():
    
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
    logParser = get_parser_from_args()
    Analyzer().run(logParser)

