# parser를 통해 추출된 파일들을 통해 분석하는 클래스
import logparser
import pandas as pd
import os
import shutil
import datetime
import json
import ast
import re

def createFolder(directory):
    try:
        if not os.path.exists(directory):
            os.makedirs(directory)
    except OSError:
        print ('Error: Creating directory. ' +  directory)

def createFolderInMalicious(path):
    createFolder(f"malicious/{path}")
    # createFolder(f"malicious/{path}/uri")
    # createFolder(f'malicious/{path}/tools')
    # createFolder(f'malicious/{path}/tools/post')
    # createFolder(f'malicious/{path}/tools/get')
    # createFolder(f'malicious/{path}/params')

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
    def __init__(self):
        self.status = dict()

    def run(self, logParser):
        # 2.0. accumulate_by_uri() : return logs
        # 2.1. filter_about_uri(): return [True or False]
        # 2.2. filter_about_tools(): return [True or False] 이상행위에 대한 감지
        # 2.3. filter_about_params(): return [True or False] 공격 탐지 관점
        createFolder("malicious")

        for logfile in logParser.file_list:
            self.accumulate_by_uri(logParser, logfile)
            path = logfile.replace('.csv', '')

            createFolderInMalicious(path)

            for urifile in os.listdir(path):
                root, extension = os.path.splitext(urifile)
                if extension != '.csv':
                    continue
                if self.filter_about_uri(urifile):
                    createFolder(f"malicious/{path}/uri")
                    shutil.move(f'{path}/{urifile}', f'malicious/{path}/uri/{urifile}')
                    continue
                self.filter_about_tools(path, urifile, logParser)
                self.filter_about_params(path, urifile, logParser)

    def __check_type(self, data):
        if data.isalpha():
            return "alpha"
        elif data.isdigit():
            return "digit"
        else:
            return "special"

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
        with open("cheatsheet/file.txt", 'r', encoding='UTF8') as file:
            lines = file.readlines()
            for line in lines:
                if (line[:-1] in uri):  #맨 뒤에 \n이 들어가서 \n소거
                    print(line + " Detected in file!")
                    return True
        return False

    def filter_about_tools(self, path, logfile, logParser):
        df = pd.read_csv(f'{path}/{logfile}')
        print(f'{path}/{logfile}')
        postDf = df[df['method'] == "POST"]

        getDf = df[df['method'] == "GET"]
        if not postDf.empty:         
            self.filter_about_tools_post(postDf, path, logfile, logParser)
        
        if not getDf.empty:
           self.filter_about_tools_get(getDf, path, logfile, logParser)

    def filter_about_tools_post(self, df, path, logfile, logParser):
        df.set_index('time', inplace=True)

        timeIndex = list(set(df.index.tolist()))

        timeIndex.sort()
        previousTime = timeIndex[0]
        logs = df.loc[previousTime]

        if isinstance(logs, pd.Series):
            logs = pd.DataFrame(logs).transpose()
        dataQueue = logs
        
        try:
            previousTime = datetime.datetime.strptime(previousTime, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            previousTime = datetime.datetime.strptime(previousTime, '%Y-%m-%d %H:%M')
        timeIndex.pop(0)

        for row in timeIndex:
            try:
                rowTime = datetime.datetime.strptime(row, '%Y-%m-%d %H:%M:%S')
            except ValueError:
                rowTime = datetime.datetime.strptime(row, '%Y-%m-%d %H:%M')

            # 만약 datetime이 연속하지 않다면
            if rowTime > previousTime + datetime.timedelta(seconds=2):
                if len(dataQueue) > 5: # 피쳐 값을 제대로 수정하면 될 듯
                    createFolder(f'malicious/{path}/tools')
                    createFolder(f'malicious/{path}/tools/post')
                    logParser.save_to_csv(dataQueue, f'malicious/{path}/tools/post/{logfile}')
                dataQueue = pd.DataFrame()
                continue
                
            # 만약 datetime이 연속하다면
            logs = df.loc[row]
            if isinstance(logs, pd.Series):
                logs = pd.DataFrame(logs).transpose()
            dataQueue = dataQueue.append(logs)
            previousTime = rowTime

        return
            
    def filter_about_tools_get(self, df, path, logfile, logParser):
        from resemblanceCalculator import ResemblanceCalculator as RC
        log = df.iloc[0]

        previousTime = log['time']

        try:
            previousTime = datetime.datetime.strptime(previousTime, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            previousTime = datetime.datetime.strptime(previousTime, '%Y-%m-%d %H:%M')

        previousParams = []
        previousFilename = log['filename']

        if log['params'] != '-':
            params = ast.literal_eval(log['params'])

            for param in params:
                try:
                    key = param.split("=")[0]
                    previousParams.append(key)
                except IndexError:
                    continue
        
        log = pd.DataFrame(log).transpose()
        dataQueue = log
        
        for i in range(1, len(df)):
            row = df.iloc[i, :]

            if row["params"] == "-": continue

            params = ast.literal_eval(row["params"])
            currentParams = []
            currentFilename = row['filename']

            for param in params:
                try:
                    key = param.split("=")[0]
                    currentParams.append(key)
                except IndexError:
                    continue
            try:    
                currentTime = datetime.datetime.strptime(row['time'], '%Y-%m-%d %H:%M:%S')
            except ValueError:
                currentTime = datetime.datetime.strptime(row['time'], '%Y-%m-%d %H:%M')

            # 만약 datetime이 연속하지 않다면
            if currentTime > previousTime + datetime.timedelta(seconds=2):
                if len(dataQueue) > 5: # 피쳐 값을 제대로 수정하면 될 듯
                    createFolder(f'malicious/{path}/tools')
                    createFolder(f'malicious/{path}/tools/get')
                    logParser.save_to_csv(dataQueue, f'malicious/{path}/tools/get/{logfile}')
                dataQueue = pd.DataFrame()
                continue

            # 만약 파라미터가 유사하지 않다면
            isResemble = True
            previousParams.sort()
            currentParams.sort()

            for i in range(max(len(previousParams), len(currentParams))):
                try:
                    if not RC.get_resemblance(previousParams[i], currentParams[i], 2):
                        isResemble = False
                        break
                except IndexError:
                    isResemble = False
                    break

            if not isResemble: 
                dataQueue = pd.DataFrame()
                previousParams = currentParams

            # 만약 datetime이 연속하고 파라미터도 유사하다면
            if isinstance(row, pd.Series):
                log = pd.DataFrame(row).transpose()
            dataQueue = dataQueue.append(log)
            previousTime = currentTime
        
        return

    def filter_about_params(self, path, logfile, logParser):
        dataQueue = pd.DataFrame()

        isMalicious = False
        df = pd.read_csv(f'{path}/{logfile}')

        # ;, <, >, =, ", ', ../, ..\
        dangerParams = [r"%3B", r"%3C", r"%3E", r"%3D", r"%22", r"%27", r"%3D", r"%2e%2e%2f", r"%2e%2e/", \
            r"..%2f", r"%2e%2e%5c", r"%2e%2e\\", r"..%5c", r"%252e%252e%255c", r"..%255c", r"..%c0%af", r"..%c1%9c"\
                r';', r'<', r'>', r'"', r"'", r'(', r')']  

        with open('cheatsheet/fileExtensions.json') as json_file:
            fileExtensions = json.load(json_file)["extensions"]

        domainRe = r'[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)'
        domainRegex = re.compile(domainRe)

        ipRe = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$'
        ipRegex = re.compile(ipRe)
        
        # 특수문자 중복 허용 갯수 
        DUP_ALLOWED = 4

        for i in range(len(df)):
            row = df.iloc[i, :]
            if row["params"] == "-": continue
            params = ast.literal_eval(row["params"])

            for param in params:
                try:
                    key = param.split("=")[0]
                    value = param.split("=")[1]
                except IndexError:
                    continue
                
                for dangerParam in dangerParams:
                    if dangerParam in value or dangerParam in key and 'amp' not in key:
                        # TODO : write file
                        print("!!danger!! Params " + dangerParam + " in " + param)
                        log = pd.DataFrame(row).transpose()
                        dataQueue = dataQueue.append(log)
                        isMalicious = True
                        break
                
                # key에 url이 없는데 url이 있을경우
                # TODO : write file 및 key에 대한 분석(ex: index.php와 같은 파일을 밸류로 가질 수 있는 키)
                if "url" not in key.lower() and "domain" not in key.lower():
                    # ip regex와 일치할 경우
                    if None != (ipRegex.search(value.lower())):
                        print("!!warning!! 허용되지 않은 url " + param)
                        log = pd.DataFrame(row).transpose()
                        dataQueue = dataQueue.append(log)
                        isMalicious = True
                        break

                    # domain regex와 일치할 경우
                    if None != (domainRegex.search(value.lower())):
                        # check extension
                        root, extension = os.path.splitext(value)
                        if extension not in fileExtensions:
                            print("!!warning!! 허용되지 않은 url " + param)
                            log = pd.DataFrame(row).transpose()
                            dataQueue = dataQueue.append(log)
                            isMalicious = True
                            break                            

                cnt = 0
                dupWord = ''
                for i in range(len(value)-1):
                    if value[i] == value[i+1]:
                        cnt += 1
                        dupWord = value[i]
                
                if (cnt > DUP_ALLOWED) and not dupWord.isdigit():
                    print("!!warning!! 특정 문자 반복 " + value)
                    log = pd.DataFrame(row).transpose()
                    dataQueue = dataQueue.append(log)
                    isMalicious = True
                    break
                
                #ls와 같이 명령어를 밸류로 가지는 경우
                with open('cheatsheet/instructions.json') as json_file:
                    instructions = json.load(json_file)["instructions"]
                
                for instruction in instructions:
                    if instruction in value:
                        log = pd.DataFrame(row).transpose()
                        dataQueue = dataQueue.append(log)
                        isMalicious = True
                        break

                #밸류로 script 문법을 가지는 경우 ex: res.end(require('fs').readdirSync('..').toString())
                with open('cheatsheet/scripts.json') as json_file:
                    scripts = json.load(json_file)["scripts"]

                for script in scripts:
                    if script in value:
                        log = pd.DataFrame(row).transpose()
                        dataQueue = dataQueue.append(log)
                        isMalicious = True
                        break
                    
                #script, backup, WEB-INF, passwd와 같이 의심되는 단어가 파라미터에 포함되는 경우
                with open('cheatsheet/words.json') as json_file:
                    words = json.load(json_file)["words"]

                for word in words:
                    if word in value:
                        log = pd.DataFrame(row).transpose()
                        dataQueue = dataQueue.append(log)
                        isMalicious = True
                        break

                
                ID_DUP_ALLOWED = 1

                if "id" in key.lower():
                    cnt = 0
                    for i in range(len(value)):
                        if value[i].isdigit() or value[i].isalpha():
                            cnt = 0
                            continue
                        
                        cnt += 1
                        
                    if cnt > ID_DUP_ALLOWED:
                        print("!!warning!! ID 키에 대해 밸류에서 특정 문자 반복 " + value)
                        log = pd.DataFrame(row).transpose()
                        dataQueue = dataQueue.append(log)
                        isMalicious = True
                        break
                
            
                if "year" in key.lower() or "month" in key.lower() \
                    or "day" in key.lower() or "time" == key.lower():
                    for i in range(len(value)):
                        if value[i].isdigit():
                            continue
                        isMalicious = True

                    if isMalicious:
                        print("!!warning!! Year, Month, Day 키에 대해 밸류에서 문자 발견 " + value)
                        log = pd.DataFrame(row).transpose()
                        dataQueue = dataQueue.append(log)
                        isMalicious = True
                        break
                        

        if isMalicious:
            createFolder(f'malicious/{path}/params')
            print("=========================================================")
            print(dataQueue)
            print("=========================================================")
            logParser.save_to_csv(dataQueue, f'malicious/{path}/params/{logfile}')

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

