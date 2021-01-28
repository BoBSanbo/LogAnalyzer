
import pandas as pd
import os
import re

# 입출력은 모두 파일 형태로
# 1. txt -> csv 이후 csv를 읽어들여 원하는 대로 파싱하는 방법

class LogParser():
    def __init__(self, target_path, target_type, extension):
        self.target_type = target_type
        self.extension = extension

        if target_type == 'dir':
            self.target_path = target_path 
            self.file_list = os.listdir(target_path)
        else:
            idx = target_path.rfind("/")
            self.target_path = target_path[:idx]
            self.file_list = [target_path[idx + 1:]]

        # IP - - [Date]
        self.pattern_2 = re.compile('(\S+) (\S+) (\S+) \[([\w:/]+\s[+\-]\d{4})\] \"(\S+)\s?(\S+)?\s?(\S+)?" (\d{3}) (\S+)')

        # IP - - - [Date]
        self.pattern_3 = re.compile('(\S+) (\S+) (\S+) (\S+) \[([\w:/]+\s[+\-]\d{4})\] \"(\S+)\s?(\S+)?\s?(\S+)?" (\d{3}) (\S+)')

    def parse_to_csv(self, filename, by):
        try: 
            columns = ['ip1','ip2','ip3','ip4','time','method','uri','protocol', 'status', 'bytes']
            df = pd.DataFrame(self.__parse_access_log(self.target_path + "/" + filename, self.pattern_3), columns=columns)
            if df.empty:
                raise ValueError
        except ValueError:
            columns = ['ip1','ip2','ip3','time','method','uri','protocol', 'status', 'bytes']
            df = pd.DataFrame(self.__parse_access_log(self.target_path + "/" + filename, self.pattern_2), columns=columns)

        df.time = pd.to_datetime(df.time, format='%d/%b/%Y:%X', exact=False)

        df2 = df.sort_values(by=by ,ascending=True)

        # Save Data to CSV
        df2.to_csv("csv/"+filename+".csv", index=False)

    def __parse_access_log(self, path, pattern):
        for line in open(path):
            for m in pattern.finditer(line):
                yield m.groups()
    
    def __read_csv(self, path):
        df = pd.read_csv(path)
        return df

    def parse_by_ip(self, filename, index):
        df = self.__read_csv('csv/' + filename)
        df.set_index(index, inplace=True)
        df = df.sort_values(by="time" ,ascending=True)

        # 고유한 index set을 탐색
        for row in set(df.index.tolist()):
            path = "ip/"+row+".csv"
            #print(df.loc[row])
            if os.path.isfile(path):
                df.loc[row].to_csv(path, index=False, mode='a', header=False)
            else :
                df.loc[row].to_csv(path, index=False)
            
    def parse_by_uri(self, logfile):
        df = self.__read_csv(self.target_path + "/" + logfile)
        for i in range(len(df)):
            try:
                line = df.loc[i, 'uri']
                idx = line.rfind('/')
                directory = line[:idx + 1]
                parameters = line[idx + 1:]
                file_and_args = parameters.split("?")
                filename = file_and_args[0]

                args = file_and_args[1].split("&")
                print(directory, filename, args)
            except IndexError: # args가 없는 경우
                print(directory, filename)
            except AttributeError:
                continue
         

    # def parseByExtension(self):
    # def parseByStatus(self):
    # def parse_by_size(self):




