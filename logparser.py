
import pandas as pd
import os
import re

# 입출력은 모두 파일 형태로
# 1. txt -> csv 이후 csv를 읽어들여 원하는 대로 파싱하는 방법

class LogParser():
    def __init__(self, path_dir):
        self.path_dir = path_dir 
        self.file_list = os.listdir(path_dir)

        # IP - - [Date]
        self.pattern_2 = re.compile('(\S+) (\S+) (\S+) \[([\w:/]+\s[+\-]\d{4})\] \"(\S+)\s?(\S+)?\s?(\S+)?" (\d{3}) (\S+)')

        # IP - - - [Date]
        self.pattern_3 = re.compile('(\S+) (\S+) (\S+) (\S+) \[([\w:/]+\s[+\-]\d{4})\] \"(\S+)\s?(\S+)?\s?(\S+)?" (\d{3}) (\S+)')

    def parse_to_csv(self, filename, by):
        try: 
            columns = ['ip1','ip2','ip3','ip4','time','method','uri','protocol', 'status', 'bytes']
            df = pd.DataFrame(self.__parse_access_log(self.path_dir + "/" + filename, self.pattern_3), columns=columns)
            if df.empty:
                raise ValueError
        except ValueError:
            columns = ['ip1','ip2','ip3','time','method','uri','protocol', 'status', 'bytes']
            df = pd.DataFrame(self.__parse_access_log(self.path_dir + "/" + filename, self.pattern_2), columns=columns)

        df.time = pd.to_datetime(df.time, format='%d/%b/%Y:%X', exact=False)

        df2 = df.sort_values(by=by ,ascending=True)

        df2.to_csv("csv/"+filename+".csv", index=False)

    def __parse_access_log(self, path, pattern):
        for line in open(path):
            for m in pattern.finditer(line):
                yield m.groups()


    # def parseByDate(self):
    # def parseByIp(self):
    # def parseByUri(self):
    # def parseByExtension(self):
    # def parseByStatus(self):
    # def parseByMethod(self):




