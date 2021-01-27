
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

        # Save Data to CSV
        df2.to_csv("csv/"+filename+".csv", index=False)

    def __parse_access_log(self, path, pattern):
        for line in open(path):
            for m in pattern.finditer(line):
                yield m.groups()
    
    def __read_csv(self, path, index):
        df = pd.read_csv(path)
        return df

    def parse_by_ip(self, logfile, index):
        df = self.__read_csv("csv/" + logfile + ".csv", index)
        df.set_index(index, inplace=True)
        df = df.sort_values(by="time" ,ascending=True)
        for row in set(df.index.tolist()):
            print(df.loc[row])
            df.loc[row].to_csv("csv/"+ index + "/"+row+".csv", index=False)

    # def parseByDate(self):
    # def parseByUri(self):
    # def parseByExtension(self):
    # def parseByStatus(self):
    # def parseByMethod(self):




