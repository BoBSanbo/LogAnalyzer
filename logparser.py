
import pandas as pd
import os
import re

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
        df2.index.name = 'idx'
        # Save Data to CSV
        df2.to_csv("csv/"+filename+".csv", index=True)

    def __parse_access_log(self, path, pattern):
        for line in open(path):
            for m in pattern.finditer(line):
                yield m.groups()
    
    def __read_csv(self, path):
        df = pd.read_csv(path, error_bad_lines=False)
        return df

    def parse_by_ip(self, logfile, index):
        df = self.__read_csv(self.target_path + "/" + logfile)
        df.set_index(index, inplace=True)
        df = df.sort_values(by="time" ,ascending=True)

        # 고유한 index set을 탐색
        for row in set(df.index.tolist()):
            path = "ip/"+row+".csv"
            self.save_to_csv(df.loc[row, :], path)
            
    def parse_by_uri(self, logfile, folder):
        df = self.__read_csv(self.target_path + "/" + logfile)
        for i in range(len(df)):
            try:
                ect = df.iloc[i] # 기존 데이터
                line = df.loc[i, 'uri'] # uri만 가지는 데이터
                items = line.split("?")
                idx = items[0].rfind('/')
                directory = items[0][:idx + 1]
                filename = items[0][idx + 1:]
                params = items[1].split("&")
                print(directory, filename, params)
            except IndexError: # params 없는 경우
                #print('IndexError')
                params = '-'
            except AttributeError:
                #print('AttributeError')
                continue

            series = pd.Series([directory, filename, params], index = ["directory", "filename", "params"])   
  
            series2 = series.append(ect)

            directory = directory.replace('/', '#')
            path = f"{folder}/"+directory+".csv"
            self.save_to_csv(pd.DataFrame(series2).transpose(), path)

    def parse_by_status(self, logfile):
        df = self.__read_csv(self.target_path + "/" + logfile)
        df.set_index('status', inplace=True)
        df = df.sort_values(by="time", ascending=True)

        # 고유한 index set을 탐색
        for row in set(df.index.tolist()):
            path = "status/" + str(row) + ".csv"
            self.save_to_csv(df.loc[row], path)

    def parse_by_size(self,logfile):
        df = self.__read_csv(self.target_path + "/" + logfile)
        df.set_index('bytes', inplace=True)
        df = df.sort_values(by="time", ascending=True)
        df=df.replace({'bytes':'-'},{'bytes':0}) #결측치 '-'를 0으로 변경
        # 고유한 index set을 탐색
        for row in set(df.index.tolist()):
            try:
                rowsize=int(row)-(int(row)%100)
            except:
                rowsize=0
            path = "size/" + str(rowsize) + ".csv"
            self.save_to_csv(df.loc[row], path)

    def parse_by_tag(self,logfile):
        df = self.__read_csv(self.target_path + "/" + logfile)

        for row in range(len(df)):
            uri = df.loc[row, 'uri']
            tags={"..%2F" : 'slash',"%3C" : 'left_bracket',"%3B" : 'semicolon',"%3E" : 'right_bracket'}
            for tag in tags: 
                try:
                    if tag in uri.lower():
                        path = "tag/" + tags[tag] + ".csv"
                        series = df.loc[row].T
                        self.save_to_csv(pd.Dataframe(series).transpose(), path)

                except TypeError:
                    print("TypeError",uri)
                    continue

                except AttributeError:
                    print("attribute:",uri)
                    continue
    
    def parse_by_param(self, logfile):
        df = self.__read_csv(self.target_path + "/" + logfile)
        for i in range(len(df)):
            try:
                ect = df.loc[i]
                line = df.loc[i, 'uri'] # uri만 가지는 데이터
                items = line.split("?")
                params = items[1].split("&")
                for param in params:
                    param = param.split("=")
                    key = param[0]
                    value = param[1]

                    series = pd.Series([value, self.__check_type(value) ], index = ["value", "type"])  
                    series2 = series.append(ect)
                    path = "param/"+key+".csv"
                    self.save_to_csv(pd.DataFrame(series2).transpose(), path)
                    
            except IndexError: # args가 없는 경우
                #print('IndexError')
                continue

            except AttributeError:
                #print('AttributeError')
                continue

    def save_to_csv(self, data, path):
        try: 
            if os.path.isfile(path):
                if data.index.name == None:
                    data.to_csv(path, mode='a', header=False, index=False)
                else:
                    data.to_csv(path, mode='a', header=False, index=True)
            else :
                if data.index.name == None:
                    data.to_csv(path, header=True, index=False)
                else:
                    data.to_csv(path, header=True, index=True)
        except OSError: 
            print('OSError : 올바르지 않은 경로')
    
    def __check_type(self, data):
        if data.isalpha():
            return "alpha"
        elif data.isdigit():
            return "digit"
        else :
            return "special"


