from logparser import *
import os
import sys

if __name__=="__main__":
    by_kinds = ['ip1','time','method','uri','protocol', 'status', 'bytes']

    if len(sys.argv) is not 3 or sys.argv[2] not in by_kinds:
        print("Insufficient arguments: main.py [path_dir] [sort_type]")
        print("sort type: 'ip1','time','method','uri','protocol', 'status', 'bytes'")
        sys.exit()

    path_dir = sys.argv[1]
    by = sys.argv[2]

    logParser = LogParser(path_dir)

    idx = 0
    for logfile in logParser.file_list:
   
        # testing code 
        # start
        if idx == 1:
            break
        idx += 1
        print(logfile)
        # end
        
        # csv file로 만듦
        #if not os.path.isfile("csv/"+logfile+".csv"):
        #    logParser.parse_to_csv(logfile, by)

        # csv 파일을 읽어들여서 ip1로 분류
        #logParser.parse_by_ip(logfile, "ip1")

        # csv 파일을 읽어들여서 uri 파싱해서 출력만
        #logParser.parse_by_uri(path_dir, logfile)
