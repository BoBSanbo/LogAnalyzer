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
        # end
        logParser.parse_to_csv(logfile, by)
        logParser.parse_by_ip(logfile, "ip1")
