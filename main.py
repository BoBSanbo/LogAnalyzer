from logparser import *
import os
import sys

if __name__=="__main__":
    path_dir = sys.argv[1]

    if len(sys.argv) != 2:
        print("Insufficient arguments")
        sys.exit()
    
    logParser = LogParser(path_dir)

    for logfile in logParser.file_list:
        logParser.parse_to_csv(logfile, "ip1")