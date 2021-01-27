from logparser import *
import os
import sys

if __name__=="__main__":
    path_dir = sys.argv[1]

    if len(sys.argv) != 2:
        print("Insufficient arguments")
        sys.exit()

    print("Folder path : " + path_dir)
    
    logparser = LogParser(path_dir)
    file_list=os.listdir(path_dir)
