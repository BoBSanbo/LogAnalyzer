from logparser import *
import os
import sys
from argparse import ArgumentParser

def createFolder(directory):
    try:
        if not os.path.exists(directory):
            os.makedirs(directory)
    except OSError:
        print ('Error: Creating directory. ' +  directory)

if __name__=="__main__":
    by_kinds = ['ip1','time','method','uri','protocol', 'status', 'bytes']

    parser = ArgumentParser()
    parser.add_argument('-p', '--path', type=str, required=True, help='The path of thing to parse')
    parser.add_argument('-e', '--extension', type=str, default='csv', choices=['csv', 'txt'], help='The type which is csv or txt. Default value is csv')
    parser.add_argument('-f', '--function', type=str, required=True, choices=['toCsv', 'byIp', 'byUri','byStatus','bySize', 'byTag', 'byParam'], help='The function which is executed')
    # parser.add_argument('-t', '--type', type=str, required=True, choices=['d', 'f'], help='The type which is Direcotory or File')

    args = parser.parse_args()
    args.path = args.path.replace('\\', '/')
    
    # if args.type == 'd':
    #     logParser = LogParser(args.path, "dir", args.extension)
    # elif args.type == 'f':
    #     logParser = LogParser(args.path, "file", args.extension)
    
    if os.path.isdir(args.path):
        logParser = LogParser(args.path, "dir", args.extension)
    elif os.path.isfile(args.path):
        logParser = LogParser(args.path, "file", args.extension)
    else:
        raise Exception('Invalid path')

    if args.function == 'toCsv':
        createFolder('./csv')
        for logfile in logParser.file_list:
            logParser.parse_to_csv(logfile, 'ip1') ## 일단은 IP별로 분류
    elif args.function == 'byIp':
        createFolder('./ip')
        for logfile in logParser.file_list: 
            logParser.parse_by_ip(logfile, 'ip1')
    elif args.function == 'byUri':
        createFolder('./uri')
        for logfile in logParser.file_list: 
            logParser.parse_by_uri(logfile)
    elif args.function == 'byStatus':
        createFolder('./status')
        for logfile in logParser.file_list:
            logParser.parse_by_status(logfile)
    elif args.function == 'bySize':
        createFolder('./size')
        for logfile in logParser.file_list:
            logParser.parse_by_size(logfile)
    elif args.function == 'byTag':
        createFolder('./tag')
        for logfile in logParser.file_list:
            logParser.parse_by_tag(logfile)
    elif args.function == 'byParam':
        createFolder('./param')
        for logfile in logParser.file_list:
            logParser.parse_by_arg(logfile)