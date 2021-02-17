import os
import pandas as pd
MALDIR="malicious"

def files_in_dir(root_dir):
    filelist=[]
    files = os.listdir(root_dir)
    for file in files:
        path = os.path.join(root_dir, file)
        if(os.path.isfile(path)):
            filelist.append(path)
        if os.path.isdir(path):
            filelist=filelist+files_in_dir(path)
    return filelist

def maltocsv(dirname,maxlength):
    linelist=[] #for debugging[REMOVABLE]
    df=pd.DataFrame({'col':[0 for i in range(maxlength)]})
    filelist=files_in_dir(dirname)
    for filepath in filelist:
        file=pd.read_csv(filepath)
        file=list(file['idx'])
        for line in file:
            linelist.append(line) #for debugging[REMOVABLE]
            df['col'][line]=1
    df.to_csv('result.csv')
    print("COMPLETED")
    linelist.sort() #for debugging[REMOVABLE]
    print(linelist) #for debugging[REMOVABLE]

maltocsv(MALDIR,300000)