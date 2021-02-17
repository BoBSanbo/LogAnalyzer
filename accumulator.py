# accumulator를 통해 합쳐진 결과에 대해 사용자가 원하는 형태로 출력할 수 있도록 하는 클래스
import os
import pandas as pd
MALDIR="malicious"

class Accumulator():

    def files_in_dir(self, root_dir):
        filelist=[]
        files = os.listdir(root_dir)
        for file in files:
            path = os.path.join(root_dir, file)
            if(os.path.isfile(path)):
                filelist.append(path)
            if os.path.isdir(path):
                filelist=filelist+self.files_in_dir(path)
        return filelist

    def malicious_to_csv(self, dirname, maxlength):
        linelist=[] #for debugging[REMOVABLE]
        df=pd.DataFrame({'col':[0 for i in range(maxlength)]})
        filelist=self.files_in_dir(dirname)
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

        
    ################################################
    ##악성파일 length보고 넣어주면되는데 현재는 30만으로함##
    ################################################
    