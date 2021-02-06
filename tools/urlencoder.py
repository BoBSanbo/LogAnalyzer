from urllib import parse
def encoder(src):
    f= open(src,'r',encoding='UTF-8')
    lines=f.readlines()
    encodedlines=[]
    for line in lines:
        url=parse.quote(line[:-1],safe='')
        url+='\n'
        encodedlines.append(url)
    f.close()
    with open("encoded_"+src,'w') as d:
        d.writelines(encodedlines)
encoder("file.txt")