# -*- coding: utf-8 -*-
#Castro Rendón Virgilio

def get_url(ip,port,protocol):
    if protocol == "HTTP":
        if port not in ['80','443']:
            url = "http://%s:%s" % (ip, port)
        else:
            url = "http://%s" % (ip)
    else:
        if port not in ['80','443']:
            url = "https://%s:%s" % (ip, port)
        else:
            url = "https://%s" % (ip)
    return url

with open('http_response.html','r') as i:
    url = get_url('www.seguridad.unam.mx','443','HTTPS')
    base = '\"'+url #The base is something like: "http://mysite.com
    for line in i.readlines(): 
        #Looks for the index of all the substrings that start with the base one in a single line
        indexes = [i for i in range(len(line)) if line.startswith(base, i)]
        if indexes != []: 
            for index in indexes:
                f_char_index = index + 1    #The first char of the url removes the '"' char added in the base substring
                #The last char of the url is '"'. The first index is added to get the index in the whole file
                l_char_index = line[f_char_index:].index('"') + f_char_index  
                url = line[f_char_index:l_char_index]
                resource = url.split('//')[1]
                print resource

