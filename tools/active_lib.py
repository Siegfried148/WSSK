# -*- coding: utf-8 -*-
#Castro Rendón Virgilio
from requests import get

"""
Get the structure from the web server depending on the resources that the main page calls
After that, it tries to complete it using the resources called by the first resources mapped
"""
def map_server(url):
    try:
        response = get(url, verify=False, timeout=6)
        if response.status_code == 200:
            text = response.text
            with open('http_response.html','wb') as o:
                o.write(response.content)
        return {'resources':text}
    except Exception as e:
#        return {'error1':  'Active Analysis Error:(%s) ' % url +'Is the information correct?'}
        return {'error1': e}


"""
Calls the other functions tog get info from the server
"""
def active_analysis(ip, port, protocol):
    try:
        if ip == '' or port == '':
            return {'active_ip':'Specify an IP address or domain name and a port.', 'active_port':port}

        result_dict = {'result':True}
        if protocol == "HTTP":
            url = "http://%s:%s" % (ip, port)
        else:
            url = "https://%s:%s" % (ip, port)
        
        result_dict.update(map_server(url))
        return result_dict
    except ValueError as e:
        result_dict.update({'error1':e, 'result':True})
        return result_dict
