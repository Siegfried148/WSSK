# -*- coding: utf-8 -*-
#Castro Rendón Virgilio
from requests import get, options
from ssl import create_default_context, CERT_NONE
from socket import socket


def check_methods(url):
    try:
        response = options(url, verify=False, timeout=6)
        if 'allow' in response.headers:
            http_methods = response.headers['allow']
        else:
            http_methods = 'Could not determine HTTP methods'
        return {'http_methods':http_methods}
    except Exception as e:
        return {'error1': 'Passive Analysis Error:(%s) ' % url +'Is the information correct?'}



def check_index(url):
    try:
        indexes = ['index.html','index.htm','index.php','index.asp', 'index.phtml', 'index.cgi', 'index.xhtml']
        index_result = ''
        for index in indexes:
            response = get('%s/%s' % (url,index), verify=False, timeout=6)
            if response.status_code == 200:
                index_result += '%s, ' % index
        return {'index_files':index_result[:-2]}
    except Exception as e:
        return {'error1': 'Passive Analysis Error:(%s) ' % url +'Is the information correct?'}


def check_robots(url):
    try:
        response = get('%s/%s' % (url,'robots.txt'), verify=False, timeout=6)
        robots_file = 'Has a robots.txt file' if response.status_code == 200 else 'Does not have a robots.txt'
        return {'robots_file':robots_file}
    except Exception as e:
        return {'error1':  'Passive Analysis Error:(%s) ' % url +'Is the information correct?'}


def check_install(url):
    try:
        directories = ['setup','install']
        dirs_result = ''
        for d in directories:
            response = get('%s/%s' % (url,d), verify=False, timeout=6)
            if response.status_code in [200,403]:
                dirs_result += '%s, ' % d
        result_dir = {'install_dir':dirs_result[:-2]} if dirs_result != '' else {'install_dir':'No installation directories'}
        return result_dir
    except Exception as e:
        return {'error1': 'Passive Analysis Error:(%s) ' % url +'Is the information correct?'}



def check_headers(url):
    try:
	    response = get(url, verify=False, timeout=6)
	    headers = response.headers
	    signature = headers['Server'] if 'Server' in headers else 'Header is not set'
	    php_version = headers['X-Powered-By'] if 'X-Powered-By' in headers else 'Header is not set'
	    x_xss_protection = headers['X-XSS-Protection'] if 'X-XSS-Protection' in headers else 'Header is not set'
	    x_frame_options = headers['X-Frame-Options'] if 'X-Frame-Options' in headers else 'Header is not set'
	    x_content_type_options = headers['X-Content-Type-Options'] if 'X-Content-Type-Options' in headers else 'Header is not set'
	    hsts = headers['Strict-Transport-Security'] if 'Strict-Transport-Security' in headers else 'Header is not set'
	    #Set-Cookie options
	    if 'Set-Cookie' in headers:
	       cookie_header = headers['Set-Cookie']
	       if 'secure' in cookie_header: setcookie_secure = 'Set-Cookie is used with the \'secure\' option'
	       else: setcookie_secure = 'Set-Cookie is used but \'secure\' is not used'
	       if 'HttpOnly' in cookie_header: setcookie_httponly = 'Set-Cookie is used with the \'HttpOnly\' option'
	       else: setcookie_httponly = 'Set-Cookie is used but \'HttpOnly\' is not used'
	    else:
	        setcookie_secure = 'The \'Set-Cookie\' header is not used'
	        setcookie_httponly = 'The \'Set-Cookie\' header is not used'
	    return {'signature':signature, 
	            'php_version':php_version, 
	            'x_xss_protection': x_xss_protection,
	            'x_frame_options':x_frame_options,
	            'x_content_type_options':x_content_type_options,
	            'hsts':hsts,
	            'setcookie_secure':setcookie_secure,
                    'setcookie_httponly':setcookie_httponly}
    except Exception as e:
        return {'error2': 'HTTP Analysis Error:(%s) ' % url +'Is the information correct?'}



def get_domain(cert):
    domain = ''
    if 'subjectAltName' in cert:
        for value in cert['subjectAltName']:
            if value[0] == 'DNS':
                domain += '%s, ' % value[1]
        return {'cert_domain': domain[:-2]}

def get_ca(cert):
    ca = ''
    if 'issuer' in cert:
#        for value in cert['issuer']:
#            if value[0] == 'commonName':
#                ca += '%s, ' % value[1]
        return {'cert_ca': cert['issuer']}

def check_certificate(ip, port=443):
    try:
        ctx = create_default_context()
        ctx.check_hostname = False
        s = ctx.wrap_socket(socket(), server_hostname=ip)
        s.connect((ip, port))
        cert = s.getpeercert()
     
        result = {}
        result.update(get_domain(cert))
        result.update(get_ca(cert))
        result.update({'ssl_suites':cert})

        return result
        
    except Exception as e:
        return {'cert_domain':e}



def passive_analysis(ip, port, protocol):
    try:
        if ip == '' or port == '':
            return {'passive_ip':'Specify an IP address or domain name and a port.', 'passive_port':port}

        result_dict = {'result':True}
        if protocol == "HTTP":
            url = "http://%s:%s" % (ip, port)
        else:
            url = "https://%s:%s" % (ip, port)

        result_dict.update(check_headers(url))
        result_dict.update(check_methods(url))
        result_dict.update(check_index(url))
        result_dict.update(check_robots(url))
        result_dict.update(check_install(url))
        if protocol == 'HTTPS':
            result_dict.update(check_certificate(ip, int(port)))
        else:
            result_dict.update(check_certificate(ip))


        return result_dict
    except ValueError as e:
        result_dict.update({'error1':e, 'result':True})
        return result_dict
