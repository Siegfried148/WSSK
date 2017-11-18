# -*- coding: utf-8 -*-
#Castro Rendón Virgilio
from requests import get, options, Session
from ssl import create_default_context, PROTOCOL_SSLv23, PROTOCOL_TLSv1, PROTOCOL_TLSv1_1, PROTOCOL_TLSv1_2, _create_unverified_context
from socket import socket
from M2Crypto import X509
from binascii import hexlify
from .httpAdapters import *

"""
Sends an HTTP request using the OPTIONS method
This is useful to determine which other HTTP methods it supports 
"""
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


"""
This functions sends an HTTP request using the GET method
It asks for each possible "index" file. If answer's code is 200,
it supposes that it has the file
"""
def check_index(url):
    try:
        code =[]
        indexes = ['index.html','index.htm','index.php','index.asp', 'index.phtml', 'index.cgi', 'index.xhtml']
        index_result = ''
        for index in indexes:
            has_index = True
            response = get('%s/%s' % (url,index), verify=False, timeout=6)
            if response.status_code == 200:
                for hist_response in response.history:
                    if hist_response.status_code == 302:
                        has_index = False
            else:
                 has_index = False
            if has_index:
                index_result += '%s, ' % index
        if index_result == '':
            index_result = 'Could not find an index file  '
        return {'index_files':index_result[:-2]}
    except Exception as e:
        return {'error1': 'Passive Analysis Error:(%s) ' % url +'Is the information correct?'}


"""
Sends an HTTP request looking for a ROBOTS file, if code is 200,
it supposes that the file exists
"""
def check_robots(url):
    try:
        has_robots = True
        response = get('%s/%s' % (url,'robots.txt'), verify=False, timeout=6)
        if response.status_code == 200:
            for hist_response in response.history:
                if hist_response.status_code == 302:
                    has_robots = False
        else:
            has_robots = False 
        robots_file = ('File: %s/robots.txt' % url) if has_robots else 'Does not have a robots.txt'
        return {'robots_file':robots_file}
    except Exception as e:
        return {'error1':  'Passive Analysis Error:(%s) ' % url +'Is the information correct?'}


"""
It looks for installation directories, if the answer's code is 200 (correct) or 403 (forbbiden),
the directory exists.
"""
def check_install(url):
    try:
        has_install = True
        directories = ['setup','install']
        dirs_result = ''
        for d in directories:
            response = get('%s/%s' % (url,d), verify=False, timeout=6)
            if response.status_code in [200,403]:
                for hist_response in response.history:
                    if hist_response.status_code == 302:
                        has_install = False
            else:
                has_install = False 
            if has_install:
                dirs_result += '%s, ' % d
        result_dir = {'install_dir':dirs_result[:-2]} if dirs_result != '' else {'install_dir':'No installation directories'}
        return result_dir
    except Exception as e:
        return {'error1': 'Passive Analysis Error:(%s) ' % url +'Is the information correct?'}


"""
This function looks for the HTTP headers. Sends an HTTP request using GET option.
Checks the answer looking for the headers.
"""
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
	    cms = headers['X-Generator'] if 'x-Generator' in headers else 'Header is not set'
	    cms_version = headers['X-Cms-Version'] if 'X-Cms-Version' in headers else 'Header is not set'
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
                    'setcookie_httponly':setcookie_httponly,
                    'cms':cms,
                    'cms_version':cms_version}
    except Exception as e:
        return {'error2': 'HTTP Analysis Error:(%s) ' % url +'Is the information correct?'}


"""
Receives an already crafted certificate.
Looks for the domain name of the SUBJECT
"""
def get_domain(cert):
    domain = ''
    if 'subjectAltName' in cert:
        for value in cert['subjectAltName']:
            if value[0] == 'DNS':
                domain += '%s, ' % value[1]
        return {'cert_domain': domain[:-2]}


"""
Receibes an already crafted certificate.
Looks for the domain name of the ISSUER
"""
def get_ca(cert):
    ca = ''
    if 'issuer' in cert:
        issuer = dict(x[0] for x in cert['issuer'])
        issued_by = issuer['commonName']
        return {'cert_ca': issued_by}


"""
Receives an already crafted certificate.
Looks for the "not before" and "not after" fields
"""
def get_validity(cert):
    validity = '%s -- %s' % (cert['notBefore'],cert['notAfter'])
    return {'cert_validity':validity}


"""
This function receives a socket. It can look for the cipher
"""
def get_algorithm(ssl_socket):
    cipher = ssl_socket.cipher()
    cipher_name = cipher[0]
    ssl_version = cipher[1]
    length = cipher[2]
    result = '%s (%s - %s)' % (cipher_name, ssl_version, length)
    return {'cert_algorithm':result}


"""
Gets a certificate in binary format.
It gets as public key of the certificate converting from binary 
to an "hex" string
"""
def get_key(raw_cert):
    try:
        m2cert = X509.load_cert_string(raw_cert, X509.FORMAT_DER)
        pub_key = m2cert.get_pubkey().as_der()
        hex_pub = str(hexlify(pub_key)).upper()
        pub_array = [hex_pub[i:i+28] for i in range(0, len(hex_pub), 28)]
        for i in range(len(pub_array)):
            pub_array[i] = ' '.join(pub_array[i][j:j+2] for j in range(0,len(pub_array[i]),2))        
        return {'ca_key':pub_array}
    except Exception as e:
        return {'ca_key':'Could not get the public key. Maybe the certificate uses ECC and not RSA.'}


"""
This function calls all the other functions that get info from the certificate.
It updates the resulting dictionary with each function
"""
def check_certificate(url):
    result = {}
    try:
        ctx = create_default_context()
#        ctx = _create_unverified_context()
        site = url.split('//')[1]
        if '/' in site:
            site = site.split('/')[0]
        if ':' in site:
            site = site.split(':')[0]
            port = int(site.split(':')[1])
        else:
            port = 443
	ctx.check_hostname = False
	ssl_socket = ctx.wrap_socket(socket(), server_hostname=site)
	ssl_socket.connect((site, port))
	cert = ssl_socket.getpeercert()
	raw_cert = ssl_socket.getpeercert(1)
	result.update(get_domain(cert))
	result.update(get_ca(cert))
	result.update(get_validity(cert))
	result.update(get_algorithm(ssl_socket))
	result.update(get_key(raw_cert))
	result.update({'ssl_suites':cert})
        ssl_socket.close()
        return result
        
    except Exception as e:
        result.update({'error3':e})
        return result


"""
Uses crafted Http Adapters to start new sessions forcing to use
each SSL protocols. If an exception is raised, the server does not support
the format
"""
def check_ssl_protocols(url):
    result = {'ssl_protocols':[]}
    protocols = []
    try:
        try:
            s1 = Session()
            s1.mount(url, Tls1HttpAdapter())
            s1.get(url, verify=False)
            protocols.append('TLS v. 1 : YES')
        except:
            protocols.append('TLS v. 1 : NO')
        try:
            s2 = Session()
            s2.mount(url, Tls1_1HttpAdapter())
            s2.get(url, verify=False)
            protocols.append('TLS v. 1.1 : YES')
        except:
            protocols.append('TLS v. 1.1 : NO')
        try:
            s3 = Session()
            s3.mount(url, Tls1_2HttpAdapter())
            s3.get(url, verify=False)
            protocols.append('TLS v. 1.2 : YES')
        except:
            protocols.append('TLS v. 1.2 : NO')
            
        result = {'ssl_protocols':protocols}
        return result
    except Exception as e:
        result.update({'error3':e})
        return result

"""
Calls the other functions tog get info from the server
"""
def passive_analysis(url):
    try:
        if url == '':
            return {'passive_url':'Specify an URL to analyze.'}

        result_dict = {'result':True}
        result_dict.update(check_headers(url))
        result_dict.update(check_methods(url))
        result_dict.update(check_index(url))
        result_dict.update(check_robots(url))
        result_dict.update(check_install(url))
        result_dict.update(check_certificate(url))
        result_dict.update(check_ssl_protocols(url))

        return result_dict
    except ValueError as e:
        result_dict.update({'error1':e, 'result':True})
        return result_dict
