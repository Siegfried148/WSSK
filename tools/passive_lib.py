# -*- coding: utf-8 -*-
#Castro Rendón Virgilio
from requests import get, options
from ssl import create_default_context, DER_cert_to_PEM_cert
from socket import socket
from M2Crypto import X509
import Crypto.PublicKey.RSA
from struct import unpack
from binascii import hexlify

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
        issuer = dict(x[0] for x in cert['issuer'])
        issued_by = issuer['commonName']
        return {'cert_ca': issued_by}

def get_validity(cert):
    validity = '%s -- %s' % (cert['notBefore'],cert['notAfter'])
    return {'cert_validity':validity}

def get_algorithm(ssl_socket):
    cipher = ssl_socket.cipher()
    cipher_name = cipher[0]
    ssl_version = cipher[1]
    length = cipher[2]
    result = '%s (%s - %s)' % (cipher_name, ssl_version, length)
    return {'cert_algorithm':result}


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
        return {'error3':e}


def check_certificate(ip, port=443):
    result = {}
    try:
         ctx = create_default_context()
	 ctx.check_hostname = False
	 ssl_socket = ctx.wrap_socket(socket(), server_hostname=ip)
	 ssl_socket.connect((ip, port))
	 cert = ssl_socket.getpeercert()
	 raw_cert = ssl_socket.getpeercert(1)
	 result = {}
	 result.update(get_domain(cert))
	 result.update(get_ca(cert))
	 result.update(get_validity(cert))
	 result.update(get_algorithm(ssl_socket))
	 result.update(get_key(raw_cert))
	 result.update({'ssl_suites':cert})
         return result
        
    except Exception as e:
        result.update({'error3':e})
        return result



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
