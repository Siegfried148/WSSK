# -*- coding: utf-8 -*-
#Castro Rendón Virgilio
from subprocess import check_output, Popen, PIPE, STDOUT
import urllib2
from requests import get
debug = True

def get_url(url, secure = True):
    if url.startswith('http://') or (url.startswith('https://') and secure):
        url = url.split('//')[1]
    elif url.startswith('https://') and not secure:
        secure = True
        url = url.split('//')[1]


    if url.endswith('/'): url = url[:-1]
    if secure: url = 'https://'+url
    else: url = 'http://'+url
    
    site = url.split('//')[1]
    if '/' in site: site = site.split('/')[0]

    if ':' in site:
        port = site.split(':')[1]
    elif secure:
        port = '443'
    else:
        port = '80'

    return url, site, port

def has_xmlrpc(url):
    try:
        if debug: print '\n'+url+'/xmlrpc.php'
        has_xmlrpc = get(url+'/xmlrpc.php', allow_redirects=False, timeout=4, verify=False)
        if debug: print 'Response code: %s' % has_xmlrpc.status_code
    except Exception as e:
        print e
        return False
    if has_xmlrpc.status_code in [200,405] and has_xmlrpc.history == []:
        return True
    return False

def check_ghost(site):
    result_dict = {}
    if debug: print '\n\n\n'+'*'*30+'GHOST VULNERABILITY'+'*'*30
    try:
        if site == '':
            return {'scanner_url':'Specify an IP address or domain name.'}
        url, site, port = get_url(site, secure=False)
        if has_xmlrpc(url):
            if debug: print 'It has a xmlrpc file'
            pingback_url = url+'/xmlrpc.php'
            src_url = 'http://%s/' % ('0' * 0x1004)
            dst_url = url+'/xmlrpc.php?p=1'
            
            data = """<?xml version="1.0"?>
            <methodCall>
               <methodName>pingback.ping</methodName>
               <params>
                  <param>
                     <value><string>%s</string></value>
                  </param>
                  <param>
                     <value><string>%s</string></value>
                    </param>
                </params>
            </methodCall>
            """ % (src_url, dst_url)
            
            if debug: print '\nSending data to xmlrpc'
            u = urllib2.urlopen(pingback_url, data)
            print u.getcode()
            if u.getcode() == 500:
                result_dict.update({'ghost_result':'%s is vulnerable' % url})
            else:
                result_dict.update({'ghost_result':'%s is not vulnerable' % url})
        else:
            if debug: print 'It does not have a xmlrpc file'
            result_dict.update({'ghost_result':'%s is not vulnerable' % url})
        return result_dict
    except Exception as e:
        print e
        result_dict.update({'ghost_result':'%s is vulnerable' % url})
        return result_dict

"""
Executes a subprocess with the command "nmap" in order to determine if is vulnerable to heartbleed
"""
def check_heartbleed(site):
    result_dict = {}
    if debug: print '\n\n\n'+'*'*30+'HEARTBLEED VULNERABILITY'+'*'*30
    try:
        if site == '':
            return {'scanner_url':'Specify an IP address or domain name.'}
        url, site, port = get_url(site)
        process = Popen(['nmap', '-p', port, '--script','ssl-heartbleed',site], stdout=PIPE, stderr=STDOUT)
        code = process.wait()
        output = process.stdout.read()
        if "VULNERABLE" not in output:
            result_dict.update({'heartbleed_result':'%s is not vulnerable' % site})
        else:
            result_dict({'heartbleed_result':'%s is vulnerable' % site})
        return result_dict
    except ValueError as e:
        print e
        result_dict.update({'heartbleed_error':e})
        return result_dict


"""
Executes a subprocess with the command "nmap" in order to determine if is vulnerable to shellshock
"""
def check_shellshock(site):
    result_dict = {}
    if debug: print '\n\n\n'+'*'*30+'SHELLSHOCK VULNERABILITY'+'*'*30
    try:
        if site == '':
            return {'scanner_url':'Specify an IP address or domain name.'}
        url, site, port = get_url(site, secure=False)
        process = Popen(['nmap', '-sV', '-p', port, '--script','http-shellshock',site], stdout=PIPE, stderr=STDOUT)
        code = process.wait()
        output = process.stdout.read()
        if "VULNERABLE" not in output:
            result_dict.update( {'shellshock_result':'%s is not vulnerable' % site})
        else:
            result_dict.update({'shellshock_result':'%s is vulnerable' % site})
        return result_dict
    except ValueError as e:
        print e
        result_dict.update({'shellshock_error':e})
        return result_dict


"""
Executes a subprocess with the command "nmap" in order to determine if is vulnerable to poodle
"""
def check_poodle(site):
    result_dict = {}
    if debug: print '\n\n\n'+'*'*30+'POODLE VULNERABILITY'+'*'*30
    try:
        if site == '':
            return {'scanner_ip':'Specify an IP address or domain name.'}
        url, site, port = get_url(site)
        process = Popen(['nmap', '-sV', '--version-light','-p', port, '--script','ssl-poodle',site], stdout=PIPE, stderr=STDOUT)
        code = process.wait()
        output = process.stdout.read()
        if "VULNERABLE" not in output:
            result_dict.update({'poodle_result':'%s is not vulnerable' % site})
        else:
            result_dict.update({'poodle_result':'%s is vulnerable' % site})
        return result_dict
    except ValueError as e:
        print e
        result_dict.update({'poodle_error':e})
        return result_dict


"""
Executes a subprocess with the command "nmap" in order to determine if is vulnerable to drown
"""
def check_drown(site):
    if debug: print '\n\n\n'+'*'*30+'DROWN VULNERABILITY'+'*'*30
    result_dict = {}
    try:
        if site == '':
            return {'scanner_ip':'Specify an IP address or domain name.'}
        url, site, port = get_url(site)
        process = Popen(['nmap','-sV', '-p', port, '--script','sslv2-drown',site], stdout=PIPE, stderr=STDOUT)
        code = process.wait()
        output = process.stdout.read()
        if "VULNERABLE" not in output:
            result_dict.update({'drown_result':'%s is not vulnerable' % site})
        else:
            result_dict.update({'drown_result':'%s is vulnerable' % site})
        return result_dict
    except ValueError as e:
        print e
        result_dict.update({'drown_error':e})
        return result_dict
