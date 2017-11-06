# -*- coding: utf-8 -*-
#Castro Rendón Virgilio
from subprocess import check_output, Popen, PIPE, STDOUT

"""
Executes a subprocess with the command "nmap" in order to determine if is vulnerable to heartbleed
"""
def check_heartbleed(site,port):
    try:
        if site == '' or port == '':
            return {'scanner_ip':'Specify an IP address or domain name and a port.', 'scanner_port':port}
        process = Popen(['nmap', '-p', port, '--script','ssl-heartbleed',site], stdout=PIPE, stderr=STDOUT)
        code = process.wait()
        output = process.stdout.read()
        if "VULNERABLE" not in output:
            return {'heartbleed_result':'%s is not vulnerable' % site}  
        return {'heartbleed_result':'%s is vulnerable' % site}
    except ValueError as e:
        result_dict.update({'heartbleed_error':e})
        return result_dict


"""
Executes a subprocess with the command "nmap" in order to determine if is vulnerable to shellshock
"""
def check_shellshock(site,port):
    try:
        if site == '' or port == '':
            return {'scanner_ip':'Specify an IP address or domain name and a port.', 'scanner_port':port}
        process = Popen(['nmap', '-sV', '-p', port, '--script','http-shellshock',site], stdout=PIPE, stderr=STDOUT)
        code = process.wait()
        output = process.stdout.read()
        if "VULNERABLE" not in output:
            return {'shellshock_result':'%s is not vulnerable' % site}  
        return {'shellshock_result':'%s is vulnerable' % site}
    except ValueError as e:
        result_dict.update({'shellshock_error':e})
        return result_dict


"""
Executes a subprocess with the command "nmap" in order to determine if is vulnerable to poodle
"""
def check_poodle(site,port):
    try:
        if site == '' or port == '':
            return {'scanner_ip':'Specify an IP address or domain name and a port.', 'scanner_port':port}
        process = Popen(['nmap', '-sV', '--version-light','-p', port, '--script','ssl-poodle',site], stdout=PIPE, stderr=STDOUT)
        code = process.wait()
        output = process.stdout.read()
        if "VULNERABLE" not in output:
            return {'poodle_result':'%s is not vulnerable' % site}  
        return {'poodle_result':'%s is vulnerable' % site}
    except ValueError as e:
        result_dict.update({'poodle_error':e})
        return result_dict


"""
Executes a subprocess with the command "nmap" in order to determine if is vulnerable to drown
"""
def check_drown(site,port):
    try:
        if site == '' or port == '':
            return {'scanner_ip':'Specify an IP address or domain name and a port.', 'scanner_port':port}
        process = Popen(['nmap','-sV', '-p', port, '--script','sslv2-drown',site], stdout=PIPE, stderr=STDOUT)
        code = process.wait()
        output = process.stdout.read()
        if "VULNERABLE" not in output:
            return {'drown_result':'%s is not vulnerable' % site}  
        return {'drown_result':'%s is vulnerable' % site}
    except ValueError as e:
        result_dict.update({'drown_error':e})
        return result_dict
