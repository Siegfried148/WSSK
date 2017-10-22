# -*- coding: utf-8 -*-
from subprocess import check_output, Popen, PIPE, STDOUT
"""
Uses HTTP requests to determine the original IP address
"""
def get_ip(request):
    try:
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return {'pub_ip':ip}
    except:
        return {'pub_ip':'An error occurred.'}


def ping(ip):
    try:
        process = Popen(['ping', ip, '-c', '5','-i','.4'], stdout=PIPE, stderr=STDOUT)
        code = process.wait()
        return {'ping_ip':ip, 'ping_out':process.stdout.read()}
    except Exception as e:
        return {'ping_ip':ip, 'ping_out':'An error ocurred.'}

        
def whois(site):
    try:
        process = Popen(['whois', site, '-H'], stdout=PIPE, stderr=STDOUT)
        code = process.wait()
        output = process.stdout.read()
        if "Invalid_String" not in output:
            return {'whois_ip':site, 'whois_out':output}
        else:
            return {'whois_ip':site, 'whois_out':'Invalid whois query.'}
    except Exception as e:
        return {'whois_ip':site, 'whois_out':'An error ocurred.'}


def traceroute(site):
    try:
        process = Popen(['traceroute', site], stdout=PIPE, stderr=STDOUT)
        code = process.wait()
        output = process.stdout.read()
        if "Name or service not known" not in output:
            return {'traceroute_ip':site, 'traceroute_out':output}  
        else:
            return {'traceroute_ip':site, 'traceroute_out':'Could not resolve name ' + site}  
    except Exception as e:
        return {'traceroute_ip':site, 'traceroute_out':'An error ocurred.'}
