# -*- coding: utf-8 -*-
#Castro Rendón Virgilio
from subprocess import check_output, Popen, PIPE, STDOUT
from socket import gethostbyname, gethostbyaddr


"""
Uses HTTP requests to determine the original IP address.
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


"""
Execcutes a subprocces with the command "ping" in order to map into the page, the output.
"""
def ping(ip):
    try:
        if ip == '':
            output = 'Specify an IP address or domain name.'
        else:
            process = Popen(['ping', ip, '-c', '5','-i','.4'], stdout=PIPE, stderr=STDOUT)
            code = process.wait()
            output = process.stdout.read()
        if "Name or service not known" not in output:
            return {'ping_ip':ip, 'ping_out':output}  
        else:
            return {'ping_ip':ip, 'ping_out':'Could not resolve name: \'%s\' ' % ip}  
    except Exception as e:
        return {'ping_ip':ip, 'ping_out':'An error ocurred.'}

   
"""
Execcutes a subprocces with the command "whois" in order to map into the page, the output.
"""
def whois(site):
    try:
        if site == '':
            output = 'Specify an IP address or domain name.'
        else:
            process = Popen(['whois', site, '-H'], stdout=PIPE, stderr=STDOUT)
            code = process.wait()
            output = process.stdout.read()
        if "Invalid_String" not in output:
            return {'whois_ip':site, 'whois_out':output}
        else:
            return {'whois_ip':site, 'whois_out':'Invalid whois query.'}
    except Exception as e:
        return {'whois_ip':site, 'whois_out':'An error ocurred.'}


"""
Execcutes a subprocces with the command "traceroute" in order to map into the page, the output.
"""
def traceroute(site):
    try:
        if site == '':
            output = 'Specify an IP address or domain name.'
        else:
            process = Popen(['traceroute', site], stdout=PIPE, stderr=STDOUT)
            code = process.wait()
            output = process.stdout.read()
        if "Name or service not known" not in output:
            return {'traceroute_ip':site, 'traceroute_out':output}  
        else:
            return {'traceroute_ip':site, 'traceroute_out':'Could not resolve name: \'%s\' ' % site}  
    except Exception as e:
        return {'traceroute_ip':site, 'traceroute_out':'An error ocurred.'}


"""
Uses the function "gethostbyname" to automatically determine the IP address of the host
"""
def lookup(name):
    try:
        ip = gethostbyname(name)
        return {'lookup_name':name,'lookup_ip':ip}
    except:
        return {'lookup_name':name,'lookup_ip':'An error ocurred.'}


"""
Returns the names registered for an IP address.
"""
def reverse(ip):
    try:
        name = gethostbyaddr(ip)[0]
        return {'reverse_ip':ip,'reverse_name':name}
    except:
        return {'reverse_ip':ip,'reverse_name':'No PTR record for %s' % ip}

