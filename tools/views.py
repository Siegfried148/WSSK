# -*- coding: utf-8 -*-
#Castro Rendón Virgilio
from __future__ import unicode_literals
from django.shortcuts import render
from .models import Tool
#from .forms import AddressForm, EncoderForm, HashForm, EncryptionForm, KeygenForm, PublicIPForm, PingForm, WhoisForm, TracerouteForm, LookupForm, ReverseForm
from .forms import *
from .crypto_lib import *
from .network_lib import *
from .passive_lib import *
from .active_lib import *
from .scanner_lib import *
import sqlite3 as lite
from time import gmtime, strftime


"""
Returns the IP address of the client
"""
def get_ip(request):
    try:
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    except Exception as e:
        print e

"""
Opens the database file
"""
con = lite.connect('/opt/wssk/db/wssk.db', check_same_thread=False)


"""
Inserts into the database, the IP that is visiting the web page
"""
def insert_visit_ip(ip):
    with con:
        cur = con.cursor()
        query = """
            INSERT OR IGNORE INTO VISIT_IP(ip) VALUES('%s');""" % ip
        cur.execute(query)



"""
Inserts into the database, the domain/IP/URL that is being analyzed
"""
def insert_consulted_domain(domain):
    with con:
        cur = con.cursor()
        query = """
            INSERT OR IGNORE INTO CONSULTED_DOMAIN(domain) VALUES('%s');""" % domain
        cur.execute(query)


"""
Insert into the database, the whole search
"""
def insert_search(ip, domain, desc_id):
    with con:
        date = strftime("%Y-%m-%d %H:%M:%S", gmtime())
        cur = con.cursor()
        query = """
            INSERT OR IGNORE INTO SEARCH(visit_ip_id, consult_dom_id, description_id, date) 
                SELECT VISIT_IP.id, CONSULTED_DOMAIN.id, %s, '%s'
                    FROM VISIT_IP, CONSULTED_DOMAIN
                    WHERE VISIT_IP.ip = '%s'
                    AND CONSULTED_DOMAIN.domain = '%s';""" % (desc_id, date, ip, domain) 
        cur.execute(query)


"""
Calls the functions that can insert into the db
"""
def insert_into_db(ip,domain,desc_id):
    try:
        insert_visit_ip(ip)
        insert_consulted_domain(domain)
        insert_search(ip,domain,desc_id)
    except Exception as e:
        print e

"""
Renders the main page.
"""
def tool_list(request):
    return render(request, 'tools/tool_list.html')


"""
Receives POST information and depending on the button that was clicked, 
calls the correct function to handle the information.
"""
def crypto(request):
    message = ""
    result_dict = {'hash_text':'', 'ascii':'', 'base64':'', 'url':'', 'hex':'', 
            'md4':'', 'md5':'', 'sha1':'', 'sha224':'', 'sha256':'', 'sha384':'', 'sha512':'', 'ntlm':''}
    if request.method == "POST":
        #A button from the encoder section
        if any(btn in request.POST for btn in ['ascii_btn','base64_btn','url_btn','hex_btn']):
            message = EncoderForm(request.POST)
            if message.is_valid():
                text = message.cleaned_data['text']
                if 'ascii_btn' in request.POST:
                    result_dict = encode_ascii(text)
                elif 'base64_btn' in request.POST:
                    result_dict = encode_base64(text)
                elif 'url_btn' in request.POST:
                    result_dict = encode_url(text)
                elif 'hex_btn' in request.POST:
                    result_dict = encode_hex(text)
        #The button from the hash section
        elif 'hash_btn' in request.POST:
            message = HashForm(request.POST)
            if message.is_valid():
                text = message.cleaned_data['text']
                result_dict = get_hashes(text)
        #A button from the cipher section
        elif any(btn in request.POST for btn in ['caesar_e_btn','caesar_d_btn',
                                                'vigenere_e_btn','vigenere_d_btn',
                                                'monoalphabetic_e_btn','monoalphabetic_d_btn',
                                                'transposition_e_btn','transposition_d_btn']):
            message = EncryptionForm(request.POST)
            if message.is_valid():
                clear_text = message.cleaned_data['clear_text']
                encrypted_text = message.cleaned_data['encrypted_text']
                key = message.cleaned_data['key']
                if 'caesar_e_btn' in request.POST: result_dict = caesar('encrypt', clear_text, key)
                elif 'caesar_d_btn' in request.POST: result_dict = caesar('decrypt', encrypted_text, key)
                elif 'monoalphabetic_e_btn' in request.POST: result_dict = monoalphabetic('encrypt', clear_text, key)
                elif 'monoalphabetic_d_btn' in request.POST: result_dict = monoalphabetic('decrypt', encrypted_text, key)
                elif 'vigenere_e_btn' in request.POST: result_dict = vigenere('encrypt', clear_text, key)
                elif 'vigenere_d_btn' in request.POST: result_dict = vigenere('decrypt', encrypted_text, key)
                elif 'transposition_e_btn' in request.POST: result_dict = transposition('encrypt', clear_text, key)
                elif 'transposition_d_btn' in request.POST: result_dict = transposition('decrypt', encrypted_text, key)
            else:
                result_dict = {'form':message}
        elif 'keygen_btn' in request.POST:
            message = KeygenForm(request.POST)
            if message.is_valid():
                text = message.cleaned_data['keylength']
                result_dict = get_keypair(text)
    return render(request, 'tools/crypto.html', result_dict)


"""
Receives a POST request. Handles the information depending on the user configuration.
After creating an initial dictionary, updates it using the function in the library.
"""
def passive(request):
    result_dict = {}
    if request.method == "POST":
        if 'passive_btn' in request.POST:
            message = PassiveForm(request.POST)
            if message.is_valid():
                url = message.cleaned_data['passive_url']
                ip = get_ip(request)
                insert_into_db(ip,url,2)
                result_dict.update({'passive_url':url})
                result_dict.update(passive_analysis(url))
    return render(request, 'tools/passive.html', result_dict)


"""
Receives a POST request. Handles the information depending on the user configuration.
After creating an initial dictionary, uses the function in the library to update it.
"""
def active(request):
    result_dict = {}
    if request.method == "POST":
        if 'active_btn' in request.POST:
            message = ActiveForm(request.POST)
            if message.is_valid():
                url = message.cleaned_data['active_url']
                ip = get_ip(request)
                insert_into_db(ip,url,1)
                result_dict.update(active_analysis(url))
    return render(request, 'tools/active.html', result_dict)


"""
Handles the information depending on the button that was clicked. It (for now) has only 4 options
"""
def scanner(request):
    result_dict = {}
    if request.method == "POST":
        if any(btn in request.POST for btn in ['heartbleed_btn','shellshock_btn','poodle_btn','drown_btn', 'ghost_btn']):
            message = ScannerForm(request.POST)
            if message.is_valid():
                url = message.cleaned_data['scanner_url']
                ip = get_ip(request)
                result_dict.update({'scanner_url':url})
                if 'heartbleed_btn' in request.POST:  
                    insert_into_db(ip,url,3)
                    result_dict.update(check_heartbleed(url))
                elif 'shellshock_btn' in request.POST:  
                    insert_into_db(ip,url,4)
                    result_dict.update(check_shellshock(url))
                elif 'poodle_btn' in request.POST:  
                    insert_into_db(ip,url,5)
                    result_dict.update(check_poodle(url))
                elif 'drown_btn' in request.POST:  
                    insert_into_db(ip,url,6)
                    result_dict.update(check_drown(url))
                elif 'ghost_btn' in request.POST:  
                    insert_into_db(ip,url,7)
                    result_dict.update(check_ghost(url))
    return render(request, 'tools/scanner.html', result_dict)


"""
Such as the "crypto" module, this function handles many buttons. Depending on that, is the function that is called
to return the data.
"""
def network(request):
    message = ""
    result_dict = {}
    if request.method == "POST":
        #The button from the public ip address section
        if 'pub_ip_btn' in request.POST:
            message = PublicIPForm(request.POST)
            if message.is_valid():
                result_dict = get_ip(request)
        elif 'ping_btn' in request.POST:
            message = PingForm(request.POST)
            if message.is_valid():
                ping_ip = message.cleaned_data['ping_ip']
                result_dict = ping(ping_ip)
        elif 'whois_btn' in request.POST:
            message = WhoisForm(request.POST)
            if message.is_valid():
                whois_ip = message.cleaned_data['whois_ip']
                result_dict = whois(whois_ip)
        elif 'traceroute_btn' in request.POST:
            message = TracerouteForm(request.POST)
            if message.is_valid():
                traceroute_ip = message.cleaned_data['traceroute_ip']
                result_dict = traceroute(traceroute_ip)
        elif 'lookup_btn' in request.POST:
            message = LookupForm(request.POST)
            if message.is_valid():
                lookup_name = message.cleaned_data['lookup_name']
                result_dict = lookup(lookup_name)
        elif 'reverse_btn' in request.POST:
            message = ReverseForm(request.POST)
            if message.is_valid():
                reverse_ip = message.cleaned_data['reverse_ip']
                result_dict = reverse(reverse_ip)
    return render(request, 'tools/network.html', result_dict)
