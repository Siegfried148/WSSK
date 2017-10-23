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


"""
Renders the main page.
"""
def tool_list(request):
    tools = Tool.objects.all().order_by('title')
    return render(request, 'tools/tool_list.html', {'tools':tools})


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


def passive(request):
    result_dict = {'passive_port':'80'}
    if request.method == "POST":
        if 'passive_btn' in request.POST:
            message = PassiveForm(request.POST)
            if message.is_valid():
                ip = message.cleaned_data['passive_ip']
                port = message.cleaned_data['passive_port']
                protocol = message.cleaned_data['protocol']
                result_dict = passive_analysis(ip, port, protocol)
    return render(request, 'tools/passive.html', result_dict)



def active(request):
    ip_address = "Valid IP address or domain name"
    port = "80"
    message = ""
    result_dict = {}
    if request.method == "POST":
        #The button from the public ip address section
        if 'pub_ip_btn' in request.POST:
            message = PublicIPForm(request.POST)
            if message.is_valid():
                result_dict = get_ip(request)

    return render(request, 'tools/active.html', {'ip_address':ip_address, 'port':port})


def scanner(request):
    return render(request, 'tools/scanner.html', {})


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
