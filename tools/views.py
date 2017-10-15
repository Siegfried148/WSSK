# -*- coding: utf-8 -*-
#Castro Rendón Virgilio

from __future__ import unicode_literals
from django.shortcuts import render
from .models import Tool
from .forms import AddressForm, EncoderForm, HashForm, EncryptionForm
from base64 import b64encode, b64decode
from urllib import quote_plus, unquote_plus
from hashlib import new, md5, sha1, sha224, sha256, sha384, sha512
from binascii import hexlify
from string import ascii_uppercase


#This function renders the main page
def tool_list(request):
    tools = Tool.objects.all().order_by('title')
    return render(request, 'tools/tool_list.html', {'tools':tools})


#Encodes an ascii-written text into the other formats
def encode_ascii(text):
    try:
        b64_text = b64encode(text.encode())
        url_text = quote_plus(text)
        hex_text = text.encode('hex')
        return {'ascii':text, 'base64':b64_text, 'url':url_text, 'hex':hex_text}
    except:
        return {'ascii':'The text has an error.', 'base64':'', 'url':'', 'hex':''}
    
def encode_base64(text):
    try:
        ascii_text = b64decode(text.encode())
        url_text = quote_plus(ascii_text)
        hex_text = ascii_text.encode('hex')
        return {'ascii':ascii_text, 'base64':text, 'url':url_text, 'hex':hex_text}
    except:
        return {'ascii':'', 'base64':'The text has an error.', 'url':'', 'hex':''}


    
def encode_url(text):
    try:
        ascii_text = unquote_plus(text)
        b64_text = b64encode(ascii_text.encode())
        hex_text = ascii_text.encode('hex')
        return {'ascii':ascii_text, 'base64':b64_text, 'url':text, 'hex':hex_text}
    except:
        return {'ascii':'', 'base64':'', 'url':'The text has an error.', 'hex':''}
    

    
def encode_hex(text):
    try:
        ascii_text = text.decode('hex')
        b64_text = b64encode(ascii_text.encode())
        url_text = quote_plus(ascii_text)
        return {'ascii':ascii_text, 'base64':b64_text, 'url':url_text, 'hex':text}
    except:
        return {'ascii':'', 'base64':'', 'url':'', 'hex':'The text has an error.'}


def get_hashes(text):
    md4_hash = new('md4', text.encode('utf-16le')).hexdigest()
    md5_hash = md5(text).hexdigest()
    ntlm = hexlify(md4_hash)
    sha1_hash = sha1(text).hexdigest()
    sha224_hash = sha224(text).hexdigest()
    sha256_hash = sha256(text).hexdigest()
    sha384_hash = sha384(text).hexdigest()
    sha512_hash = sha512(text).hexdigest()
    return {'hash_text':text, 'md4':md4_hash, 'md5':md5_hash, 'sha1':sha1_hash, 'sha224':sha224_hash, 
            'sha256':sha256_hash, 'sha384':sha384_hash, 'sha512':sha512_hash, 'ntlm':ntlm}

def caesar(mode, text, key):
    try:
        key_int = int(key)%26
        message = list(text.upper())
        key_int = key_int if mode == "encrypt" else (26-key_int)
        for i in range(len(message)):
            if message[i] not in ascii_uppercase:
                continue
            if ord(message[i])+key_int <= 90:
                message[i] = chr(ord(message[i])+key_int) 
            else:
                message[i] = chr(ord(message[i])-(26-key_int))
        new_text = ''.join(message)
        if mode == 'encrypt':
            return {'clear_caesar':text, 'encrypted_caesar':new_text, 'key_caesar':key}
        else:
            return {'clear_caesar':new_text, 'encrypted_caesar':text, 'key_caesar':key}
    except:
        if mode == 'encrypt':
            return {'clear_caesar':text, 'encrypted_caesar':'An error ocurred'}
        else:
            return {'clear_caesar':'An error ocurred', 'encrypted_caesar':text}



def monoalphabetic(mode, text, key):
    try:
        cipher = {}
        inverse_cipher = {}
        text = text.upper()
        new_text = []
        #Checks if the key has the correct format
        key = list(key.upper().replace(' ','').replace('-',''))
        if len(key) != 26 or len(key) > len(set(key)):
            raise ValueError('The key does not have the specified format')
        for l in key:
            if l not in ascii_uppercase:
                raise ValueError('The key does not have the specified format')

        #Generates the dictionaries to work
        for i in range(26):
            cipher[key[i]] = ascii_uppercase[i]
        for k, v in cipher.iteritems():
            inverse_cipher[v] = k
        #Encrypts
        for letter in text:
            if letter not in ascii_uppercase:
                new_text.append(letter)
            else:
                if mode == 'encrypt':
                    new_text.append(cipher[letter])
                else:
                    new_text.append(inverse_cipher[letter])
        #Returns result
        if mode == 'encrypt':
            return {'clear_monoalphabetic':text,'encrypted_monoalphabetic':''.join(new_text), 'key_monoalphabetic':''.join(key)}
        else:
            return {'clear_monoalphabetic':''.join(new_text),'encrypted_monoalphabetic':text, 'key_monoalphabetic':''.join(key)}
    
    except:
        if mode == 'encrypt':
            return {'clear_monoalphabetic':text,'encrypted_monoalphabetic':'The key has an error','key_monoalphabetic':''.join(key)}
        else:
            return {'clear_monoalphabetic':'They key has an error','encrypted_monoalphabetic':text,'key_monoalphabetic':''.join(key)}



def vigenere(mode, text, key):
    try:
        new_text = []
        keyIndex = 0
        key = key.upper()
        text = text.upper()
        for letter in text:
            num = ascii_uppercase.find(letter.upper())
            if num != -1:
                if mode == 'encrypt':
                    num += ascii_uppercase.find(key[keyIndex])
                else:
                    num -= ascii_uppercase.find(key[keyIndex])
                num %= len(ascii_uppercase)
                new_text.append(ascii_uppercase[num])
                keyIndex += 1
                if keyIndex == len(key):
                    keyIndex = 0
            else:
                new_text.append(letter) 
        if mode == 'encrypt':
            return {'clear_vigenere':text,'encrypted_vigenere':''.join(new_text), 'key_vigenere':key}
        else:
            return {'clear_vigenere':''.join(new_text),'encrypted_vigenere':text, 'key_vigenere':key}
    
    except:
        if mode == 'encrypt':
            return {'clear_vigenere':text,'encrypted_vigenere':'An error has ocurred','key_monoalphabetic':key}
        else:
            return {'clear_vigenere':'An error has ocurred','encrypted_vigenere':text,'key_vigenere':key}



def crypto(request):
    message = ""
    result_dict = {'hash_text':'', 'ascii':'', 'base64':'', 'url':'', 'hex':'', 
            'md4':'', 'md5':'', 'sha1':'', 'sha224':'', 'sha256':'', 'sha384':'', 'sha512':'', 'ntlm':''}

    if request.method == "POST":
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
        elif 'hash_btn' in request.POST:
            message = HashForm(request.POST)
            if message.is_valid():
                text = message.cleaned_data['text']
                result_dict = get_hashes(text)
        elif any(btn in request.POST for btn in ['caesar_e_btn','caesar_d_btn',
                                                'vigenere_e_btn','vigenere_d_btn',
                                                'monoalphabetic_e_btn','monoalphabetic_d_btn']):
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
            else:
                result_dict = {'form':message}


    return render(request, 'tools/crypto.html', result_dict)


def passive(request):
    ip_address = "Valid IP address or domain name"
    port = "80"

    if request.method == "POST":
        address = AddressForm(request.POST)
        if address.is_valid():
            ip_address = address.cleaned_data('ip_address')
            port = address.cleaned_data('port')
    else:
        address = AddressForm()

    return render(request, 'tools/passive.html', {'ip_address':ip_address, 'port':port})



def active(request):
    ip_address = "Valid IP address or domain name"
    port = "80"

    if request.method == "POST":
        address = AddressForm(request.POST)
        if address.is_valid():
            ip_address = address.cleaned_data('ip_address')
            port = address.cleaned_data('port')
    else:
        address = AddressForm()

    return render(request, 'tools/active.html', {'ip_address':ip_address, 'port':port})


def scanner(request):
    return render(request, 'tools/scanner.html', {})


def network(request):
    return render(request, 'tools/network.html', {})
