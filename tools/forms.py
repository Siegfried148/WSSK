#-*- coding: utf-8 -*-
from django import forms

class AddressForm(forms.Form):
    ip_address = forms.CharField(max_length = 100)
    port = forms.CharField(max_length = 5)


class EncoderForm(forms.Form):
    text = forms.CharField(widget=forms.Textarea)

class HashForm(forms.Form):
    text = forms.CharField(widget=forms.Textarea)

class EncryptionForm(forms.Form):
    clear_text = forms.CharField(widget=forms.Textarea, required=False)    
    encrypted_text = forms.CharField(widget=forms.Textarea, required=False)
    key = forms.CharField(max_length = 80, required=False)

class KeygenForm(forms.Form):
    options = (('1024','1024'),('2048','2048'))
    keylength = forms.ChoiceField(choices = options)

class PublicIPForm(forms.Form):
    pub_ip = forms.CharField(max_length = 15, required=False)

class PingForm(forms.Form):
    ping_ip = forms.CharField(max_length = 150, required=False)
    ping_out = forms.CharField(widget=forms.Textarea, required=False)    

class WhoisForm(forms.Form):
    whois_ip = forms.CharField(max_length = 150, required=False)
    whois_out = forms.CharField(widget=forms.Textarea, required=False)    

class TracerouteForm(forms.Form):
    traceroute_ip = forms.CharField(max_length = 150, required=False)
    traceroute_out = forms.CharField(widget=forms.Textarea, required=False)    

class LookupForm(forms.Form):
    lookup_name = forms.CharField(max_length = 150, required=False)
    lookup_ip = forms.CharField(max_length = 15, required=False)

class ReverseForm(forms.Form):
    reverse_ip = forms.CharField(max_length = 15, required=False)
    reverse_name = forms.CharField(max_length = 150, required=False)

class PassiveForm(forms.Form):
    options = (('HTTP','HTTP'),('HTTPS','HTTPS'))
    passive_ip = forms.CharField(max_length = 150, required=False)
    passive_port = forms.CharField(max_length = 5, required=False)
    protocol = forms.ChoiceField(choices = options, required=False)

class ActiveForm(forms.Form):
    options = (('HTTP','HTTP'),('HTTPS','HTTPS'))
    active_ip = forms.CharField(max_length = 150, required=False)
    active_port = forms.CharField(max_length = 5, required=False)
    protocol = forms.ChoiceField(choices = options, required=False)
