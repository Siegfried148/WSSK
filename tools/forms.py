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
