from django import forms
from django.contrib.auth.forms import AuthenticationForm
from django.forms.widgets import PasswordInput, TextInput


class CustomAuthForm(AuthenticationForm):
    username = forms.CharField(widget=TextInput(attrs={'id': 'inputEmail', 'class':'form-control',
     'placeholder': 'Username' ,'required' : 'True', 'autofocus':'True'}))
    password = forms.CharField(widget=PasswordInput(attrs={'placeholder':'Password'}))