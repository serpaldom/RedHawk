from django.forms import ModelForm
from .models import target
from django import forms


# Form to set up a new target
class TargetForm(ModelForm):
    class Meta:
        model = target
        fields = ['Url', 'Domain', 'IPs']
        widgets = {
            'Url': forms.TextInput(attrs={'placeholder': 'URL [http(s)://localhost:(port)]'}),
            'Domain': forms.TextInput(
                attrs={'placeholder': 'Domain [localhost]'}),
            'IPs': forms.TextInput(
                    attrs={'placeholder': 'IP Address [127.0.0.1]'}),
        }
