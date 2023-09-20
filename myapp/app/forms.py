from django import forms
from django.contrib.auth.forms import AuthenticationForm


class SignInForm(AuthenticationForm):
    remember_me = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={"class": "form-check-input"}),
    )
    recaptcha = forms.CharField(
        required=True,
        widget=forms.HiddenInput(attrs={"class": "g-recaptcha"}),
    )