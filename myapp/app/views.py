from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login
import re
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.conf import settings
import requests


def handling_404(request, exception):
   hide_navbar = True
   return render(request, 'pages/404.html', {'hide_navbar': hide_navbar})

def index(request):
    return render(request, 'index.html')

def sign_in(request):
    error_messages = {}  # Custom dictionary to store error messages for each field

    if request.method == 'POST':
        # Get the form data submitted by the user
        username = request.POST.get('username')
        password = request.POST.get('password')

        if not username:
            error_messages['username'] = 'Username is required.'

        if not password:
            error_messages['password'] = 'Password is required.'

        # Perform authentication here
        user = authenticate(username=username, password=password)

        if user is not None:
            # Authentication successful, log the user in
            login(request, user)
            return redirect('index')
        else:
            # Authentication failed
            error_messages['auth'] = 'Invalid username or password.'

        # Validate reCAPTCHA
        recaptcha_response = request.POST.get('g-recaptcha-response')
        if not recaptcha_response:
            error_messages['recaptcha'] = 'Please complete the reCAPTCHA.'
        else:
            data = {
                'secret': settings.RECAPTCHA_PRIVATE_KEY,
                'response': recaptcha_response,
            }
            response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data)
            result = response.json()
            if not result['success']:
                error_messages['recaptcha'] = 'reCAPTCHA verification failed. Please try again.'

    return render(request, 'pages/sign-in.html', {'hide_navbar': True, 'error_messages': error_messages})

def sign_up(request):
    error_messages = {}  # Custom dictionary to store error messages for each field
    username_regex = r'^\S{6,}$'
    password_regex = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[@#$%^&-+=()])(?=.{8,})'

    if request.method == 'POST':
        # Get the form data submitted by the user
        first_name = request.POST.get('firstname')
        last_name = request.POST.get('lastname')
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirmPassword')

        if not first_name:
            error_messages['firstname'] = 'First name is required.'

        if not last_name:
            error_messages['lastname'] = 'Last name is required.'

        if not email:
            error_messages['email'] = 'Email is required.'
        else:
            try:
                validate_email(email)
            except ValidationError:
                error_messages['email'] = 'Please enter a valid email address.'

        if not password:
            error_messages['password'] = 'Password is required.'

        elif password != confirm_password:
            error_messages['confirmPassword'] = 'Your password confirmation does not match the entered password. Please enter again.'
        else:
            if not re.match(password_regex, password):
                error_messages['password'] = 'Password must be 8 characters including uppercase, lowercase, number, and symbol.'

        if not re.match(username_regex, username):
            error_messages['username'] = 'Username should not contain spaces and must be at least 6 characters long.'

        if User.objects.filter(username=username).exists():
            error_messages['username'] = 'This username is already taken. Please choose a different username.'

        if User.objects.filter(email=email).exists():
            error_messages['email'] = 'An account with this email already exists. Please enter a different email or sign in to your account.'
        # Validate reCAPTCHA
        recaptcha_response = request.POST.get('g-recaptcha-response')
        if not recaptcha_response:
            error_messages['recaptcha'] = 'Please complete the reCAPTCHA.'
        else:
            data = {
                'secret': settings.RECAPTCHA_PRIVATE_KEY,
                'response': recaptcha_response,
            }
            response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data)
            result = response.json()
            if not result['success']:
                error_messages['recaptcha'] = 'reCAPTCHA verification failed. Please try again.'

    if error_messages:
        return render(request, 'pages/sign-up.html', {'hide_navbar': True, 'error_messages': error_messages})

    # If there are no errors, handle successful form submission
    if request.method == 'POST':
        # Create the user in the database
        user = User.objects.create_user(username=username, email=email, password=password,
                                        first_name=first_name, last_name=last_name)
        user.save()
        return redirect('index')

    return render(request, 'pages/sign-up.html', {'hide_navbar': True})



