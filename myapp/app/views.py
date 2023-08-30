from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login
import re
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.conf import settings
import requests
from django.core.mail import send_mail
from django.urls import reverse
from .models import Profile, VerificationToken, UserProfile
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
import google.auth
from django.contrib.auth.decorators import login_required



def handling_404(request, exception):
   hide_navbar = True
   return render(request, 'pages/404.html', {'hide_navbar': hide_navbar})

def index(request):
    context = {'current_page': 'index'}
    return render(request, 'index.html', context)

def about(request):
    context = {'current_page': 'about'}
    return render(request, 'about.html', context)

def jobs(request):
    context = {'current_page': 'jobs'}
    return render(request, 'jobs.html', context)

def jobdetails(request):
    context = {'current_page': 'jobs'}
    return render(request, 'pages/job-details.html', context)

def signin(request):
    return render(request, 'pages/signin.html')

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

def verify_email(request, token):
    try:
        verification_token = VerificationToken.objects.get(token=token)
        user = verification_token.user
        user.profile.is_verified = True
        user.profile.save()
        verification_token.delete()  # Delete the token after successful verification
        # Added success message
        messages.success(request, 'Email Verified!')
        return redirect('sign-in')  # Redirect to login page or any other page you want
    except VerificationToken.DoesNotExist:
        return render(request, 'verification_failed.html')  # Token not found

def send_verification_email(user, token):
    subject = 'Verify Your Email'
    message = f'Click the link below to verify your email:\n\n{settings.HOST_URL}/verify/{token}/'

    response = requests.post(
        f"https://api.mailgun.net/v3/{settings.MAILGUN_DOMAIN}/messages",
        auth=("api", settings.MAILGUN_API_KEY),
        data={"from": f"{settings.EMAIL_SENDER_NAME} <mailgun@{settings.MAILGUN_DOMAIN}>",
              "to": [user.email],
              "subject": subject,
              "text": message})

    return response


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

        # Create a profile for the user
        profile = Profile.objects.create(user=user)

        # Generate a verification token
        verification_token = VerificationToken.objects.create(user=user)


        # Send verification email
        send_verification_email(user, verification_token.token)

        return redirect('index')

    return render(request, 'pages/sign-up.html', {'hide_navbar': True})


def google_signup(request):
    flow = Flow.from_client_secrets_file(
        'D:/13IIV/THESIS/Predicting-Employee-Retention/myapp/clientsecret.json',  # Path to your downloaded OAuth2 credentials JSON file
        scopes=['https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email'],
        redirect_uri='http://127.0.0.1:8000/google-signup-redirect/'
    )
    authorization_url, _ = flow.authorization_url(prompt='consent')

    return redirect(authorization_url)

def google_signup_redirect(request):
    flow = Flow.from_client_secrets_file(
        'D:/13IIV/THESIS/Predicting-Employee-Retention/myapp/clientsecret.json', 
        scopes=['https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email'],
        redirect_uri='http://127.0.0.1:8000/google-signup-redirect/'
    )
    flow.fetch_token(authorization_response=request.build_absolute_uri())

    credentials = flow.credentials
    # Use credentials to get user info and create a new user or associate with an existing user
    # You can use `credentials.id_token` for additional user information

    return redirect('index')  # Redirect to the desired page


@login_required
def viewprofile(request):
    user = request.user
    user_profile = UserProfile.objects.get(user=request.user)
    # user_profile = UserProfile.objects.get(user=request.user)
    context = {
        'user_profile': user_profile,
        'user':user,
    }
    return render(request, 'profile/viewprofile.html', context)

@login_required
def editprofile(request):
    user = request.user
    user_profile, created = UserProfile.objects.get_or_create(user=user)

    if request.method == 'POST':
        user.first_name = request.POST.get('first_name')
        user.last_name = request.POST.get('last_name')
        user.email = request.POST.get('email')
        
        user_profile.phone = request.POST.get('phone')
        user_profile.address = request.POST.get('address')

        profile_picture = request.FILES.get('profile_picture')
        if profile_picture:
            user_profile.profile_picture = profile_picture

        user.save()
        user_profile.save()
        
        messages.success(request, 'Profile information updated successfully.')
        return redirect('edit-profile')  # Redirect to the same page after saving

    context = {
        'user_profile': user_profile,
        'user': user,
    }
    return render(request, 'profile/editprofile.html', context)

