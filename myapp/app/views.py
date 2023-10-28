from django.shortcuts import render, redirect,get_object_or_404
from django.contrib import messages
from django.contrib.auth.models import User
from django.db.models import Count
from django.contrib.auth import authenticate, login, update_session_auth_hash
import re
import os
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.conf import settings
from django.http import HttpResponseRedirect
import requests
from django.core.mail import send_mail
from django.urls import reverse
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
import google.auth
from django.contrib.auth.decorators import login_required, user_passes_test
from functools import wraps
from django.utils.html import strip_tags
from urllib.parse import urlparse
from datetime import datetime, date
from django.template.loader import get_template
import weasyprint
from django.http import HttpResponse
from django.utils import timezone
import imghdr
from .models import (
    VerificationToken,
    UserProfile,
    CandidateProfile,
    Education,
    WorkExperience,
    Certification,
    Skill,
    EmployerProfile,
    Job,
    JobApplication,
)


def handling_404(request, exception):
    hide_navbar = True
    return render(request, "pages/404.html", {"hide_navbar": hide_navbar})


def index(request):
    today = date.today()
    # Retrieve the six most recent non-expired job posts with associated employer profiles having logos
    recent_jobs = Job.objects.filter(
        deadline_date__gte=today,
        employer_profile__isnull=False,
        employer_profile__logo__isnull=False
    ).order_by('-created_date')[:6]

    context = {
        "current_page": "index",
        "recent_jobs": recent_jobs,
    }
    return render(request, "index.html", context)





def about(request):
    context = {"current_page": "about"}
    return render(request, "about.html", context)


def pdf_test(request):
    user = request.user
    candidate_profile = CandidateProfile.objects.filter(user=request.user)
    education_records = Education.objects.filter(user_profile=request.user.userprofile).order_by('-start_year')
    workexperiences = WorkExperience.objects.filter(user_profile=request.user.userprofile).order_by('-start_year')
    certifications = Certification.objects.filter(user_profile=request.user.userprofile)
    skills = Skill.objects.filter(user_profile=request.user.userprofile)

    context = {
        'user': user,
        'candidate_profile' :candidate_profile,
        'education_records': education_records,
        'workexperiences': workexperiences,
        'certifications': certifications,
        'skills': skills,
        'hide_navbar': True,
        'hide_footer': True,
    }
    return render(request, "pdf-resume.html", context)


#====================================================================================================================================================


def jobs(request):
    today = timezone.now()
    jobs_list = Job.objects.filter(deadline_date__gte=today).annotate(application_count=Count('jobapplication'))

    # Check if the user is authenticated
    if request.user.is_authenticated:
        user_profile = UserProfile.objects.get(user=request.user)
        applied_jobs = JobApplication.objects.filter(applicant=user_profile).values_list('job_id', flat=True)
    else:
        user_profile = None
        applied_jobs = []

    # Calculate the count of jobs in the list
    job_count = jobs_list.count()

    context = {
        "current_page": "jobs",
        "jobs_list": jobs_list,
        "applied_jobs": applied_jobs,
        "job_count": job_count,
        "user_profile": user_profile,  # Pass the user's profile to access the role
    }
    return render(request, "jobs.html", context)




#==================================================================================================================================================== MAIN PROCESS OF THE SYSTEM, DITO PAPASOK SI RULES BASED.
def apply_for_job(request, job_id):
    # Get the user's profile (assuming the user is logged in)
    user_profile = request.user.userprofile

    try:
        job = Job.objects.get(pk=job_id)
        # Create a JobApplication object
        JobApplication.objects.create(applicant=user_profile, job=job)
    except Job.DoesNotExist:
        # Handle the case where the job doesn't exist
        pass

    # You can redirect the user to a "Thank You" page or back to the job listing
    return redirect('jobs')
#====================================================================================================================================================
def job_details(request, job_id):
    try:
        job = Job.objects.select_related('employer_profile').get(pk=job_id)
    except Job.DoesNotExist:
        job = None

    user = request.user
    employer_profile = job.employer_profile

    if user.is_authenticated:
        user_profile = UserProfile.objects.get(user=user)
        user_role = user_profile.role
        applied_jobs = JobApplication.objects.filter(applicant=user_profile).values_list('job_id', flat=True)
    else:
        user_role = 'candidate'
        applied_jobs = []

    context = {
        "current_page": "jobs",
        "job": job,
        "user_email": user.email,
        "user_role": user_role,
        "applied_jobs": applied_jobs,
        "employer_profile": employer_profile,
    }
    return render(request, "apply_jobs/job_details.html", context)




#====================================================================================================================================================

#====================================================================================================================================================
def user_login(request):
    error_messages = {}  # Custom dictionary to store error messages for each field

    if request.method == "POST":
        # Get the form data submitted by the user
        username = request.POST.get("username")
        password = request.POST.get("password")

        if not username:
            error_messages["username"] = "Username is required."

        if not password:
            error_messages["password"] = "Password is required."

        # Perform authentication here
        user = authenticate(username=username, password=password)

        if user is not None:
            try:
                user_profile = UserProfile.objects.get(user=user)
                if user_profile.is_verified:
                    # Authentication successful and email is verified, log the user in
                    login(request, user)
                    return redirect("index")
                else:
                    # Email is not verified, show an error message
                    error_messages["auth"] = "Email is not verified. Please check your email for a verification link."
            except UserProfile.DoesNotExist:
                # UserProfile doesn't exist for this user
                error_messages["auth"] = "Invalid username or password."
        else:
            # Authentication failed
            error_messages["auth"] = "Invalid username or password."

        # Validate reCAPTCHA
        recaptcha_response = request.POST.get("g-recaptcha-response")
        if not recaptcha_response:
            error_messages["recaptcha"] = "Please complete the reCAPTCHA."
        else:
            data = {
                "secret": settings.RECAPTCHA_PRIVATE_KEY,
                "response": recaptcha_response,
            }
            response = requests.post(
                "https://www.google.com/recaptcha/api/siteverify", data=data
            )
            result = response.json()
            if not result["success"]:
                error_messages[
                    "recaptcha"
                ] = "reCAPTCHA verification failed. Please try again."

    return render(
        request,
        "pages/sign-in.html",
        {"hide_navbar": True, "error_messages": error_messages},
    )


def verify_email(request, token):
    try:
        verification_token = VerificationToken.objects.get(token=token)
        user = verification_token.user
        user_profile = UserProfile.objects.get(user=user)

        # Log in the user
        login(request, user)

        # Mark the user's profile as verified and complete
        user_profile.is_verified = True
        user_profile.is_profile_complete = False
        user_profile.save()

        # Delete the token after successful verification
        verification_token.delete()

        # Determine the redirection URL based on the user's role
        if user_profile.role == 'candidate':
            # Redirect to the candidate profile creation page
            return redirect("create_candidate_profile")
        elif user_profile.role == 'employer':
            # Redirect to the employer profile creation page
            return redirect("create_employer_profile")

        return redirect("index")  # A fallback redirect, if needed

    except VerificationToken.DoesNotExist:
        return render(request, "verification_failed.html")  # Token not found

def send_verification_email(user, token):
    subject = "Verify Your Email"
    message = f"Click the link below to verify your email:\n\n{settings.HOST_URL}/verify/{token}/"

    response = requests.post(
        f"https://api.mailgun.net/v3/{settings.MAILGUN_DOMAIN}/messages",
        auth=("api", settings.MAILGUN_API_KEY),
        data={
            "from": f"{settings.EMAIL_SENDER_NAME} <mailgun@{settings.MAILGUN_DOMAIN}>",
            "to": [user.email],
            "subject": subject,
            "text": message,
        },
    )

    return response

def register(request):
    error_messages = {}  # Custom dictionary to store error messages for each field
    username_regex = r"^\S{6,}$"
    password_regex = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[@#$%^&-+=()])(?=.{8,})"

    if request.method == "POST":
        # Get the form data submitted by the user
        first_name = request.POST.get("firstname")
        last_name = request.POST.get("lastname")
        username = request.POST.get("username")
        email = request.POST.get("email")
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirmPassword")
        role = request.POST.get("role")  # Get the selected role

        if not first_name:
            error_messages["firstname"] = "First name is required."

        if not last_name:
            error_messages["lastname"] = "Last name is required."

        if not email:
            error_messages["email"] = "Email is required."
        else:
            try:
                validate_email(email)
            except ValidationError:
                error_messages["email"] = "Please enter a valid email address."

        if not password:
            error_messages["password"] = "Password is required."

        elif password != confirm_password:
            error_messages[
                "confirmPassword"
            ] = "Your password confirmation does not match the entered password. Please enter again."
        else:
            if not re.match(password_regex, password):
                error_messages[
                    "password"
                ] = "Password must be 8 characters including uppercase, lowercase, number, and symbol."

        if not re.match(username_regex, username):
            error_messages[
                "username"
            ] = "Username should not contain spaces and must be at least 6 characters long."

        if User.objects.filter(username=username).exists():
            error_messages[
                "username"
            ] = "This username is already taken. Please choose a different username."

        if User.objects.filter(email=email).exists():
            error_messages[
                "email"
            ] = "An account with this email already exists. Please enter a different email or sign in to your account."

        # Validate reCAPTCHA
        recaptcha_response = request.POST.get("g-recaptcha-response")
        if not recaptcha_response:
            error_messages["recaptcha"] = "Please complete the reCAPTCHA."
        else:
            data = {
                "secret": settings.RECAPTCHA_PRIVATE_KEY,
                "response": recaptcha_response,
            }
            response = requests.post(
                "https://www.google.com/recaptcha/api/siteverify", data=data
            )
            result = response.json()
            if not result["success"]:
                error_messages[
                    "recaptcha"
                ] = "reCAPTCHA verification failed. Please try again."

    if error_messages:
        return render(
            request,
            "pages/sign-up.html",
            {"hide_navbar": True, "error_messages": error_messages},
        )

    # If there are no errors, handle successful form submission
    if request.method == "POST":
        # Create the user in the database
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
        )
        user.save()

        # Create a UserProfile for the user
        user_profile = UserProfile.objects.create(user=user)  # Create UserProfile

        # Set the user's role based on the selected role
        user_profile.role = role  # 'role' is the selected role (e.g., 'candidate' or 'employer')
        user_profile.save()

        # Generate a verification token and send the verification email
        verification_token = VerificationToken.objects.create(user=user)
        send_verification_email(user, verification_token.token)

        return redirect("index")

    return render(request, "pages/sign-up.html", {"hide_navbar": True})


#====================================================================================================================================================

@login_required
def create_candidate_profile(request):
    user_profile = UserProfile.objects.get(user=request.user)

    if user_profile.is_profile_complete:
        return redirect('index')

    error_messages = {}
    success_message = None

    if request.method == 'POST':
        profile_picture = request.FILES.get('profile_picture')
        job_title = request.POST.get('job_title')
        experience = request.POST.get('experience')
        current_salary = request.POST.get('current_salary')
        expected_salary = request.POST.get('expected_salary')
        birthdate = request.POST.get('birthdate')
        education_levels = request.POST.get('education_levels')
        region = request.POST.get('region')
        city = request.POST.get('city')
        barangay = request.POST.get('barangay')
        street_address = request.POST.get('street_address')
        phone = request.POST.get('phone')
        description = request.POST.get('description')

        phone_pattern = re.compile(r'^\d{11}$')
        if not phone_pattern.match(phone):
            error_messages['phone'] = 'Please enter a valid phone number (e.g., 09261006969).'

        words = strip_tags(description).split()
        if len(words) > 60:
            error_messages['description'] = 'Description should be 60 words or less.'

        required_fields = ['job_title', 'experience', 'phone', 'current_salary', 'expected_salary', 'birthdate', 'education_levels', 'region', 'city', 'barangay', 'street_address', 'description']

        for field in required_fields:
            if not request.POST.get(field):
                error_messages[field] = f"{field.replace('_', ' ').title()} is required."

        # Check if the uploaded file is a valid image (PNG or JPG)
        if profile_picture:
            file_type = imghdr.what(profile_picture)
            if file_type not in ['jpeg', 'png']:
                error_messages['profile_picture'] = 'Please upload a valid PNG or JPG image.'

        if any(error_messages.values()):
            context = {
                'error_messages': error_messages
            }
            return render(request, "pages/create_candidate_profile.html", context)
        else:
            candidate_profile, created = CandidateProfile.objects.get_or_create(user=request.user)
            candidate_profile.profile_picture = profile_picture
            candidate_profile.job_title = job_title
            candidate_profile.experience = experience
            candidate_profile.current_salary = current_salary
            candidate_profile.expected_salary = expected_salary
            candidate_profile.birthdate = birthdate
            candidate_profile.education_levels = education_levels
            candidate_profile.region = region
            candidate_profile.city = city
            candidate_profile.barangay = barangay
            candidate_profile.street_address = street_address
            candidate_profile.phone = phone
            candidate_profile.description = description
            candidate_profile.save()

            user_profile.is_profile_complete = True
            user_profile.save()
            return redirect('index')

            success_message = 'Profile created or updated successfully!'
    context = {
        'success_message': success_message
    }

    return render(request, "pages/create_candidate_profile.html", context)


#====================================================================================================================================================

@login_required
def create_employer_profile(request):
    user_profile = UserProfile.objects.get(user=request.user)

    if user_profile.is_profile_complete:
        return redirect('index')

    if request.method == 'POST':
        company_name = request.POST['company_name']
        phone = request.POST['phone']
        website_link = request.POST['website_link']
        since_date = request.POST['since_date']
        team_size = request.POST['team_size']
        company_description = request.POST['company_description']
        region = request.POST['region']
        city = request.POST['city']
        barangay = request.POST['barangay']
        street = request.POST['street']
        logo = request.FILES.get('logo')

        required_fields = ['company_name', 'phone', 'since_date', 'team_size', 'company_description', 'region', 'city', 'barangay', 'street']
        error_messages = {}

        for field in required_fields:
            if not request.POST.get(field):
                error_messages[field] = f"{field.replace('_', ' ').title()} is required."

        phone_pattern = re.compile(r'^\d{11}$')
        if not phone_pattern.match(phone):
            error_messages['phone'] = 'Please enter a valid phone number (e.g., 09261006969).'

        if website_link:
            if "://" not in website_link:
                website_link = "http://" + website_link

            parsed_url = urlparse(website_link)

            if not parsed_url.netloc:
                error_messages['website_link'] = "Website link is not a valid URL."

        if since_date:
            try:
                datetime.strptime(since_date, '%Y-%m-%d')
            except ValueError:
                error_messages['since_date'] = "Date should be in the format 'YYYY-MM-DD'."

        if any(error_messages.values()):
            context = {
                'error_messages': error_messages,
            }
            return render(request, 'pages/create_employer_profile.html', context)

        employer_profile = EmployerProfile(
            user_profile=request.user.userprofile,
            company_name=company_name,
            phone=phone,
            website_link=website_link,
            since_date=since_date,
            team_size=team_size,
            company_description=company_description,
            region=region,
            city=city,
            barangay=barangay,
            street=street,
            logo=logo
        )
        employer_profile.save()
        user_profile.is_profile_complete = True
        user_profile.save()
        return redirect('index')

    return render(request, 'pages/create_employer_profile.html')
#====================================================================================================================================================

@login_required
def viewprofile(request):
    user = request.user
    user_profile = UserProfile.objects.get(user=request.user)
    # user_profile = UserProfile.objects.get(user=request.user)
    context = {
        "user_profile": user_profile,
        "user": user,
    }
    return render(request, "profile/viewprofile.html", context)


@login_required
def editprofile(request):
    user = request.user
    user_profile, created = UserProfile.objects.get_or_create(user=user)

    if request.method == "POST":
        user.first_name = request.POST.get("first_name")
        user.last_name = request.POST.get("last_name")
        user.email = request.POST.get("email")

        user_profile.phone = request.POST.get("phone")
        user_profile.address = request.POST.get("address")

        profile_picture = request.FILES.get("profile_picture")
        if profile_picture:
            user_profile.profile_picture = profile_picture

        user.save()
        user_profile.save()

        messages.success(request, "Profile information updated successfully.")
        return redirect("edit-profile")  # Redirect to the same page after saving

    context = {
        "user_profile": user_profile,
        "user": user,
    }
    return render(request, "profile/editprofile.html", context)

#====================================================================================================================================================


def user_is_candidate(user):
    return user.userprofile.role == "candidate"


def user_is_employer(user):
    return user.userprofile.role == "employer"


@user_passes_test(user_is_candidate, login_url="/login/")
@login_required
def candidate_dashboard(request):
    user_profile = UserProfile.objects.get(user=request.user)
    applied_jobs_count = JobApplication.objects.filter(applicant=user_profile).count()
    recent_applied_jobs = JobApplication.objects.filter(applicant=user_profile).order_by('-application_date')[:4]

    context = {
        "current_page": "dashboard",
        "applied_jobs_count": applied_jobs_count,
        "recent_applied_jobs": recent_applied_jobs,
    }

    return render(request, "candidate_dashboard/dashboard.html", context)

#====================================================================================================================================================
@user_passes_test(user_is_candidate, login_url="/login/")
@login_required
def view_profile(request):
    context = {"current_page": "profile"}

    try:
        candidate_profile = CandidateProfile.objects.get(user=request.user)
    except CandidateProfile.DoesNotExist:
        candidate_profile = None

    # Calculate age if birthdate is available
    age = None
    if candidate_profile and candidate_profile.birthdate:
        today = date.today()
        age = today.year - candidate_profile.birthdate.year - ((today.month, today.day) < (candidate_profile.birthdate.month, candidate_profile.birthdate.day))

    context["candidate_profile"] = candidate_profile
    context["age"] = age  # Pass the calculated age to the template
    error_message = request.GET.get('error_message')
    success_message = request.GET.get('success_message')
    context['error_message'] = error_message
    context['success_message'] = success_message

    return render(request, "candidate_dashboard/profile/view_profile.html", context)


@user_passes_test(user_is_candidate, login_url="/login/")
@login_required
def edit_profile(request):
    context = {"current_page": "profile"}
    candidate_profile = CandidateProfile.objects.filter(user=request.user).first()
    error_messages = {}
    success_message = {}

    if not candidate_profile:
        return redirect('add_profile')

    if request.method == 'POST':
        profile_picture = request.FILES.get('profile_picture')
        job_title = request.POST.get('job_title')
        phone = request.POST.get('phone')
        current_salary = request.POST.get('current_salary')
        expected_salary = request.POST.get('expected_salary')
        experience = request.POST.get('experience')
        birthdate = request.POST.get('birthdate')
        education_levels = request.POST.get('education_levels')
        region = request.POST.get('region')
        city = request.POST.get('city')
        barangay = request.POST.get('barangay')
        street_address = request.POST.get('street_address')
        description = request.POST.get('description')

        phone_pattern = re.compile(r'^\d{11}$')
        if not phone_pattern.match(phone):
            error_messages['phone'] = 'Please enter a valid phone number (e.g., 09261006969).'

        words = strip_tags(description).split()
        if len(words) > 60:
            error_messages['description'] = 'Description should be 60 words or less.'

        required_fields = ['job_title', 'phone', 'current_salary', 'expected_salary', 'experience', 'birthdate', 'education_levels', 'region', 'city', 'barangay', 'street_address', 'description']

        for field in required_fields:
            if not request.POST.get(field):
                error_messages[field] = f"{field.replace('_', ' ').title()} is required."

        if any(error_messages.values()):
            context['error_messages'] = error_messages
        else:
            candidate_profile.job_title = job_title
            candidate_profile.phone = phone
            candidate_profile.current_salary = current_salary
            candidate_profile.expected_salary = expected_salary
            candidate_profile.experience = experience
            candidate_profile.birthdate = birthdate
            candidate_profile.education_levels = education_levels
            candidate_profile.region = region
            candidate_profile.city = city
            candidate_profile.barangay = barangay
            candidate_profile.street_address = street_address
            candidate_profile.description = description
            candidate_profile.profile_picture=profile_picture
            candidate_profile.save()

            success_message = 'Profile updated successfully!'

            redirect_url = reverse('view_profile') + f'?success_message={success_message}'
            return HttpResponseRedirect(redirect_url)

    context['candidate_profile'] = candidate_profile
    context['success_message'] = success_message

    return render(request, "candidate_dashboard/profile/edit_profile.html", context)

#====================================================================================================================================================
@user_passes_test(user_is_candidate, login_url="/login/")
@login_required
def resume(request):
    education_records = Education.objects.filter(user_profile=request.user.userprofile).order_by('-start_year')
    workexperiences = WorkExperience.objects.filter(user_profile=request.user.userprofile).order_by('-start_year')
    certifications = Certification.objects.filter(user_profile=request.user.userprofile)
    skills = Skill.objects.filter(user_profile=request.user.userprofile)

    context = {
        'current_page': 'resume',
        'education_records': education_records,
        'workexperiences': workexperiences,
        'certifications': certifications,
        'skills': skills,
    }


    success_message = request.GET.get('success_message')
    error_message = request.GET.get('error_message')

    context['success_message'] = success_message
    context['error_message'] = error_message

    return render(request, 'candidate_dashboard/resume/resume.html', context)



@user_passes_test(user_is_candidate, login_url="/login/")
@login_required
def generate_pdf(request):
    user = request.user
    candidate_profile = CandidateProfile.objects.filter(user=request.user)
    education_records = Education.objects.filter(user_profile=request.user.userprofile).order_by('-start_year')
    workexperiences = WorkExperience.objects.filter(user_profile=request.user.userprofile).order_by('-start_year')
    certifications = Certification.objects.filter(user_profile=request.user.userprofile)
    skills = Skill.objects.filter(user_profile=request.user.userprofile)

    context = {
        'user': user,
        'candidate_profile' :candidate_profile,
        'education_records': education_records,
        'workexperiences': workexperiences,
        'certifications': certifications,
        'skills': skills,
        'hide_navbar': True,
        'hide_footer': True,
    }

    template_path = 'candidate_dashboard/resume/resume_pdf.html'
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="resume.pdf"'

    template = get_template(template_path)
    html = template.render(context)

    # Generate PDF using WeasyPrint with the specified stylesheet
    weasyprint.HTML(string=html).write_pdf(response, stylesheets=[weasyprint.CSS(settings.STATIC_ROOT + '/css/pdf.css')])

    return response

#====================================================================================================================================================
@user_passes_test(user_is_candidate, login_url="/login/")
@login_required
def edit_education(request, education_id):
    education_record = get_object_or_404(Education, id=education_id)

    if request.method == 'POST':
        educational_degree = request.POST['educational_degree']
        start_month = request.POST.get('start_month')
        start_year = request.POST.get('start_year')
        end_month = request.POST.get('end_month')
        end_year = request.POST.get('end_year')
        school_name = request.POST['school_name']
        additional_info = request.POST['additional_info']

        education_record.educational_degree = educational_degree
        education_record.start_month = start_month
        education_record.start_year = start_year
        education_record.end_month = end_month
        education_record.end_year = end_year
        education_record.school_name = school_name
        education_record.additional_info = additional_info
        education_record.save()

        success_message = 'Education updated successfully!'

        redirect_url = reverse('resume') + f'?success_message={success_message}'
        return HttpResponseRedirect(redirect_url)

    context = {
        'current_page': 'resume',
        'education_record': education_record,
    }

    return render(request, 'candidate_dashboard/resume/education/edit_education.html', context)

@user_passes_test(user_is_candidate, login_url="/login/")
@login_required
def add_education(request):
    if request.method == 'POST':

        educational_degree = request.POST.get('educational_degree')
        school_name = request.POST.get('school_name')
        start_month = request.POST.get('start_month')
        start_year = request.POST.get('start_year')
        end_month = request.POST.get('end_month')
        end_year = request.POST.get('end_year')
        additional_info = request.POST.get('additional_info')

        required_fields = ['educational_degree', 'school_name', 'start_month','start_year','additional_info']
        error_messages = {}

        for field in required_fields:
            if not request.POST.get(field):
                error_messages[field] = f"{field.replace('_', ' ').title()} is required."

        if any(error_messages.values()):
            context = {
                'current_page': 'resume',
                'error_messages': error_messages,
            }
            return render(request, 'candidate_dashboard/resume/education/add_education.html', context)

        education_record = Education(
            user_profile=request.user.userprofile,
            educational_degree=educational_degree,
            school_name=school_name,
            start_month=start_month,
            start_year=start_year,
            end_month=end_month,
            end_year=end_year,
            additional_info=additional_info
        )
        education_record.save()

        success_message = 'Education created successfully!'
        redirect_url = reverse('resume') + f'?success_message={success_message}'
        return HttpResponseRedirect(redirect_url)

    context = {
        'current_page': 'resume',
    }

    return render(request, 'candidate_dashboard/resume/education/add_education.html', context)



@user_passes_test(user_is_candidate, login_url="/login/")
@login_required
def delete_education(request, education_id):
    try:
        user_profile = UserProfile.objects.get(user=request.user)
        education_record = Education.objects.get(id=education_id, user_profile=user_profile)
        education_record.delete()
    except Education.DoesNotExist:
        pass

    success_message = 'Education deleted successfully!'
    redirect_url = reverse('resume') + f'?success_message={success_message}'
    return HttpResponseRedirect(redirect_url)
#====================================================================================================================================================
@user_passes_test(user_is_candidate, login_url="/login/")
@login_required
def add_experience(request):
    if request.method == 'POST':
        # Retrieve data from the form submission
        position_title = request.POST.get('position_title')
        company_name = request.POST.get('company_name')
        location_type = request.POST.get('location_type')
        employment_type = request.POST.get('employment_type')
        start_month = request.POST.get('start_month')
        start_year = request.POST.get('start_year')
        end_month = request.POST.get('end_month')
        end_year = request.POST.get('end_year')
        work_description = request.POST.get('work_description')


        required_fields = ['position_title', 'company_name', 'location_type', 'employment_type', 'start_month','start_year','work_description']
        error_messages = {}

        for field in required_fields:
            if not request.POST.get(field):
                error_messages[field] = f"{field.replace('_', ' ').title()} is required."

        if any(error_messages.values()):
            context = {
                'current_page': 'resume',
                'error_messages': error_messages,
            }
            return render(request, 'candidate_dashboard/resume/experience/add_experience.html', context)


        work_experience = WorkExperience(
            user_profile=request.user.userprofile,
            position_title=position_title,
            company_name=company_name,
            location_type=location_type,
            employment_type=employment_type,
            start_month=start_month,
            start_year=start_year,
            end_month=end_month,
            end_year=end_year,
            work_description=work_description
        )
        work_experience.save()

        success_message = 'Work experience added successfully!'
        redirect_url = reverse('resume') + f'?success_message={success_message}'
        return HttpResponseRedirect(redirect_url)

    context = {
        'current_page': 'resume',
    }

    return render(request, 'candidate_dashboard/resume/experience/add_experience.html', context)


@user_passes_test(user_is_candidate, login_url="/login/")
@login_required
def edit_experience(request, workexperience_id):
    try:
        work_experience = WorkExperience.objects.get(id=workexperience_id, user_profile=request.user.userprofile)

        if request.method == 'POST':
            position_title = request.POST.get('position_title')
            employment_type = request.POST.get('employment_type')
            company_name = request.POST.get('company_name')
            location_type = request.POST.get('location_type')
            currently_working = request.POST.get('currently_working') == 'on'  # Checkbox value
            start_month = request.POST.get('start_month')
            start_year = request.POST.get('start_year')
            end_month = request.POST.get('end_month')
            end_year = request.POST.get('end_year')
            work_description = request.POST.get('work_description')

            # Validate and process the form data as needed

            # Update the work experience object with the new field values
            work_experience.position_title = position_title
            work_experience.employment_type = employment_type
            work_experience.company_name = company_name
            work_experience.location_type = location_type
            work_experience.currently_working = currently_working
            work_experience.start_month = start_month
            work_experience.start_year = start_year
            work_experience.end_month = end_month
            work_experience.end_year = end_year
            work_experience.work_description = work_description
            work_experience.save()

            success_message = 'Work experience updated successfully!'
            redirect_url = reverse('resume') + f'?success_message={success_message}'
            return HttpResponseRedirect(redirect_url)

        context = {
            'current_page': 'resume',
            'work_experience': work_experience,
        }

        return render(request, 'candidate_dashboard/resume/experience/edit_experience.html', context)

    except WorkExperience.DoesNotExist:
        # Handle the case where the work experience does not exist
        # You can redirect or show an error message as needed
        pass


@user_passes_test(user_is_candidate, login_url="/login/")
@login_required
def delete_experience(request, workexperience_id):
    try:
        user_profile = UserProfile.objects.get(user=request.user)
        experience_record = WorkExperience.objects.get(id=workexperience_id, user_profile=user_profile)
        experience_record.delete()
    except WorkExperience.DoesNotExist:
        pass

    success_message = 'Work Experience deleted successfully!'
    redirect_url = reverse('resume') + f'?success_message={success_message}'
    return HttpResponseRedirect(redirect_url)

#====================================================================================================================================================

@user_passes_test(user_is_candidate, login_url="/login/")
@login_required

def add_certification(request):
    if request.method == 'POST':
        # Retrieve data from the form submission
        certification_name = request.POST.get('certification_name')
        issuing_organization = request.POST.get('issuing_organization')
        issue_year = request.POST.get('issue_year')
        issue_month = request.POST.get('issue_month')
        description = request.POST.get('description')


        # Check if required fields are empty
        required_fields = ['certification_name', 'issuing_organization', 'issue_year', 'issue_month', 'description']
        error_messages = {}

        for field in required_fields:
            if not request.POST.get(field):
                error_messages[field] = f"{field.replace('_', ' ').title()} is required."

        if any(error_messages.values()):
            context = {
                'current_page': 'resume',
                'error_messages': error_messages,
            }
            return render(request, 'candidate_dashboard/resume/certification/add_certification.html', context)

        # Create a new Certification record and save it
        certification = Certification(
            user_profile=request.user.userprofile,
            name=certification_name,
            organization=issuing_organization,
            issue_year=issue_year,
            issue_month=issue_month,
            description=description
        )
        certification.save()

        success_message = 'Certification added successfully!'
        redirect_url = reverse('resume') + f'?success_message={success_message}'
        return HttpResponseRedirect(redirect_url)

    context = {
        'current_page': 'resume',
        'years': range(date.today().year, 1999, -1),
    }

    return render(request, 'candidate_dashboard/resume/certification/add_certification.html', context)


@user_passes_test(user_is_candidate, login_url="/login/")
@login_required
def edit_certification(request, certification_id):
    try:
        # Retrieve the existing certification
        certification = Certification.objects.get(id=certification_id, user_profile=request.user.userprofile)

        if request.method == 'POST':
            # Retrieve data from the form submission
            certification_name = request.POST.get('certification_name')
            issuing_organization = request.POST.get('issuing_organization')
            issue_year = request.POST.get('issue_year')
            issue_month = request.POST.get('issue_month')
            description = request.POST.get('description')

            # Required field validation
            required_fields = ['certification_name', 'issuing_organization', 'issue_year', 'issue_month', 'description']
            error_messages = {}

            for field in required_fields:
                if not request.POST.get(field):
                    error_messages[field] = f"{field.replace('_', ' ').title()} is required."

            if any(error_messages.values()):
                context = {
                    'current_page': 'resume',
                    'certification': certification,
                    'error_messages': error_messages,
                }
                return render(request, 'candidate_dashboard/resume/certification/edit_certification.html', context)

            # Update the certification with data from the form submission
            certification.name = certification_name
            certification.issuing_organization = issuing_organization
            certification.issue_year = issue_year
            certification.issue_month = issue_month
            certification.description = description
            certification.save()

            success_message = 'Certification updated successfully!'
            redirect_url = reverse('resume') + f'?success_message={success_message}'
            return HttpResponseRedirect(redirect_url)

        context = {
            'current_page': 'resume',
            'years': range(date.today().year, 1999, -1),
            'certification': certification,
        }

        return render(request, 'candidate_dashboard/resume/certification/edit_certification.html', context)

    except Certification.DoesNotExist:
        # Handle the case where the certification does not exist
        # You can redirect or show an error message as needed
        pass


@user_passes_test(user_is_candidate, login_url="/login/")
@login_required
def delete_certification(request, certification_id):
    try:
        user_profile = UserProfile.objects.get(user=request.user)
        certification_record = Certification.objects.get(id=certification_id, user_profile=user_profile)
        certification_record.delete()
    except Certification.DoesNotExist:
        pass

    success_message = 'Certification deleted successfully!'
    redirect_url = reverse('resume') + f'?success_message={success_message}'
    return HttpResponseRedirect(redirect_url)

#====================================================================================================================================================
@user_passes_test(user_is_candidate, login_url="/login/")
@login_required
def add_skill(request):
    if request.method == 'POST':
        skill = request.POST.get('skill')
        expi_years = request.POST.get('expi_years')

        required_fields = ['skill', 'expi_years']
        error_messages = {}

        for field in required_fields:
            if not request.POST.get(field):
                error_messages[field] = f"{field.replace('_', ' ').title()} is required."

        if any(error_messages.values()):
            context = {
                'current_page': 'resume',
                'error_messages': error_messages,
            }
            return render(request, 'candidate_dashboard/resume/skill/add_skill.html', context)

        skill_obj = Skill(
            user_profile=request.user.userprofile,
            skill=skill,
            expi_years=expi_years
        )
        skill_obj.save()

        success_message = 'Skill added successfully!'
        redirect_url = reverse('resume') + f'?success_message={success_message}'
        return HttpResponseRedirect(redirect_url)

    context = {
        'current_page': 'resume',
    }

    return render(request, 'candidate_dashboard/resume/skill/add_skill.html', context)

@user_passes_test(user_is_candidate, login_url="/login/")
@login_required
def edit_skill(request, skill_id):
    try:
        # Retrieve the existing skill
        skill = Skill.objects.get(id=skill_id, user_profile=request.user.userprofile)

        if request.method == 'POST':
            # Retrieve the data from the form submission
            skill_name = request.POST.get('skill')
            expi_years = request.POST.get('expi_years')

            required_fields = ['skill', 'expi_years']
            error_messages = {}

            # Validate required fields
            for field in required_fields:
                if not request.POST.get(field):
                    error_messages[field] = f"{field.replace('_', ' ').title()} is required."

            if any(error_messages.values()):
                context = {
                    'current_page': 'resume',
                    'error_messages': error_messages,
                    'skill': skill,  # Include the existing skill in the context
                }
                return render(request, 'candidate_dashboard/resume/skill/edit_skill.html', context)

            # Update the skill with data from the form submission
            skill.skill = skill_name
            skill.expi_years = expi_years
            skill.save()

            success_message = 'Skill updated successfully!'
            redirect_url = reverse('resume') + f'?success_message={success_message}'
            return HttpResponseRedirect(redirect_url)

        context = {
            'current_page': 'resume',
            'skill': skill,
        }

        return render(request, 'candidate_dashboard/resume/skill/edit_skill.html', context)

    except Skill.DoesNotExist:
        # Handle the case where the skill does not exist
        # You can redirect or show an error message as needed
        pass


@user_passes_test(user_is_candidate, login_url="/login/")
@login_required
def delete_skill(request, skill_id):
    try:
        user_profile = UserProfile.objects.get(user=request.user)
        experience_record = Skill.objects.get(id=skill_id, user_profile=user_profile)
        experience_record.delete()
    except Skill.DoesNotExist:
        pass

    success_message = 'Skill deleted successfully!'
    redirect_url = reverse('resume') + f'?success_message={success_message}'
    return HttpResponseRedirect(redirect_url)



#====================================================================================================================================================
@user_passes_test(user_is_candidate, login_url="/login/")
@login_required
def candidate_jobs(request):
    # Retrieve job applications for the current user
    user_profile = UserProfile.objects.get(user=request.user)
    job_applications = JobApplication.objects.filter(applicant=user_profile)

    # Fetch the count of all users who applied for each job
    jobs = Job.objects.annotate(application_count=Count('jobapplication__applicant'))

    # Create a list of dictionaries to store job titles and application counts
    job_counts = [{'job_title': job.job_title, 'application_count': job.application_count} for job in jobs]

    context = {
        "current_page": "applied_jobs",
        "job_applications": job_applications,
        "job_counts": job_counts,
    }

    return render(request, "candidate_dashboard/applied_jobs/applied_jobs.html", context)


#====================================================================================================================================================

@user_passes_test(user_is_candidate, login_url="/login/")
@login_required
def job_application_status(request, job_application_id):
    # Retrieve the specific job application details
    job_application = JobApplication.objects.get(pk=job_application_id)

    context = {
        "current_page": "applied_jobs",
        "job_application": job_application,
    }

    return render(request, "candidate_dashboard/applied_jobs/job_application_status.html", context)


#====================================================================================================================================================
@user_passes_test(user_is_candidate, login_url="/login/")
@login_required
def candidate_details(request):
    user = request.user
    error_messages = {}
    context = {"current_page": "account_details"}

    if request.method == "POST":
        # Get the submitted form data
        first_name = request.POST.get("first_name")
        last_name = request.POST.get("last_name")
        username = request.POST.get("username")
        email = request.POST.get("email")

        # Validate the form data
        errors = {}

        if not first_name:
            errors["first_name"] = "First Name is required."

        if not last_name:
            errors["last_name"] = "Last Name is required."

        if not username:
            errors["username"] = "Username is required."
        elif User.objects.exclude(pk=user.pk).filter(username=username).exists():
            errors["username"] = "Username is already taken."

        if not email:
            errors["email"] = "Email is required."
        elif User.objects.exclude(pk=user.pk).filter(email=email).exists():
            errors["email"] = "Email is already in use."

        if not errors:
            # Update the user model if there are no errors
            user.first_name = first_name
            user.last_name = last_name
            user.username = username
            user.email = email
            user.save()

            messages.success(request, "Your account details have been updated.")
            return redirect("candidate_details")
        else:
            # If there are errors, populate the error_messages dictionary
            for field, error_message in errors.items():
                error_messages[field] = error_message

    return render(
        request,
        "candidate_dashboard/account_details.html",
        {"user": user, "error_messages": error_messages, **context},
    )


@user_passes_test(user_is_candidate, login_url="/login/")
@login_required
def candidate_changepass(request):
    context = {"current_page": "change_password"}
    error_messages = {}  # Custom dictionary to store error messages for each field

    if request.method == "POST":
        # Get the submitted form data
        old_password = request.POST.get("old_password")
        new_password1 = request.POST.get("new_password1")
        new_password2 = request.POST.get("new_password2")

        # Validate the old password
        if not request.user.check_password(old_password):
            error_messages["old_password"] = "Old password is incorrect."

        # Validate the new password using the regex pattern
        password_regex = (
            r"^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[@#$%^&-+=()])(?=.{8,})"
        )
        if not re.match(password_regex, new_password1):
            error_messages[
                "new_password1"
            ] = "Password must be 8 characters including at least one uppercase letter, one lowercase letter, one digit, and one special character (@#$%^&-+=())."

        # Confirm if the new password matches the confirmation
        if new_password1 != new_password2:
            error_messages[
                "new_password2"
            ] = "Your password confirmation does not match the entered password. Please enter again."

        if not error_messages:
            # If there are no errors, update the password
            request.user.set_password(new_password1)
            request.user.save()
            update_session_auth_hash(
                request, request.user
            )  # Update the session after password change
            messages.success(request, "Your password has been successfully updated.")
            return redirect("candidate_changepass")

    return render(
        request,
        "candidate_dashboard/change_password.html",
        {"error_messages": error_messages, "current_page": "change_password"},
    )


# EMPLOYER VIEWS
@user_passes_test(user_is_employer, login_url="/login/")
@login_required
def employer_dashboard(request):
    context = {"current_page": "dashboard"}
    return render(request, "employer_dashboard/dashboard.html", context)

#====================================================================================================================================================
@user_passes_test(user_is_employer, login_url="/login/")
@login_required
def company_profile(request):
    context = {"current_page": "profile"}

    try:
        employer_profile = EmployerProfile.objects.get(user_profile=request.user.userprofile)
        context["employer_profile"] = employer_profile
    except EmployerProfile.DoesNotExist:
        employer_profile = None


    success_message = request.GET.get('success_message')
    error_message = request.GET.get('error_message')

    context['success_message'] = success_message
    context['error_message'] = error_message

    return render(request, "employer_dashboard/company_profile.html", context)


@user_passes_test(user_is_employer, login_url="/login/")
@login_required
def addcompany_profile(request):
    if request.method == 'POST':

        company_name = request.POST['company_name']
        phone = request.POST['phone']
        website_link = request.POST['website_link']
        since_date = request.POST['since_date']
        team_size = request.POST['team_size']
        company_description = request.POST['company_description']
        region = request.POST['region']
        city = request.POST['city']
        barangay = request.POST['barangay']
        street = request.POST['street']
        logo = request.FILES.get('logo')


        required_fields = ['company_name', 'phone', 'since_date', 'team_size', 'company_description', 'region', 'city', 'barangay', 'street' ]
        error_messages = {}

        for field in required_fields:
            if not request.POST.get(field):
                error_messages[field] = f"{field.replace('_', ' ').title()} is required."

        phone_pattern = re.compile(r'^\d{11}$')
        if not phone_pattern.match(phone):
            error_messages['phone'] = 'Please enter a valid phone number (e.g., 09261006969).'

        if website_link:
            from urllib.parse import urlparse

            if "://" not in website_link:
                website_link = "http://" + website_link

            parsed_url = urlparse(website_link)

            if not parsed_url.netloc:
                error_messages['website_link'] = "Website link is not a valid URL."

        if since_date:
            try:

                datetime.strptime(since_date, '%Y-%m-%d')
            except ValueError:
                error_messages['since_date'] = "Date should be in the format 'YYYY-MM-DD'."

        if any(error_messages.values()):
            context = {
                'current_page': 'profile',
                'error_messages': error_messages,
            }
            return render(request, 'employer_dashboard/company_profile/add_profile.html', context)

        employer_profile = EmployerProfile(
            user_profile=request.user.userprofile,
            company_name=company_name,
            phone=phone,
            website_link=website_link,
            since_date=since_date,
            team_size=team_size,
            company_description=company_description,
            region=region,
            city=city,
            barangay=barangay,
            street=street,
            logo=logo
        )
        employer_profile.save()

        success_message = 'Profile added successfully!'
        redirect_url = reverse('company_profile') + f'?success_message={success_message}'
        return HttpResponseRedirect(redirect_url)

    context = {
        'current_page': 'profile',
    }

    return render(request, 'employer_dashboard/company_profile/add_profile.html', context)

@user_passes_test(user_is_employer, login_url="/login/")
@login_required

def editcompany_profile(request):

    employer_profile = EmployerProfile.objects.get(user_profile=request.user.userprofile)

    if request.method == 'POST':

        company_name = request.POST['company_name']
        phone = request.POST['phone']
        website_link = request.POST['website_link']
        since_date = request.POST['since_date']
        team_size = request.POST['team_size']
        company_description = request.POST['company_description']
        region = request.POST['region']
        city = request.POST['city']
        barangay = request.POST['barangay']
        street = request.POST['street']
        logo = request.FILES.get('logo')

        if logo:
            if employer_profile.logo:
                employer_profile.logo.delete()

        required_fields = ['company_name', 'phone', 'since_date', 'team_size', 'company_description', 'region', 'city', 'barangay', 'street']
        error_messages = {}

        for field in required_fields:
            if not request.POST.get(field):
                error_messages[field] = f"{field.replace('_', ' ').title()} is required."

        phone_pattern = re.compile(r'^\d{11}$')
        if not phone_pattern.match(phone):
            error_messages['phone'] = 'Please enter a valid phone number (e.g., 09261006969).'

        if website_link:
            if "://" not in website_link:
                website_link = "http://" + website_link

            parsed_url = urlparse(website_link)

            if not parsed_url.netloc:
                error_messages['website_link'] = "Website link is not a valid URL."

        if since_date:
            try:
                datetime.strptime(since_date, '%Y-%m-%d')
            except ValueError:
                error_messages['since_date'] = "Date should be in the format 'YYYY-MM-DD'."

        if any(error_messages.values()):
            context = {
                'current_page': 'profile',
                'employer_profile': employer_profile,
                'error_messages': error_messages,
            }
            return render(request, 'employer_dashboard/company_profile/edit_profile.html', context)

        employer_profile.company_name = company_name
        employer_profile.phone = phone
        employer_profile.website_link = website_link
        employer_profile.since_date = since_date
        employer_profile.team_size = team_size
        employer_profile.company_description = company_description
        employer_profile.region = region
        employer_profile.city = city
        employer_profile.barangay = barangay
        employer_profile.street = street
        if logo:
            employer_profile.logo = logo
        employer_profile.save()

        success_message = 'Profile updated successfully!'
        redirect_url = reverse('company_profile') + f'?success_message={success_message}'
        return HttpResponseRedirect(redirect_url)

    context = {
        'current_page': 'profile',
        'employer_profile': employer_profile,
    }

    return render(request, 'employer_dashboard/company_profile/edit_profile.html', context)

#====================================================================================================================================================
@user_passes_test(user_is_employer, login_url="/login/")
@login_required
def manage_jobs(request):
    context = {"current_page": "manage_jobs"}

    try:
        employer_profile = request.user.userprofile.employer_profile
        jobs = Job.objects.filter(employer_profile=employer_profile).annotate(application_count=Count('jobapplication'))
        context["jobs"] = jobs

        today = date.today()
        for job in jobs:
            deadline_date = job.deadline_date
            created_date = job.created_date

            # Calculate days until deadline in the view
            days_until_deadline = (deadline_date - today).days
            job.days_until_deadline = days_until_deadline

        # Count the jobs
        job_count = len(jobs)
        context["job_count"] = job_count

    except Job.DoesNotExist:
        jobs = None

    success_message = request.GET.get('success_message')
    error_message = request.GET.get('error_message')

    context['success_message'] = success_message
    context['error_message'] = error_message
    return render(request, "employer_dashboard/manage_jobs.html", context)




@user_passes_test(user_is_employer, login_url="/login/")
@login_required
def employer_jobs(request, job_id):
    job = get_object_or_404(Job, pk=job_id)
    context = {
        'current_page': 'manage_jobs',
        'job': job,
    }
    return render(request, 'employer_dashboard/jobs/jobs.html', context)

@user_passes_test(user_is_employer, login_url="/login/")
@login_required
def post_jobs(request):
    if request.method == 'POST':
        # Extract form data
        job_title = request.POST['job_title']
        job_description = request.POST['job_description']
        specializations = request.POST['specializations']
        job_type = request.POST['job_type']
        job_setup = request.POST['job_setup']
        job_level = request.POST['job_level']
        experience_level = request.POST['experience_level']
        education_level = request.POST['education_level']
        offered_salary = request.POST['offered_salary']
        offered_salary_other = request.POST['offered_salary_other']
        deadline_date = request.POST['deadline_date']
        region = request.POST['region']
        city = request.POST['city']
        barangay = request.POST['barangay']
        street = request.POST['street']
        attachment = request.FILES.get('attachment')

        # Extract and process the skills_needed field
        skills_needed = request.POST.get('skills_needed', '')  # Get the raw input string
        skills_needed_list = [skill.strip() for skill in skills_needed.split(',')]  # Split and clean tags
        skills_needed_str = ','.join(skills_needed_list)  # Convert the list to a string

        error_messages = {}

        if offered_salary == "TBD":
            # "TBD" option selected, no further validation needed
            pass
        elif offered_salary == "enter_specific":
            # Check if offered_salary_other is not empty and contains valid numeric characters
            if not offered_salary_other or not offered_salary_other.isdigit():
                error_messages['offered_salary'] = 'Offered Salary must be a number.'

        required_fields = [
            'job_title', 'job_description', 'specializations', 'job_type', 'job_setup', 'job_level',
            'experience_level', 'education_level', 'deadline_date',
            'region', 'city', 'barangay', 'street'
        ]

        for field in required_fields:
            if not request.POST.get(field):
                error_messages[field] = f"{field.replace('_', ' ').title()} is required."

        if error_messages:
            context = {
                'current_page': 'manage_jobs',
                'error_messages': error_messages,
            }
            return render(request, 'employer_dashboard/jobs/post_jobs.html', context)

        # Create and save the Job instance
        job = Job(
            user_profile=request.user.userprofile,
            job_title=job_title,
            job_description=job_description,
            specializations=specializations,
            job_type=job_type,
            job_setup=job_setup,
            job_level=job_level,
            experience_level=experience_level,
            education_level=education_level,
            offered_salary=offered_salary if offered_salary != "enter_specific" else offered_salary_other,
            deadline_date=deadline_date,
            region=region,
            city=city,
            barangay=barangay,
            street=street,
            attachment=attachment,
            skills_needed=skills_needed_str  # Save the skills as a string
        )
        job.save()

        success_message = 'Job added successfully!'
        redirect_url = reverse('manage_jobs') + f'?success_message={success_message}'
        return HttpResponseRedirect(redirect_url)

    context = {
        'current_page': 'manage_jobs',
    }

    return render(request, 'employer_dashboard/jobs/post_jobs.html', context)




@user_passes_test(user_is_employer, login_url="/login/")
@login_required
def edit_job(request, job_id):
    employer_profile = request.user.userprofile.employer_profile
    job = get_object_or_404(Job, id=job_id, employer_profile=employer_profile)

    if request.method == 'POST':
        # Extract form data
        job_title = request.POST['job_title']
        job_description = request.POST['job_description']
        specializations = request.POST['specializations']
        job_type = request.POST['job_type']
        job_setup = request.POST['job_setup']
        job_level = request.POST['job_level']
        experience_level = request.POST['experience_level']
        education_level = request.POST['education_level']

        offered_salary_option = request.POST['offered_salary']
        if offered_salary_option == 'specific':
            offered_salary = request.POST['offered_salary_other']
        else:
            offered_salary = offered_salary_option

        deadline_date = request.POST['deadline_date']
        region = request.POST['region']
        city = request.POST['city']
        barangay = request.POST['barangay']
        street = request.POST['street']
        attachment = request.FILES.get('attachment')

        # Extract and process the skills_needed field
        skills_needed = request.POST.get('skills_needed', '')  # Get the raw input string
        skills_needed_list = [skill.strip() for skill in skills_needed.split(',')]  # Split and clean tags
        skills_needed_str = ','.join(skills_needed_list)  # Convert the list to a string

        error_messages = {}

        if offered_salary_option == 'specific' and (not offered_salary or not offered_salary.isdigit()):
            error_messages['offered_salary'] = 'Offered Salary must be a number.'

        required_fields = [
            'job_title', 'job_description', 'specializations', 'job_type', 'job_setup', 'job_level',
            'experience_level', 'education_level', 'deadline_date',
            'region', 'city', 'barangay', 'street'
        ]

        for field in required_fields:
            if not request.POST.get(field):
                error_messages[field] = f"{field.replace('_', ' ').title()} is required."

        if error_messages:
            context = {
                'current_page': 'manage_jobs',
                'error_messages': error_messages,
                'job': job,
            }
            return render(request, 'employer_dashboard/jobs/edit_jobs.html', context)

        job.job_title = job_title
        job.job_description = job_description
        job.specializations = specializations
        job.job_type = job_type
        job.job_setup = job_setup
        job.job_level = job_level
        job.experience_level = experience_level
        job.education_level = education_level
        job.offered_salary = offered_salary
        job.deadline_date = deadline_date
        job.region = region
        job.city = city
        job.barangay = barangay
        job.street = street
        if attachment:
            job.attachment = attachment
        job.skills_needed = skills_needed_str  # Update the skills_needed field
        job.save()

        success_message = 'Job updated successfully!'
        redirect_url = reverse('manage_jobs') + f'?success_message={success_message}'
        return HttpResponseRedirect(redirect_url)

    else:
        context = {
            'current_page': 'profile',
            'job': job,
        }

        return render(request, 'employer_dashboard/jobs/edit_jobs.html', context)



@user_passes_test(user_is_employer, login_url="/login/")
@login_required
def delete_job(request, job_id):
    try:
        user_profile = UserProfile.objects.get(user=request.user)
        jobs = Job.objects.get(id=job_id, user_profile=user_profile)
        jobs.delete()
    except Job.DoesNotExist:
        pass

    success_message = 'Job deleted successfully!'
    redirect_url = reverse('manage_jobs') + f'?success_message={success_message}'
    return HttpResponseRedirect(redirect_url)


#====================================================================================================================================================
@user_passes_test(user_is_employer, login_url="/login/")
@login_required
def all_positions(request):
    if request.user.is_authenticated and request.user.userprofile.role == 'employer':
        # Fetch jobs related to this employer
        employer_profile = request.user.userprofile.employer_profile  
        jobs = Job.objects.filter(employer_profile=employer_profile)

        # Fetch job applications related to these jobs
        job_applications = JobApplication.objects.filter(job__in=jobs)

        context = {
            "current_page": "applicants",
            "jobs": jobs,
            "job_applications": job_applications,
        }
        return render(request, "employer_dashboard/applicants/all_positions.html", context)
    else:
        # Handle the case where the user is not an employer or is not logged in
        # Redirect to the appropriate page or show an error message
        # Example: return a response indicating the user doesn't have access
        return HttpResponse("Access denied")
#====================================================================================================================================================
def positions(request, job_id):
    # Fetch the job details based on the job_id
    job = get_object_or_404(Job, id=job_id)

    # Get the list of applicants for this job
    job_applications = JobApplication.objects.filter(job=job)

    # Extract the applicant data including the profile picture
    applicants_data = []
    for application in job_applications:
        applicant = application.applicant
        first_name = applicant.user.first_name
        last_name = applicant.user.last_name
        profile_picture = None  # Initialize to None
        if applicant.role == 'candidate':
            # If the applicant is a candidate, fetch their profile picture
            candidate_profile = CandidateProfile.objects.get(user=applicant.user)
            profile_picture = candidate_profile.profile_picture
        applicants_data.append({"first_name": first_name, "last_name": last_name, "profile_picture": profile_picture})

    context = {
        "current_page": "applicants",
        "job": job,  # Pass the job details to the template
        "applicants_data": applicants_data,  # Pass the applicant data to the template
    }
    return render(request, "employer_dashboard/applicants/positions.html", context)



#====================================================================================================================================================
@user_passes_test(user_is_employer, login_url="/login/")
@login_required
def applicants(request):
    context = {"current_page": "applicants"}
    return render(request, "employer_dashboard/applicants.html", context)

