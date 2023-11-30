from django.shortcuts import render, redirect,get_object_or_404
from django.contrib import messages
from django.contrib.auth.models import User
from django.db.models import Count
from django.contrib.auth import authenticate, login, update_session_auth_hash
import re
from django.http import Http404
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
from django.template.loader import render_to_string
from calendar import month_name
import google.auth
from django.contrib.auth.decorators import login_required, user_passes_test
from functools import wraps
from django.utils.html import strip_tags
from urllib.parse import urlparse
from datetime import datetime, date, timedelta
from django.template.loader import get_template
import weasyprint
from django.http import HttpResponse
from django.utils import timezone
import imghdr
from collections import OrderedDict
from django.http import JsonResponse
from django.core.files.base import ContentFile
from django.db.models import Sum, F, Case, When, ExpressionWrapper, IntegerField, Value, CharField, fields
import json
from datetime import datetime
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
    JobTraining
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
    user_profile = request.user.userprofile

    if not has_required_information(user_profile):
        messages.error(request, "Please complete your resume before applying for a job.")
        return redirect('job_details', job_id=job_id)

    try:
        job = Job.objects.get(pk=job_id)

        # Check if the application already exists
        existing_application = JobApplication.objects.filter(applicant=user_profile, job=job).first()
        if existing_application:
            messages.warning(request, "You have already applied for this job.")
        else:
            # Calculate retention score based on Decision Tree
            job_application = calculate_retention_score(user_profile, job)

            messages.success(request, "Application submitted successfully!")

    except Job.DoesNotExist:
        raise Http404("Job not found.")  # Raise Http404 for job not found
    except Exception as e:
        # Raise the caught exception to let Django handle it
        raise

    return redirect('job_details', job_id=job_id)


def load_market_salaries(file_path):
    try:
        with open(file_path, 'r') as file:
            market_salaries = json.load(file)
        return market_salaries
    except FileNotFoundError:
        print(f"File {file_path} not found.")
        return {}


def get_market_rate(job_title, market_salaries):
    # Try to find an exact match first
    if job_title in market_salaries:
        print(f"Exact match found for job title: {job_title}")
        return market_salaries[job_title]

    # If no exact match, try to find a partial match
    for json_job_title in market_salaries:
        if json_job_title.lower() in job_title.lower() or job_title.lower() in json_job_title.lower():
            print(f"Partial match found for job title: {job_title} (JSON title: {json_job_title})")
            return market_salaries[json_job_title]

    # Default to 30000 if no match is found
    print(f"No match found for job title: {job_title}, using default market rate")
    return 30000


def count_promotions(work_experiences):
    # Count promotions based on changes in position_title within the same company
    promotions = sum(
        1 for i in range(len(work_experiences) - 1)
        if work_experiences[i].company_name == work_experiences[i + 1].company_name
        and work_experiences[i].position_title != work_experiences[i + 1].position_title
    )
    return promotions

def calculate_age(birthdate):
    if birthdate:
        today = date.today()
        age = today.year - birthdate.year - ((today.month, today.day) < (birthdate.month, birthdate.day))
        return age
    return None

def calculate_employment_gaps(work_experiences):
    # Sort work experiences by end date in ascending order
    sorted_work_experiences = sorted(work_experiences, key=lambda x: (x.end_year, x.end_month or "January"))

    gap_count = 0
    current_date = datetime.now().date()

    for i in range(len(sorted_work_experiences) - 1):
        end_date = datetime(
            year=sorted_work_experiences[i].end_year,
            month=list(month_name).index(sorted_work_experiences[i].end_month or "January"),
            day=1
        )
        start_date = datetime(
            year=sorted_work_experiences[i + 1].start_year,
            month=list(month_name).index(sorted_work_experiences[i + 1].start_month or "January"),
            day=1
        ) if sorted_work_experiences[i + 1].start_year else current_date

        # Calculate the gap in months
        gap = (start_date.year - end_date.year) * 12 + start_date.month - end_date.month

        if gap > 6:  # If the gap is greater than 6 months
            gap_count += 1
            print(f"Gap {gap_count}: {end_date.strftime('%B %Y')} to {start_date.strftime('%B %Y')}")

    return gap_count



class DecisionTree:
    @staticmethod
    def evaluate_rule1(offered_salary, market_rate):
        if offered_salary < 0.85 * market_rate:
            print("Rule 1: Turnover Risk - Candidate's current salary is <85% market rate.")
            return 0, "Salary offered is below 85% of the market rate."
        else:
            print("Rule 1: Retain")
            return 1, None

    @staticmethod
    def evaluate_rule2(matching_percentage):
        if matching_percentage < 50:
            print("Rule 2: Turnover Risk - Candidate has <50% of desired skills.")
            return 0, "Candidate has less than 50% of the desired skills."
        else:
            print("Rule 2: Retain")
            return 1, None

    @staticmethod
    def evaluate_rule3(required_certifications, candidate_certifications):
        if required_certifications.issubset(candidate_certifications):
            print("Rule 3: Retain")
            return 1, None
        else:
            print("Rule 3: Turnover Risk - Candidate is missing some required certifications.")
            return 0, "Candidate is missing some required certifications."

    @staticmethod
    def evaluate_rule5(last_two_jobs):
        if all(job.end_year - job.start_year >= 2 for job in last_two_jobs):
            print("Rule 5: Retain")
            return 1, None
        else:
            print("Rule 5: Turnover Risk - Candidate has not remained at their last 2 IT jobs for 2+ years.")
            return 0, "Candidate has not remained at their last 2 IT jobs for 2+ years."

    @staticmethod
    def evaluate_rule6(job_changes_last_five_years):
        if job_changes_last_five_years.count() > 3:
            print("Rule 6: Turnover Risk - Candidate has changed jobs more than 3 times in the last 5 years.")
            return 0, "Candidate has changed jobs more than 3 times in the last 5 years."
        else:
            print("Rule 6: Retain")
            return 1, None

    @staticmethod
    def evaluate_rule7(promotions):
        if promotions > 0:
            print("Rule 7: Retain - Candidate has received a raise/promotion in the past job.")
            return 1, None
        else:
            print("Rule 7: No promotions detected.")
            return 0, "No promotions were detected for the candidate in past jobs."

    @staticmethod
    def evaluate_rule8(age):
        if age is not None and age > 40:
            print("Rule 8: Retain")
            return 1, None
        else:
            print("Rule 8: Applicant age is < 40.")
            return 0, "Applicant age is below 40."

    @staticmethod
    def evaluate_rule9(job_setup, work_experiences):
        for experience in work_experiences:
            if experience.location_type == job_setup:
                print(f"Rule 9: Retain - Candidate has prior experience with the job setup")
                return 1, None

        print(f"Rule 9: Candidate has no prior experience with the job setup.")
        return 0, "Candidate has no prior experience with the job setup."

    @staticmethod
    def evaluate_rule10(work_experiences):
        gap_count = calculate_employment_gaps(work_experiences)

        if gap_count > 0:
            print(f"Rule 10: Turnover Risk - Candidate has {gap_count} employment gaps > 6 months in the last 5 years.")
            return 0, f"Candidate has {gap_count} employment gaps greater than 6 months in the last 5 years."
        else:
            print("Rule 10: Retain - No employment gaps > 6 months in the last 5 years.")
            return 1, None

# Assuming the implementation of the calculate_employment_gaps function and other required functions.

def calculate_retention_score(user_profile, job):
    # Load market salaries from the JSON file
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    json_file_path = os.path.join(BASE_DIR, 'app', 'market_jobsalaries.json')
    market_salaries = load_market_salaries(json_file_path)

    # Rule 1
    market_rate_placeholder = get_market_rate(job.job_title, market_salaries)
    offered_salary = float(job.offered_salary)
    rule1_outcome, rule1_reason = DecisionTree.evaluate_rule1(offered_salary, market_rate_placeholder)

    # Rule 2
    required_skills = set(job.skills_needed.split(','))
    candidate_skills = set(Skill.objects.filter(user_profile=user_profile).values_list('skill', flat=True))
    matching_percentage = len(candidate_skills.intersection(required_skills)) / len(required_skills) * 100
    rule2_outcome, rule2_reason = DecisionTree.evaluate_rule2(matching_percentage)

    # Rule 3
    required_certifications = set(job.certification_needed.split(','))
    candidate_certifications = set(
        Certification.objects.filter(user_profile=user_profile).values_list('name', flat=True)
    )
    rule3_outcome, rule3_reason = DecisionTree.evaluate_rule3(required_certifications, candidate_certifications)

    # Rule 5
    work_experiences = WorkExperience.objects.filter(user_profile=user_profile).order_by('-end_year')
    last_two_jobs = work_experiences[:2]
    rule5_outcome, rule5_reason = DecisionTree.evaluate_rule5(last_two_jobs)

    # Rule 6
    five_years_ago = datetime.now() - timedelta(days=5 * 365)
    job_changes_last_five_years = work_experiences.filter(start_year__gte=five_years_ago.year)
    rule6_outcome, rule6_reason = DecisionTree.evaluate_rule6(job_changes_last_five_years)

    # Rule 7: Promotions
    promotions = count_promotions(work_experiences)
    rule7_outcome, rule7_reason = DecisionTree.evaluate_rule7(promotions)

    outcomes = [rule1_outcome, rule2_outcome, rule3_outcome, rule5_outcome, rule6_outcome]
    if promotions > 0 and rule7_outcome == 1:
        outcomes.append(rule7_outcome)

    # Rule 8: Age
    age = calculate_age(user_profile.candidateprofile.birthdate)
    rule8_outcome, rule8_reason = DecisionTree.evaluate_rule8(age)

    # Rule 9: Job setup type
    job_setup_type = job.job_setup
    rule9_outcome, rule9_reason = DecisionTree.evaluate_rule9(job_setup_type, work_experiences)

    # Rule 10: Employment gaps
    rule10_outcome, rule10_reason = DecisionTree.evaluate_rule10(work_experiences)

    # Count the number of "Retain" and "Turnover Risk" outcomes
    outcomes = [rule1_outcome, rule2_outcome, rule3_outcome, rule5_outcome, rule6_outcome, rule8_outcome, rule9_outcome, rule10_outcome]

    retain_count = outcomes.count(1)
    turnover_count = outcomes.count(0)


    # Determine the final outcome and reason for turnover based on the results of individual rules
    reasons_for_turnover = []

    # Rule 1
    rule1_outcome, rule1_reason = DecisionTree.evaluate_rule1(offered_salary, market_rate_placeholder)
    if rule1_outcome == 0:
        reasons_for_turnover.append(rule1_reason or "")

    # Rule 2
    rule2_outcome, rule2_reason = DecisionTree.evaluate_rule2(matching_percentage)
    if rule2_outcome == 0:
        reasons_for_turnover.append(rule2_reason or "")

    # Rule 3
    rule3_outcome, rule3_reason = DecisionTree.evaluate_rule3(required_certifications, candidate_certifications)
    if rule3_outcome == 0:
        reasons_for_turnover.append(rule3_reason or "")

    # Rule 5
    rule5_outcome, rule5_reason = DecisionTree.evaluate_rule5(last_two_jobs)
    if rule5_outcome == 0:
        reasons_for_turnover.append(rule5_reason or "")

    # Rule 6
    rule6_outcome, rule6_reason = DecisionTree.evaluate_rule6(job_changes_last_five_years)
    if rule6_outcome == 0:
        reasons_for_turnover.append(rule6_reason or "")

    # Rule 7
    rule7_outcome, rule7_reason = DecisionTree.evaluate_rule7(promotions)
    if rule7_outcome == 0:
        reasons_for_turnover.append(rule7_reason or "")

    # Rule 8
    rule8_outcome, rule8_reason = DecisionTree.evaluate_rule8(age)
    if rule8_outcome == 0:
        reasons_for_turnover.append(rule8_reason or "")

    # Rule 9
    rule9_outcome, rule9_reason = DecisionTree.evaluate_rule9(job_setup_type, work_experiences)
    if rule9_outcome == 0:
        reasons_for_turnover.append(rule9_reason or "")

    # Rule 10
    rule10_outcome, rule10_reason = DecisionTree.evaluate_rule10(work_experiences)
    if rule10_outcome == 0:
        reasons_for_turnover.append(rule10_reason or "")

    final_reason_for_turnover = "\n".join(reasons_for_turnover)

    # Determine the final outcome based on the results of individual rules
    retain_count = outcomes.count(1)
    turnover_count = outcomes.count(0)

    if turnover_count > retain_count:
        final_outcome = 'Low Retention'
    else:
        final_outcome = 'High Retention' if 6 <= retain_count <= 7 else 'Moderate Retention'

    final_reason_for_turnover = "\n".join(reasons_for_turnover)

    # Calculate the retention score based on the number of "Retain" outcomes
    retention_score = retain_count

    # Update the JobApplication model instance with the retention score, category, and reasons for turnover
    job_application = JobApplication(
        applicant=user_profile,
        job=job,
        outcome=final_outcome,
        retention_score=retention_score,
        risk_factors=final_reason_for_turnover,
    )

    # Associate the reasons for turnover with the JobApplication
    if reasons_for_turnover:
        # Combine reasons into a single string
        reasons_text = "\n".join(reasons_for_turnover)

        # Set the reasons_for_turnover field directly in the model
        job_application.reasons_for_turnover = reasons_text

    job_application.save()

    return job_application



def has_required_information(user_profile):
    # Check if the user has filled in all the required information (Education, WorkExperience, Certification, and Skill)
    return (
        Education.objects.filter(user_profile=user_profile).exists() and
        # WorkExperience.objects.filter(user_profile=user_profile).exists() and
        Certification.objects.filter(user_profile=user_profile).exists() and
        Skill.objects.filter(user_profile=user_profile).exists()
    )
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

        required_fields = ['job_title', 'experience', 'phone', 'expected_salary', 'birthdate', 'education_levels', 'region', 'city', 'barangay', 'street_address', 'description']

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
            candidate_profile, created = CandidateProfile.objects.get_or_create(user_profile=user_profile)
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
        candidate_profile = CandidateProfile.objects.get(user_profile__user=request.user)
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
    candidate_profile = CandidateProfile.objects.filter(user_profile__user=request.user).first()
    error_messages = {}
    success_message = None

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

        required_fields = ['job_title', 'phone', 'expected_salary', 'experience', 'birthdate', 'education_levels', 'region', 'city', 'barangay', 'street_address', 'description']

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
            if profile_picture:
                candidate_profile.profile_picture = profile_picture
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
    job_trainings = JobTraining.objects.filter(user_profile=request.user.userprofile).order_by('-start_year')
    certifications = Certification.objects.filter(user_profile=request.user.userprofile)
    skills = Skill.objects.filter(user_profile=request.user.userprofile)

    context = {
        'current_page': 'resume',
        'education_records': education_records,
        'workexperiences': workexperiences,
        'job_trainings': job_trainings,
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
    candidate_profile = CandidateProfile.objects.get(user_profile=user.userprofile)
    education_records = Education.objects.filter(user_profile=user.userprofile).order_by('-start_year')
    workexperiences = WorkExperience.objects.filter(user_profile=user.userprofile).order_by('-start_year')
    certifications = Certification.objects.filter(user_profile=user.userprofile)
    skills = Skill.objects.filter(user_profile=user.userprofile)
    job_trainings = JobTraining.objects.filter(user_profile=user.userprofile)


    context = {
        'user': user,
        'candidate_profile': candidate_profile,
        'education_records': education_records,
        'workexperiences': workexperiences,
        'certifications': certifications,
        'skills': skills,
        'job_trainings': job_trainings,
        'hide_navbar': True,
        'hide_footer': True,
    }

    template_path = 'candidate_dashboard/resume/resume_pdf.html'

    # Generate the PDF
    pdf_file_name = 'resume.pdf'
    pdf_file_path = os.path.join(settings.PDF_STORAGE_PATH, pdf_file_name)

    template = get_template(template_path)
    html = template.render(context)

    # Generate PDF content as a string
    pdf_content = weasyprint.HTML(string=html).write_pdf(stylesheets=[weasyprint.CSS(settings.STATIC_ROOT + '/css/pdf.css')])

    # Save the PDF content to the candidate's resume field
    candidate_profile.resume.save(pdf_file_name, ContentFile(pdf_content), save=False)
    candidate_profile.save()

    # Create an HttpResponse with the PDF content for the user to download
    response = HttpResponse(pdf_content, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="{pdf_file_name}"'

    return response


#====================================================================================================================================================
@user_passes_test(user_is_candidate, login_url="/login/")
@login_required
def edit_education(request, education_id):
    education_record = get_object_or_404(Education, id=education_id)

    if request.method == 'POST':
        education_level = request.POST['education_level']
        educational_degree = request.POST['educational_degree']
        start_month = request.POST.get('start_month')
        start_year = request.POST.get('start_year')
        end_month = request.POST.get('end_month')
        end_year = request.POST.get('end_year')
        school_name = request.POST['school_name']
        additional_info = request.POST['additional_info']

        education_record.education_level = education_level
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

    years = list(range(2023, 1999, -1))

    context = {
        'current_page': 'resume',
        'education_record': education_record,
        'years': years,
    }

    return render(request, 'candidate_dashboard/resume/education/edit_education.html', context)

@user_passes_test(user_is_candidate, login_url="/login/")
@login_required
def add_education(request):
    if request.method == 'POST':
        education_level = request.POST.get('education_level')
        educational_degree = request.POST.get('educational_degree')
        school_name = request.POST.get('school_name')
        start_month = request.POST.get('start_month')
        start_year = request.POST.get('start_year')
        end_month = request.POST.get('end_month')
        end_year = request.POST.get('end_year')
        additional_info = request.POST.get('additional_info')

        required_fields = ['education_level', 'educational_degree', 'school_name', 'start_month', 'start_year', 'additional_info']
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
            education_level=education_level,
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
def add_trainings(request):
    if request.method == 'POST':
        # Retrieve data from the form submission
        training_title = request.POST.get('training_title')
        training_type = request.POST.get('training_type')
        training_organization = request.POST.get('training_organization')
        location_type = request.POST.get('location_type')
        start_month = request.POST.get('start_month')
        start_year = request.POST.get('start_year')
        end_month = request.POST.get('end_month')
        end_year = request.POST.get('end_year')
        training_description = request.POST.get('training_description')

        # Validation and error handling
        required_fields = ['training_title', 'training_type', 'training_organization', 'location_type', 'start_month', 'start_year', 'training_description']
        error_messages = {}

        for field in required_fields:
            if not request.POST.get(field):
                error_messages[field] = f"{field.replace('_', ' ').title()} is required."

        if any(error_messages.values()):
            context = {
                'current_page': 'resume',
                'error_messages': error_messages,
            }
            return render(request, 'candidate_dashboard/resume/job_trainings/add_trainings.html', context)

        # Save the training information to the database
        job_training = JobTraining(
            user_profile=request.user.userprofile,
            training_title=training_title,
            training_type=training_type,
            training_organization=training_organization,
            location_type=location_type,
            start_month=start_month,
            start_year=start_year,
            end_month=end_month,
            end_year=end_year,
            training_description=training_description
        )
        job_training.save()

        success_message = 'Job training added successfully!'
        redirect_url = reverse('resume') + f'?success_message={success_message}'
        return HttpResponseRedirect(redirect_url)

    context = {
        'current_page': 'resume',
    }

    return render(request, 'candidate_dashboard/resume/job_trainings/add_trainings.html', context)




@user_passes_test(user_is_candidate, login_url="/login/")
@login_required
def update_trainings(request, jobtraining_id):
    try:
        job_training = JobTraining.objects.get(id=jobtraining_id, user_profile=request.user.userprofile)

        years = range(2023, 2009, -1)  # from 2023 to 2010
        months = [
            'January', 'February', 'March', 'April', 'May', 'June',
            'July', 'August', 'September', 'October', 'November', 'December'
        ]

        if request.method == 'POST':
            # Retrieve data from the POST request
            training_title = request.POST.get('training_title')
            training_type = request.POST.get('training_type')
            training_organization = request.POST.get('training_organization')
            location_type = request.POST.get('location_type')
            start_month = request.POST.get('start_month')
            start_year = request.POST.get('start_year')
            end_month = request.POST.get('end_month')
            end_year = request.POST.get('end_year')
            training_description = request.POST.get('training_description')

            # Update the JobTraining instance
            job_training.training_title = training_title
            job_training.training_type = training_type
            job_training.training_organization = training_organization
            job_training.location_type = location_type
            job_training.start_month = start_month
            job_training.start_year = start_year
            job_training.end_month = end_month
            job_training.end_year = end_year
            job_training.training_description = training_description

            # Save the updated instance to the database
            job_training.save()

            success_message = 'Training updated successfully!'
            redirect_url = reverse('resume') + f'?success_message={success_message}'
            return HttpResponseRedirect(redirect_url)

        context = {
            "current_page": "resume",
            "job_training": job_training,
            'months': months,
            'years': years,
        }

        return render(request, "candidate_dashboard/resume/job_trainings/update_trainings.html", context)

    except JobTraining.DoesNotExist:
        # Handle the case where the job training does not exist
        # You can redirect or show an error message as needed
        pass

@user_passes_test(user_is_candidate, login_url="/login/")
@login_required
def delete_training(request, jobtraining_id):
    try:
        user_profile = UserProfile.objects.get(user=request.user)
        training_record = JobTraining.objects.get(id=jobtraining_id, user_profile=user_profile)
        training_record.delete()
    except JobTraining.DoesNotExist:
        pass

    success_message = 'Job Training deleted successfully!'
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

        # Check if the skill already exists for the user
        existing_skill = Skill.objects.filter(
            user_profile=request.user.userprofile,
            skill__iexact=skill  # Case-insensitive check
        ).first()

        if existing_skill:
            error_messages['skill'] = 'Skill already exists. Please enter a different skill.'
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

    # Fetch the count of all users who applied for each job, considering only jobs with applications
    jobs = Job.objects.filter(jobapplication__in=job_applications).annotate(application_count=Count('jobapplication'))

    # Create a list of dictionaries to store job titles and application counts
    job_counts = [{'job_title': job.job_title, 'application_count': job.application_count} for job in jobs]
    for application in job_applications:
        application.status_text = application.get_status_display()
    context = {
        "current_page": "applied_jobs",
        "job_applications": job_applications,
        "job_counts": job_counts,
    }

    return render(request, "candidate_dashboard/applied_jobs/applied_jobs.html", context)


#====================================================================================================================================================
def get_application_statistics(request, job_id):
    # Define all possible status labels
    all_status_labels = OrderedDict([
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('withdrawn', 'Withdrawn'),
    ])

    # Fetch and annotate counts for job applications
    job_applications = JobApplication.objects.filter(job_id=job_id).values('status').annotate(count=Count('status'))

    # Initialize counts for all statuses to 0
    status_counts = {status: 0 for status in all_status_labels}

    # Fill in the actual counts where available
    for entry in job_applications:
        status_counts[entry['status']] = entry['count']

    # Extract labels and counts
    labels = list(all_status_labels.values())
    counts = list(status_counts.values())

    response_data = {
        'labels': labels,
        'counts': counts,
    }

    return JsonResponse(response_data)

@user_passes_test(user_is_candidate, login_url="/login/")
@login_required
def withdraw_application(request, job_application_id):
    # Retrieve the specific job application details
    job_application = JobApplication.objects.get(pk=job_application_id)

    # Check if the current user owns the job application
    if request.user == job_application.applicant.user:
        # Update the status to "withdrawn"
        job_application.status = "withdrawn"
        job_application.save()

    # Redirect back to the job application status page
    return redirect('job_application_status', job_application_id=job_application_id)

@user_passes_test(user_is_candidate, login_url="/login/")
@login_required
def job_application_status(request, job_application_id):
    # Retrieve the specific job application details
    job_application = JobApplication.objects.get(pk=job_application_id)

    # Pass the job ID as part of the context
    job_id = job_application.job.id

    context = {
        "current_page": "applied_jobs",
        "job_application": job_application,
        "job_id": job_id,  # Pass the job ID to the template
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
#====================================================================================================================================================
@user_passes_test(user_is_employer, login_url="/login/")
@login_required
def employer_dashboard(request):
    # Get the currently logged-in user's employer profile
    employer_profile = EmployerProfile.objects.get(user_profile__user=request.user)

    # Retrieve the jobs associated with the employer
    posted_jobs = Job.objects.filter(employer_profile=employer_profile)

    # Fetch the recent job applications for these posted jobs
    recent_applications = JobApplication.objects.filter(job__in=posted_jobs).order_by('-application_date')[:5]

    context = {
        "current_page": "dashboard",
        "posted_job_count": posted_jobs.count(),
        "recent_applications": recent_applications,
    }

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


#====================================================================================================================================================

@user_passes_test(user_is_employer, login_url="/login/")
@login_required
def employer_jobs(request, job_id):
    job = get_object_or_404(Job, pk=job_id)
    context = {
        'current_page': 'manage_jobs',
        'job': job,
    }
    return render(request, 'employer_dashboard/jobs/jobs.html', context)
#====================================================================================================================================================
@user_passes_test(user_is_employer, login_url="/login/")
@login_required
def post_jobs(request):
    if request.method == 'POST':
        # Extract form data
        job_title = request.POST['job_title']
        job_description = request.POST['job_description']
        specializations = request.POST['specializations']
        other_specialization = request.POST.get('otherSpecialization', '')
        job_type = request.POST['job_type']
        job_setup = request.POST['job_setup']
        job_level = request.POST['job_level']
        experience_level = request.POST['experience_level']
        education_level = request.POST['education_level']
        educational_degree = request.POST.get('educational_degree', '')
        offered_salary = request.POST['offered_salary']
        offered_salary_other = request.POST['offered_salary_other']
        deadline_date = request.POST['deadline_date']
        region = request.POST['region']
        city = request.POST['city']
        barangay = request.POST['barangay']
        street = request.POST['street']
        job_vacancy = request.POST['job_vacancy']
        attachment = request.FILES.get('attachment')

        # Extract and process the skills_needed field
        skills_needed = request.POST.get('skills_needed', '')
        skills_needed_list = [skill.strip() for skill in skills_needed.split(',')]
        skills_needed_str = ','.join(skills_needed_list)

        # Extract and process the certification_needed field

        certification_needed = request.POST.get('certification_needed', '')
        certification_needed_list = [cert.strip() for cert in certification_needed.split(',')]
        certification_needed_str = ','.join(certification_needed_list)
        error_messages = {}

        if specializations == 'Other':
            if not other_specialization:
                error_messages['specializations'] = 'Other Specialization is required when "Other" is selected.'
            else:
                specializations = other_specialization

        if offered_salary == "TBD":
            pass
        elif offered_salary == "enter_specific":
            # Check if offered_salary_other is not empty and contains valid numeric characters
            if not offered_salary_other or not offered_salary_other.isdigit():
                error_messages['offered_salary'] = 'Offered Salary must be a number.'

        required_fields = [
            'job_title', 'job_description', 'specializations', 'job_type', 'job_setup', 'job_level',
            'experience_level', 'education_level', 'deadline_date',
            'region', 'city', 'barangay', 'street', 'job_vacancy'
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
            employer_profile=request.user.userprofile.employer_profile,
            job_title=job_title,
            job_description=job_description,
            specializations=specializations,
            job_type=job_type,
            job_setup=job_setup,
            job_level=job_level,
            experience_level=experience_level,
            education_level=education_level,
            educational_degree=educational_degree,
            offered_salary = offered_salary if offered_salary != "specific" else offered_salary_other,
            deadline_date=deadline_date,
            region=region,
            city=city,
            barangay=barangay,
            street=street,
            attachment=attachment,
            job_vacancy=job_vacancy,
            skills_needed=skills_needed_str,
            certification_needed=certification_needed_str
        )
        job.save()

        success_message = 'Job added successfully!'
        redirect_url = reverse('manage_jobs') + f'?success_message={success_message}'
        return HttpResponseRedirect(redirect_url)

    context = {
        'current_page': 'manage_jobs',
    }

    return render(request, 'employer_dashboard/jobs/post_jobs.html', context)


#====================================================================================================================================================

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
        other_specialization = request.POST.get('otherSpecialization', '')
        job_type = request.POST['job_type']
        job_setup = request.POST['job_setup']
        job_level = request.POST['job_level']
        experience_level = request.POST['experience_level']
        education_level = request.POST['education_level']
        other_education_level = request.POST.get('otherEducationLevel', '')

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
        job_vacancy = request.POST['job_vacancy']
        attachment = request.FILES.get('attachment')

        # Extract and process the skills_needed field
        skills_needed = request.POST.get('skills_needed', '')
        skills_needed_list = [skill.strip() for skill in skills_needed.split(',')]
        skills_needed_str = ','.join(skills_needed_list)

        # Extract and process the certification_needed field
        certification_needed = request.POST.get('certification_needed', '')
        certification_needed_list = [certification.strip() for certification in certification_needed.split(',')]
        certification_needed_str = ','.join(certification_needed_list)

        error_messages = {}

        if specializations == 'Other':
            if not other_specialization:
                error_messages['specializations'] = 'Other Specialization is required when "Other" is selected.'
            else:
                specializations = other_specialization
        if education_level == 'Other':
            if not other_education_level:
                error_messages['education_level'] = 'Other Education Level is required when "Other" is selected.'
            else:
                education_level = other_education_level

        if offered_salary_option == 'specific' and (not offered_salary or not offered_salary.isdigit()):
            error_messages['offered_salary'] = 'Offered Salary must be a number.'

        required_fields = [
            'job_title', 'job_description', 'specializations', 'job_type', 'job_setup', 'job_level',
            'experience_level', 'education_level', 'deadline_date',
            'region', 'city', 'barangay', 'street', 'job_vacancy'
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
        job_vacancy = job_vacancy
        if attachment:
            job.attachment = attachment
        job.skills_needed = skills_needed_str
        job.certification_needed = certification_needed_str
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

#====================================================================================================================================================

@user_passes_test(user_is_employer, login_url="/login/")
@login_required
def delete_job(request, job_id):
    try:
        user_profile = UserProfile.objects.get(user=request.user)
        job = Job.objects.get(id=job_id, employer_profile=user_profile.employer_profile)
        job.delete()
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
    job = get_object_or_404(Job, id=job_id)
    job_applications = JobApplication.objects.filter(job=job)
    applicants_data = []
    pending_applicants_data = []  # Create a list for pending applicants
    approved_applicants_data = []  # Create a list for approved applicants
    rejected_applicants_data = []  # Create a list for rejected applicants

    total_applicants_count = 0
    pending_applicants_count = 0  # Initialize the pending count to 0
    approved_applicants_count = 0  # Initialize the approved count to 0
    rejected_applicants_count = 0  # Initialize the rejected count to 0

    filter_status = request.GET.get('status')  # Get the filter status from the query parameters
    sortby = request.GET.get('sortby')
    
    if sortby == 'High to Low':
        order_by_field = '-applicant__candidateprofile__job_title'
    elif sortby == 'Low to High':   
        order_by_field = 'applicant__candidateprofile__job_title'

    if sortby:
        job_applications = job_applications.order_by(order_by_field)

    for application in job_applications:
        applicant = application.applicant
        first_name = applicant.user.first_name
        last_name = applicant.user.last_name
        job_title = applicant.candidateprofile.job_title
        profile_picture = None

        if applicant.role == 'candidate':
            candidate_profile = applicant.candidateprofile
            profile_picture = candidate_profile.profile_picture
            region = candidate_profile.region  # Access the region field

        applicant_info = {
            "id": applicant.id,
            "first_name": first_name,
            "last_name": last_name,
            "profile_picture": profile_picture,
            "job_title": job_title,
            "region": region,  # Include the region field
        }

        if application.status == 'pending':
            pending_applicants_data.append(applicant_info)  # Append pending applicants to the pending list
            pending_applicants_count += 1  # Increment pending count
        elif application.status == 'approved':
            approved_applicants_data.append(applicant_info)  # Append approved applicants to the approved list
            approved_applicants_count += 1  # Increment approved count
        elif application.status == 'rejected':
            rejected_applicants_data.append(applicant_info)  # Append rejected applicants to the rejected list
            rejected_applicants_count += 1  # Increment rejected count

        if not filter_status:  # If no filter status is specified, count as "Total"
            applicants_data.append(applicant_info)  # Append non-pending applicants to the total list
            total_applicants_count += 1  # Increment total count

    context = {
        "current_page": "applicants",
        "job": job,
        "applicants_data": applicants_data,
        "pending_applicants_data": pending_applicants_data,
        "approved_applicants_data": approved_applicants_data,
        "rejected_applicants_data": rejected_applicants_data,  # Pass the rejected applicants data to the template
        "applicants_count": total_applicants_count,
        "pending_applicants_count": pending_applicants_count,
        "approved_applicants_count": approved_applicants_count,
        "rejected_applicants_count": rejected_applicants_count,  # Pass the rejected count to the template
    }

    return render(request, "employer_dashboard/applicants/positions.html", context)



#====================================================================================================================================================
@user_passes_test(user_is_employer, login_url="/login/")
@login_required
def applicant_details(request, applicant_id, job_id):
    applicant = UserProfile.objects.get(id=applicant_id)
    candidate_profile = applicant.candidateprofile
    job = get_object_or_404(Job, id=job_id)
    employer_profile = job.employer_profile

    total_experience = WorkExperience.objects.filter(user_profile=applicant).aggregate(
        total_months=Sum(
            Case(
                When(end_month=None, end_year=None, then=ExpressionWrapper(
                    (datetime.now().year * 12 + datetime.now().month) - 
                    (F('start_year') * 12 + F('start_month')), output_field=IntegerField()
                )),
                default=ExpressionWrapper(F('end_year'), output_field=IntegerField()) * 12 +
                        ExpressionWrapper(F('end_month'), output_field=IntegerField()) -
                        ExpressionWrapper(F('start_year'), output_field=IntegerField()) * 12 -
                        ExpressionWrapper(F('start_month'), output_field=IntegerField())
            )
        )
    )['total_months']

    if total_experience is not None:
        total_experience = int(total_experience / 12)

    previous_jobs_count = WorkExperience.objects.filter(user_profile=applicant) \
        .values('company_name').distinct().count()

    job_skills = set([skill.lower() for skill in job.skills_needed.split(',')])
    applicant_skills = set([skill.skill.lower() for skill in applicant.skill_set.all()])

    common_skills = job_skills.intersection(applicant_skills)

    skills_match_percentage = (len(common_skills) / len(job_skills)) * 100 if job_skills else 0
    skills_match_percentage = round(skills_match_percentage)

    application = JobApplication.objects.filter(
        applicant=applicant,
        job=job
    ).first()

    outcome = None
    reason_for_turnover = None

    if application:
        outcome = application.outcome
        reason_for_turnover = application.risk_factors

    minutes = hours = days = months = None

    retention_score = application.retention_score

    if application:
        application_date = application.application_date
        now = datetime.now(application_date.tzinfo)
        delta = now - application_date
        minutes = int(delta.total_seconds() / 60)
        hours = int(delta.total_seconds() / 3600)
        days = int(delta.total_seconds() / (3600 * 24))
        months = int(delta.total_seconds() / (3600 * 24 * 30))

    context = {
        "current_page": "applicants",
        "applicant": applicant,
        "candidate_profile": candidate_profile,
        "job": job,
        "minutes_since_application": minutes,
        "hours_since_application": hours,
        "days_since_application": days,
        "months_since_application": months,
        "total_experience_years": total_experience,
        "previous_jobs_count": previous_jobs_count,
        "skills_match_percentage": skills_match_percentage,
        "application": application,
        "outcome": outcome,
        "reason_for_turnover": reason_for_turnover,
        "retention_score": retention_score,
        "employer_profile": employer_profile,
        # "acceptance_date": "November 25, 2023",  # Replace with the actual acceptance date
        # "acceptance_time": "10:00 AM",  # Replace with the actual acceptance time
        # "acceptance_location": "Company Office",
    }

    if request.method == 'POST':
        if 'send_email' in request.POST:
            # This block handles the form submission from the modal
            date = request.POST.get('date')
            time = request.POST.get('time')
            location = request.POST.get('location')

            # Now you can use these values as needed
            # For example, you can pass them to the context dictionary for rendering the email template
            context.update({
                "date": date,
                "time": time,
                "location": location,
            })

            # # Rest of the code to handle the email sending...
            # # Use the context to render the email body
            # if application.status == 'approved':
            #     email_body = render_to_string('employer_dashboard/applicants/accepted_email.html', context)
            # elif application.status == 'rejected':
            #     email_body = render_to_string('employer_dashboard/applicants/rejection_email.html', context)
            # else:
            #     # Handle the case where the status is neither approved nor rejected
            #     # You may want to raise an error or provide a default email template
            #     email_body = "Unsupported application status"


            if application.status == 'approved':
                subject = f"Congratulations! Your application to {employer_profile.company_name} has been accepted"
                email_body = render_to_string('employer_dashboard/applicants/accepted_email.html', context)
            elif application.status == 'rejected':
                subject = f"We regret to inform you that your application to {employer_profile.company_name} has been  rejected"
                email_body = render_to_string('employer_dashboard/applicants/rejection_email.html', context)
            else:
                # Handle the case where the status is neither approved nor rejected
                # You may want to raise an error or provide a default subject
                subject = "Application Status Update"
                email_body = "Unsupported application status"

            # Send the email using Mailgun configuration
            response = send_mail_using_mailgun(subject, email_body, [applicant.user.email])


            # Check the response and handle accordingly
            if response.status_code == 200:
                # Email sent successfully
                return redirect('applicant_details', applicant_id=applicant_id, job_id=job_id)
            else:
                # Email sending failed, handle appropriately (e.g., show an error message)
                return render(request, "error_template.html", {'error_message': 'Failed to send email'})

    return render(request, "employer_dashboard/applicants/applicant_details.html", context)

def send_mail_using_mailgun(subject, message, recipient_list):
    # Use Mailgun API to send email
    response = requests.post(
        f"https://api.mailgun.net/v3/{settings.MAILGUN_DOMAIN}/messages",
        auth=("api", settings.MAILGUN_API_KEY),
        data={
            "from": f"{settings.EMAIL_SENDER_NAME} <mailgun@{settings.MAILGUN_DOMAIN}>",
            "to": recipient_list,
            "subject": subject,
            "html": message,
        },
    )
    return response

def process_application(request, applicant_id, job_id):
    application = JobApplication.objects.filter(applicant_id=applicant_id, job_id=job_id).first()
    if application and application.status == 'pending':
        action = request.POST.get('action')
        if action == 'accept':
            application.status = 'approved'
        elif action == 'reject':
            application.status = 'rejected'
        application.save()
    return redirect('applicant_details', applicant_id=applicant_id, job_id=job_id)


def change_application_status(request, applicant_id, job_id, new_status):
    # Ensure that the new_status is one of the allowed status choices
    allowed_statuses = [choice[0] for choice in JobApplication.APPLICANT_STATUS_CHOICES]
    if new_status not in allowed_statuses:
        # Handle invalid status here, e.g., show an error message or redirect
        pass

    # Get the job application
    application = JobApplication.objects.filter(applicant__id=applicant_id, job__id=job_id).first()

    if application:
        # Update the status
        application.status = new_status
        application.save()

    # Redirect back to the applicant details page
    return redirect('applicant_details', applicant_id=applicant_id, job_id=job_id)