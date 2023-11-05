from django.contrib.auth.models import User
from django.db import models
import uuid

# class Profile(models.Model):
#     user = models.OneToOneField(User, on_delete=models.CASCADE)
#     is_verified = models.BooleanField(default=False)

class VerificationToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

ROLE_CHOICES = (
    ('candidate', 'Candidate'),
    ('employer', 'Employer'),
    ('superadmin', 'Super Admin'),
)

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='candidate')
    is_verified = models.BooleanField(default=False)
    is_profile_complete = models.BooleanField(default=False)  # Added for profile completeness

    def __str__(self):
        return str(self.user)

class CandidateProfile(models.Model):
    user_profile = models.OneToOneField(UserProfile, on_delete=models.CASCADE, null=True)
    profile_picture = models.ImageField(upload_to='profile_pictures/', blank=True, null=True)
    job_title = models.CharField(max_length=255)
    phone = models.CharField(max_length=15)
    current_salary = models.CharField(max_length=10)
    expected_salary = models.CharField(max_length=10)
    experience = models.CharField(max_length=20)
    birthdate = models.DateField(null=True)
    education_levels = models.CharField(max_length=20)
    region = models.CharField(max_length=255)
    city = models.CharField(max_length=255)
    barangay = models.CharField(max_length=255)
    street_address = models.CharField(max_length=255)
    description = models.TextField()
    resume = models.FileField(upload_to='resume_files/', blank=True, null=True)
    def __str__(self):
        return str(self.user_profile.user)


class Education(models.Model):
    user_profile = models.ForeignKey(UserProfile, on_delete=models.CASCADE)
    educational_degree = models.CharField(null=True, max_length=255, verbose_name="Educational Degree")
    school_name = models.CharField(null=True, max_length=255, verbose_name="School Name")
    additional_info = models.TextField(null=True, verbose_name="Additional Information")
    start_month = models.CharField(max_length=255, verbose_name="Start Month", null=True, blank=True)
    start_year = models.IntegerField(verbose_name="Start Year", null=True, blank=True)
    end_month = models.CharField(max_length=255, verbose_name="End Month", null=True, blank=True)
    end_year = models.IntegerField(verbose_name="End Year", null=True, blank=True)

    def __str__(self):
        return self.educational_degree


class WorkExperience(models.Model):
    user_profile = models.ForeignKey(UserProfile, on_delete=models.CASCADE)
    position_title = models.CharField(max_length=255, verbose_name="Position Title")
    company_name = models.CharField(max_length=255, verbose_name="Company Name")
    work_description = models.TextField(verbose_name="Work Description")
    location_type = models.CharField(max_length=255, verbose_name="Location Type", null=True, blank=True)
    employment_type = models.CharField(max_length=255, verbose_name="Employment Type", null=True, blank=True)
    start_month = models.CharField(max_length=255, verbose_name="Start Month", null=True, blank=True)
    start_year = models.IntegerField(verbose_name="Start Year", null=True, blank=True)
    end_month = models.CharField(max_length=255, verbose_name="End Month", null=True, blank=True)
    end_year = models.IntegerField(verbose_name="End Year", null=True, blank=True)

    def __str__(self):
        return self.position_title

class Certification(models.Model):
    user_profile = models.ForeignKey(UserProfile, on_delete=models.CASCADE)
    name = models.CharField(max_length=255, verbose_name="Certification Name")
    organization = models.CharField(max_length=255, verbose_name="Issuing Organization")
    issue_year = models.IntegerField(verbose_name="Issue Year", null=True, blank=True)
    issue_month = models.CharField(max_length=255, verbose_name="Issue Month", null=True, blank=True)
    description = models.TextField(null=True, verbose_name="Description")

    def __str__(self):
        return self.name

class Skill(models.Model):
    user_profile = models.ForeignKey(UserProfile, on_delete=models.CASCADE)
    skill = models.CharField(null=True, max_length=255, verbose_name="Skill")
    expi_years = models.CharField(null=True, max_length=255, verbose_name="Years of Experience")

    def __str__(self):
        return self.skill_title


class EmployerProfile(models.Model):
    user_profile = models.OneToOneField(UserProfile, on_delete=models.CASCADE, related_name='employer_profile')
    company_name = models.CharField(max_length=255)
    phone = models.CharField(max_length=15)
    region = models.CharField(max_length=255)
    city = models.CharField(max_length=255)
    barangay = models.CharField(max_length=255)
    street = models.CharField(max_length=255)
    website_link = models.URLField()
    since_date = models.DateField()
    team_size = models.CharField(max_length=10)
    company_description = models.TextField(null=True)
    logo = models.ImageField(upload_to='employer_logos/', null=True, blank=True)

    def __str__(self):
        return self.company_name

class Job(models.Model):
    employer_profile = models.ForeignKey(EmployerProfile, on_delete=models.CASCADE, null=True)
    job_title = models.CharField(max_length=255)
    job_description = models.TextField()
    skills_needed = models.CharField(max_length=255, blank=True)
    specializations = models.CharField(max_length=255)
    job_type = models.CharField(max_length=255)
    job_setup = models.CharField(max_length=255)
    job_level = models.CharField(max_length=255)
    experience_level = models.CharField(max_length=255)
    education_level = models.CharField(max_length=255)
    offered_salary = models.CharField(max_length=255)
    deadline_date = models.DateField()
    attachment = models.FileField(upload_to='job_attachments/')
    region = models.CharField(max_length=255)
    city = models.CharField(max_length=255)
    barangay = models.CharField(max_length=255)
    street = models.CharField(max_length=255)
    created_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.job_title

class JobApplication(models.Model):
    APPLICANT_STATUS_CHOICES = (
        ('pending', 'Pending'),  # Application is pending review.
        ('approved', 'Approved'),  # Application has been approved.
        ('rejected', 'Rejected'),  # Application has been rejected.
        ('withdrawn', 'Withdrawn'),  # Applicant has withdrawn their application.
    )

    applicant = models.ForeignKey(UserProfile, on_delete=models.CASCADE)
    job = models.ForeignKey(Job, on_delete=models.CASCADE)
    application_date = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=10, choices=APPLICANT_STATUS_CHOICES, default='pending')

    def __str__(self):
        return f"{self.applicant.user} - {self.job.job_title} - {self.get_status_display()}"

