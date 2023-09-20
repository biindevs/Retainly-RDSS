from django.contrib.auth.models import User
from django.db import models
import uuid

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    is_verified = models.BooleanField(default=False)

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

    def __str__(self):
        return str(self.user)

class CandidateProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    profile_picture = models.ImageField(upload_to='profile_pictures/', blank=True, null=True)
    job_title = models.CharField(max_length=255)
    phone = models.CharField(max_length=15)
    current_salary = models.CharField(max_length=10)
    expected_salary = models.CharField(max_length=10)
    experience = models.CharField(max_length=20)
    age = models.IntegerField()
    education_levels = models.CharField(max_length=20)
    region = models.CharField(max_length=255)
    city = models.CharField(max_length=255)
    barangay = models.CharField(max_length=255)
    street_address = models.CharField(max_length=255)
    description = models.TextField()

    def __str__(self):
        return str(self.user)

class Education(models.Model):
    user_profile = models.ForeignKey(UserProfile, on_delete=models.CASCADE)
    educational_degree = models.CharField(null=True, max_length=255, verbose_name="Educational Degree")
    year = models.IntegerField(choices=[(str(year), str(year)) for year in range(2010, 2022)], verbose_name="Year")
    school_name = models.CharField(null=True, max_length=255, verbose_name="School Name")
    additional_info = models.TextField(null=True, verbose_name="Additional Information")

    def __str__(self):
        return self.educational_degree


class WorkExperience(models.Model):
    user_profile = models.ForeignKey(UserProfile, on_delete=models.CASCADE)
    position_title = models.CharField(max_length=255, verbose_name="Position Title")
    work_year = models.IntegerField(choices=[(str(year), str(year)) for year in range(2010, 2022)], verbose_name="Year")
    company_name = models.CharField(max_length=255, verbose_name="Company Name")
    work_description = models.TextField(verbose_name="Work Description")

    def __str__(self):
        return self.position_title


class Award(models.Model):
    user_profile = models.ForeignKey(UserProfile, on_delete=models.CASCADE)
    role = models.CharField(null=True, max_length=255, verbose_name="Role")
    award_year = models.IntegerField(choices=[(str(year), str(year)) for year in range(2010, 2022)], verbose_name="Year")
    award_name = models.CharField(max_length=255, verbose_name="Award Name")
    award_description = models.TextField(verbose_name="Award Description")

    def __str__(self):
        return self.award_title


class Skill(models.Model):
    user_profile = models.ForeignKey(UserProfile, on_delete=models.CASCADE)
    skill = models.CharField(null=True, max_length=255, verbose_name="Skill")
    mastery_level = models.CharField(null=True, max_length=255, verbose_name="Skill Mastery")

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