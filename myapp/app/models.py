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
    profile_picture = models.ImageField(upload_to='profile_pictures/', blank=True, null=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='candidate')

    def __str__(self):
        return str(self.user)


# class Candidate(models.Model):
#     user = models.OneToOneField(User, on_delete=models.CASCADE)
#     job_title = models.CharField(max_length=255)
#     phone = models.CharField(max_length=20)
#     website_link = models.URLField(max_length=255, blank=True)
#     current_salary = models.CharField(max_length=10)
#     expected_salary = models.CharField(max_length=10)
#     experience = models.CharField(max_length=20)
#     age = models.CharField(max_length=5)
#     education_levels = models.CharField(max_length=20)
#     languages = models.CharField(max_length=255)
#     description = models.TextField()

# class ContactInformation(models.Model):
#     candidate = models.OneToOneField(Candidate, on_delete=models.CASCADE)
#     region = models.CharField(max_length=255)
#     city = models.CharField(max_length=255)
#     barangay = models.CharField(max_length=255)
#     street_address = models.CharField(max_length=255)

class CandidateProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    job_title = models.CharField(max_length=255)
    phone = models.CharField(max_length=15)
    email = models.EmailField()
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

