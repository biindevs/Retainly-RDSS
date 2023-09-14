# Generated by Django 4.2.3 on 2023-09-13 16:32

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('app', '0004_alter_userprofile_profile_picture'),
    ]

    operations = [
        migrations.CreateModel(
            name='Candidate',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('job_title', models.CharField(max_length=255)),
                ('phone', models.CharField(max_length=20)),
                ('website_link', models.URLField(blank=True, max_length=255)),
                ('current_salary', models.CharField(max_length=10)),
                ('expected_salary', models.CharField(max_length=10)),
                ('experience', models.CharField(max_length=20)),
                ('age', models.CharField(max_length=5)),
                ('education_levels', models.CharField(max_length=20)),
                ('languages', models.CharField(max_length=255)),
                ('description', models.TextField()),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='ContactInformation',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('region', models.CharField(max_length=255)),
                ('city', models.CharField(max_length=255)),
                ('barangay', models.CharField(max_length=255)),
                ('street_address', models.CharField(max_length=255)),
                ('candidate', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to='app.candidate')),
            ],
        ),
    ]