# Generated by Django 4.2.3 on 2023-09-20 14:30

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0022_remove_skill_skill_mastery_skill_mastery_level'),
    ]

    operations = [
        migrations.CreateModel(
            name='EmployerProfile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('company_name', models.CharField(max_length=255)),
                ('phone', models.CharField(max_length=15)),
                ('region', models.CharField(max_length=255)),
                ('city', models.CharField(max_length=255)),
                ('barangay', models.CharField(max_length=255)),
                ('street', models.CharField(max_length=255)),
                ('website_link', models.URLField()),
                ('since_date', models.DateField()),
                ('team_size', models.CharField(max_length=10)),
                ('user_profile', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='employer_profile', to='app.userprofile')),
            ],
        ),
    ]