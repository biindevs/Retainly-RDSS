# Generated by Django 4.2.3 on 2023-11-02 14:43

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0049_remove_job_user_profile_job_employer_profile'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='candidateprofile',
            name='user',
        ),
        migrations.AddField(
            model_name='candidateprofile',
            name='user_profile',
            field=models.OneToOneField(null=True, on_delete=django.db.models.deletion.CASCADE, to='app.userprofile'),
        ),
    ]
