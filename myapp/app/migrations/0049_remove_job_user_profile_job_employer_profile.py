# Generated by Django 4.2.3 on 2023-10-27 14:34

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0048_userprofile_is_profile_complete_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='job',
            name='user_profile',
        ),
        migrations.AddField(
            model_name='job',
            name='employer_profile',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='app.employerprofile'),
        ),
    ]
