# Generated by Django 4.2.3 on 2023-08-28 16:06

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0002_userprofile'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='userprofile',
            name='email',
        ),
        migrations.RemoveField(
            model_name='userprofile',
            name='full_name',
        ),
    ]
