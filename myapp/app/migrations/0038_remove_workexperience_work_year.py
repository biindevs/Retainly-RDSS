# Generated by Django 4.2.3 on 2023-09-28 14:50

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0037_workexperience_employment_type_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='workexperience',
            name='work_year',
        ),
    ]