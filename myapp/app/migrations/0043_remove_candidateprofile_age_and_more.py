# Generated by Django 4.2.3 on 2023-09-30 10:41

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0042_certification_description'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='candidateprofile',
            name='age',
        ),
        migrations.AddField(
            model_name='candidateprofile',
            name='birthdate',
            field=models.DateField(null=True),
        ),
    ]
