# Generated by Django 4.2.3 on 2023-09-20 19:12

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0025_alter_employerprofile_table'),
    ]

    operations = [
        migrations.AddField(
            model_name='employerprofile',
            name='logo',
            field=models.ImageField(blank=True, null=True, upload_to='employer_logos/'),
        ),
    ]
