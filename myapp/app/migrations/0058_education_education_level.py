# Generated by Django 4.2.3 on 2023-11-19 06:30

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0057_remove_jobapplication_reason_for_turnover_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='education',
            name='education_level',
            field=models.CharField(choices=[('High School Diploma', 'High School Diploma'), ("Associate's Degree", "Associate's Degree"), ("Bachelor's Degree", "Bachelor's Degree"), ("Master's Degree", "Master's Degree"), ('Doctorate Degree', 'Doctorate Degree')], max_length=20, null=True, verbose_name='Education Level'),
        ),
    ]
