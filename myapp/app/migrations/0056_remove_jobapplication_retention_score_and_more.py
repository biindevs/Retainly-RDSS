# Generated by Django 4.2.3 on 2023-11-18 16:03

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0055_job_certification_needed'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='jobapplication',
            name='retention_score',
        ),
        migrations.AddField(
            model_name='jobapplication',
            name='outcome',
            field=models.CharField(blank=True, choices=[('Turnover Risk', 'Turnover Risk'), ('Retain', 'Retain')], max_length=15, null=True),
        ),
        migrations.AddField(
            model_name='jobapplication',
            name='reason_for_turnover',
            field=models.TextField(blank=True, null=True),
        ),
    ]
