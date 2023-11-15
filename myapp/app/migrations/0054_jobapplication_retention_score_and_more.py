# Generated by Django 4.2.3 on 2023-11-12 13:46

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0053_job_job_vacancy'),
    ]

    operations = [
        migrations.AddField(
            model_name='jobapplication',
            name='retention_score',
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name='jobapplication',
            name='risk_factors',
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name='jobapplication',
            name='turnover_risk_flag',
            field=models.BooleanField(default=False),
        ),
    ]
