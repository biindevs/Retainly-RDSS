# Generated by Django 4.2.3 on 2023-10-17 10:39

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0045_remove_certification_certification_year_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='job',
            name='skills_needed',
            field=models.CharField(blank=True, max_length=255),
        ),
    ]
