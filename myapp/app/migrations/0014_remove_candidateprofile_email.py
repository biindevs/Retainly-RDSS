# Generated by Django 4.2.3 on 2023-09-16 19:41

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0013_remove_contactinformation_candidate_delete_candidate_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='candidateprofile',
            name='email',
        ),
    ]