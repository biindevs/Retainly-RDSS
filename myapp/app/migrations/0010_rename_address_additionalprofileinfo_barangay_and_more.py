# Generated by Django 4.2.3 on 2023-09-16 06:40

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0009_additionalprofileinfo'),
    ]

    operations = [
        migrations.RenameField(
            model_name='additionalprofileinfo',
            old_name='address',
            new_name='barangay',
        ),
        migrations.RenameField(
            model_name='additionalprofileinfo',
            old_name='description',
            new_name='street_address',
        ),
    ]
