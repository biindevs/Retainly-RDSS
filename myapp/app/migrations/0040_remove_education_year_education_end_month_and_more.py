# Generated by Django 4.2.3 on 2023-09-29 08:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0039_remove_workexperience_end_date_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='education',
            name='year',
        ),
        migrations.AddField(
            model_name='education',
            name='end_month',
            field=models.CharField(blank=True, max_length=255, null=True, verbose_name='End Month'),
        ),
        migrations.AddField(
            model_name='education',
            name='end_year',
            field=models.IntegerField(blank=True, null=True, verbose_name='End Year'),
        ),
        migrations.AddField(
            model_name='education',
            name='start_month',
            field=models.CharField(blank=True, max_length=255, null=True, verbose_name='Start Month'),
        ),
        migrations.AddField(
            model_name='education',
            name='start_year',
            field=models.IntegerField(blank=True, null=True, verbose_name='Start Year'),
        ),
    ]