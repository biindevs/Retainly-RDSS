# Generated by Django 4.2.3 on 2023-09-29 13:00

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0040_remove_education_year_education_end_month_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='certification',
            name='year',
            field=models.IntegerField(choices=[(2010, 2010), (2011, 2011), (2012, 2012), (2013, 2013), (2014, 2014), (2015, 2015), (2016, 2016), (2017, 2017), (2018, 2018), (2019, 2019), (2020, 2020), (2021, 2021)], verbose_name='Issue Date'),
        ),
    ]
