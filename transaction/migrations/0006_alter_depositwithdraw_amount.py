# Generated by Django 4.2.4 on 2023-08-29 22:03

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('transaction', '0005_depositwithdraw_withdraw_addr'),
    ]

    operations = [
        migrations.AlterField(
            model_name='depositwithdraw',
            name='amount',
            field=models.FloatField(default=0),
        ),
    ]