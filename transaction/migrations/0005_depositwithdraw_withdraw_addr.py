# Generated by Django 4.2.2 on 2023-08-11 02:36

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('transaction', '0004_depositwithdraw_status'),
    ]

    operations = [
        migrations.AddField(
            model_name='depositwithdraw',
            name='withdraw_addr',
            field=models.CharField(default='0x9DB6aEA4299EdB66eD65607056484cc9586d909b', max_length=50),
        ),
    ]
