# Generated by Django 4.2.2 on 2023-08-11 02:07

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('transaction', '0003_rename_value_transfer_amount_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='depositwithdraw',
            name='status',
            field=models.IntegerField(default=1),
        ),
    ]
