# Generated by Django 4.2.2 on 2023-08-01 07:27

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('tokens', '0005_token_type'),
    ]

    operations = [
        migrations.AddField(
            model_name='usertoken',
            name='prev_balance',
            field=models.FloatField(default=0),
        ),
    ]