# Generated by Django 4.2.4 on 2024-01-19 09:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0012_user_iqdt_payout_amount'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='reward_amount',
            field=models.FloatField(default=0),
        ),
    ]