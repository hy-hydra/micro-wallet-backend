# Generated by Django 4.2.2 on 2023-07-23 14:00

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0004_rename_private_address_userwalletcredential_private_key_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='refer_enabled',
            field=models.BooleanField(default=False),
        ),
    ]