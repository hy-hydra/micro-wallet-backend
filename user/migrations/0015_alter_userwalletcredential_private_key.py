# Generated by Django 4.2.4 on 2024-01-23 08:48

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0014_userwalletcredential_encryption_key'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userwalletcredential',
            name='private_key',
            field=models.TextField(unique=True),
        ),
    ]
