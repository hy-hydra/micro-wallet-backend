# Generated by Django 4.2.2 on 2023-07-26 14:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('tokens', '0004_token_created_at_token_updated_at_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='token',
            name='type',
            field=models.CharField(default='ERC20', max_length=20),
        ),
    ]