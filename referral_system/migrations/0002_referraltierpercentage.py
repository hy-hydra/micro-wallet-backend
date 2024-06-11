# Generated by Django 4.2.2 on 2023-07-22 08:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('referral_system', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='ReferralTierPercentage',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('first_tier', models.FloatField(default=45)),
                ('second_tier', models.FloatField(default=30)),
                ('third_tier', models.FloatField(default=10)),
            ],
        ),
    ]
