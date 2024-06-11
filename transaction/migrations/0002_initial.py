# Generated by Django 4.2.2 on 2023-07-10 13:32

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('transaction', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('tokens', '0002_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='transfer',
            name='_from',
            field=models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, related_name='_from', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='transfer',
            name='_to',
            field=models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, related_name='_to', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='transfer',
            name='token',
            field=models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, to='tokens.token'),
        ),
        migrations.AddField(
            model_name='swap',
            name='get_token',
            field=models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, related_name='get_token', to='tokens.token'),
        ),
        migrations.AddField(
            model_name='swap',
            name='send_token',
            field=models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, related_name='send_token', to='tokens.token'),
        ),
        migrations.AddField(
            model_name='swap',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='depositwithdraw',
            name='token',
            field=models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, to='tokens.token'),
        ),
        migrations.AddField(
            model_name='depositwithdraw',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, to=settings.AUTH_USER_MODEL),
        ),
    ]