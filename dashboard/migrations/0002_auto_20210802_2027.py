# Generated by Django 2.2.22 on 2021-08-02 20:27

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='target',
            name='Name',
        ),
        migrations.AddField(
            model_name='target',
            name='Url',
            field=models.CharField(default='', max_length=255),
        ),
    ]