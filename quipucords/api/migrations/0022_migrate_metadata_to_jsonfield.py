# Generated by Django 3.2.17 on 2023-03-16 15:07

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0021_migrate_hosts_and_exclude_hosts_jsonfield"),
    ]

    operations = [
        migrations.AlterField(
            model_name="systemfingerprint",
            name="metadata",
            field=models.JSONField(null=True),
        ),
    ]
