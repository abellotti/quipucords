# Generated by Django 4.2.5 on 2023-10-09 14:09

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0040_alter_credential_cred_type_alter_source_source_type"),
    ]

    operations = [
        migrations.AddField(
            model_name="systemfingerprint",
            name="installed_products",
            field=models.JSONField(blank=True, null=True),
        ),
    ]