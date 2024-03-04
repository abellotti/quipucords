# Generated by Django 4.2.10 on 2024-02-28 22:14

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0049_inspectresult_tasks"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="taskinspectionresult",
            name="job_inspection_result",
        ),
        migrations.RemoveField(
            model_name="inspectresult",
            name="task_inspection_result",
        ),
        migrations.RemoveField(
            model_name="scanjob",
            name="inspection_results",
        ),
        migrations.RemoveField(
            model_name="scantask",
            name="inspection_result",
        ),
        migrations.DeleteModel(
            name="JobInspectionResult",
        ),
        migrations.DeleteModel(
            name="TaskInspectionResult",
        ),
        migrations.AlterField(
            model_name="scantask",
            name="connection_result",
            field=models.OneToOneField(
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                to="api.taskconnectionresult",
            ),
        ),
        migrations.AlterField(
            model_name="scantask",
            name="source",
            field=models.ForeignKey(
                null=True, on_delete=django.db.models.deletion.SET_NULL, to="api.source"
            ),
        ),
    ]