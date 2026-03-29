from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0002_vulnerability_fix_fields'),
    ]

    operations = [
        migrations.AddField(
            model_name='scan',
            name='input_method',
            field=models.CharField(
                blank=True, default='paste', max_length=10,
                choices=[('paste', 'Pasted Code'), ('upload', 'Uploaded File')]
            ),
        ),
        migrations.AlterField(
            model_name='scan',
            name='target_type',
            field=models.CharField(
                choices=[('code', 'Code / File Analysis')],
                default='code',
                max_length=10,
            ),
        ),
    ]
