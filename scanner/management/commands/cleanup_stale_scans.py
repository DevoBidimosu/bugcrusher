from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from scanner.models import Scan


class Command(BaseCommand):
    help = 'Mark scans stuck in "running" for over 10 minutes as failed.'

    def handle(self, *args, **options):
        cutoff = timezone.now() - timedelta(minutes=10)
        stale = Scan.objects.filter(status='running', created_at__lt=cutoff)
        count = stale.update(
            status='failed',
            error_message='Scan was automatically cleaned up after exceeding the 10-minute time limit.'
        )
        self.stdout.write(self.style.SUCCESS(f'Cleaned up {count} stale scan(s).'))
