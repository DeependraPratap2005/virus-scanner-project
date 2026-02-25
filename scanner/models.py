from django.db import models

class UploadedFile(models.Model):
    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('SCANNING', 'Scanning'),
        ('CLEAN', 'Clean'),
        ('SUSPICIOUS', 'Suspicious'),
        ('FAILED', 'Failed'),
    ]

    file = models.FileField(upload_to='uploads/')
    filename = models.CharField(max_length=255)
    file_hash = models.CharField(max_length=64, unique=True)  # idempotency
    file_size = models.BigIntegerField(default=0)

    uploaded_at = models.DateTimeField(auto_now_add=True)

    scan_status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='PENDING'
    )

    detections = models.IntegerField(default=0)
    scan_report = models.TextField(blank=True, null=True)
    report_url = models.URLField(blank=True, null=True)

    provider = models.CharField(max_length=50, default="VirusTotal")
    vt_analysis_id = models.CharField(max_length=200, blank=True, null=True)

    def __str__(self):
        return self.filename