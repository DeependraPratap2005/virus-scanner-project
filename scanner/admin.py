from django.contrib import admin
from .models import UploadedFile


@admin.register(UploadedFile)
class UploadedFileAdmin(admin.ModelAdmin):
    # Table columns
    list_display = (
        "filename",
        "scan_status",
        "detections",
        "provider",
        "uploaded_at",
    )

    # Right-side filters
    list_filter = (
        "scan_status",
        "provider",
        "uploaded_at",
    )

    # Top search box
    search_fields = (
        "filename",
    )

    # Default ordering
    ordering = ("-uploaded_at",)

    # Read-only fields (safe)
    readonly_fields = (
        "uploaded_at",
    )