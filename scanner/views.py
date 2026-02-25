import time
import hashlib
import os

from django.conf import settings
from django.db import models
from django.db.models import Count
from django.http import HttpResponse
from django.shortcuts import render, redirect, get_object_or_404

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import inch

from .models import UploadedFile
from .virustotal import (
    get_file_report,
    upload_file_for_scan,
    wait_for_analysis,
    extract_stats_from_file_report,
    extract_stats_from_analysis,
    VTError,
)

ALLOWED_EXT = {".pdf", ".jpg", ".jpeg", ".png"}


def _human_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    kb = n / 1024
    if kb < 1024:
        return f"{kb:.1f} KB"
    mb = kb / 1024
    return f"{mb:.2f} MB"


def home(request):
    files = UploadedFile.objects.all().order_by("-uploaded_at")

    stats = UploadedFile.objects.aggregate(
        total=Count("id"),
        clean=Count("id", filter=models.Q(scan_status="CLEAN")),
        suspicious=Count("id", filter=models.Q(scan_status="SUSPICIOUS")),
        pending=Count("id", filter=models.Q(scan_status="PENDING")),
        scanning=Count("id", filter=models.Q(scan_status="SCANNING")),
        failed=Count("id", filter=models.Q(scan_status="FAILED")),
    )

    return render(
        request,
        "scanner/home.html",
        {
            "files": files,
            "stats": stats,
            "max_mb": settings.MAX_UPLOAD_SIZE_MB,
        },
    )


def upload_file(request):
    if request.method != "POST":
        return redirect("home")

    f = request.FILES.get("file")
    if not f:
        return redirect("home")

    ext = os.path.splitext(f.name.lower())[1]
    if ext not in ALLOWED_EXT:
        return redirect("home")

    if f.size > settings.MAX_UPLOAD_SIZE_BYTES:
        return redirect("home")

    # SHA256
    file_data = f.read()
    sha256 = hashlib.sha256(file_data).hexdigest()
    f.seek(0)

    # Idempotency
    if UploadedFile.objects.filter(file_hash=sha256).exists():
        return redirect("home")

    obj = UploadedFile.objects.create(
        file=f,
        filename=f.name,
        file_hash=sha256,
        file_size=f.size,
        scan_status="SCANNING",
        scan_report="Scanning started...",
        provider="VirusTotal",
    )

    api_key = settings.VT_API_KEY

    # 🧪 MOCK MODE
    if not api_key or api_key == "dummy_key_for_now":
        time.sleep(1)
        obj.scan_status = "CLEAN"
        obj.detections = 0
        obj.provider = "MOCK_SCANNER"
        obj.scan_report = "Mock scan completed successfully."
        obj.report_url = None
        obj.save()
        return redirect("home")

    # 🌐 REAL VIRUSTOTAL
    try:
        report = get_file_report(api_key, sha256)
        if report:
            mal, susp, harmless, link = extract_stats_from_file_report(report)
            detections = mal + susp
            obj.detections = detections
            obj.scan_status = "SUSPICIOUS" if detections > 0 else "CLEAN"
            obj.scan_report = f"VT stats: malicious={mal}, suspicious={susp}"
            obj.report_url = link
            obj.save()
            return redirect("home")

        analysis_id = upload_file_for_scan(api_key, obj.file.path)
        obj.vt_analysis_id = analysis_id
        obj.save(update_fields=["vt_analysis_id"])

        analysis = wait_for_analysis(api_key, analysis_id, timeout_seconds=20)
        if not analysis:
            obj.scan_status = "SCANNING"
            obj.scan_report = "Scan in progress. Please refresh."
            obj.save()
            return redirect("home")

        mal, susp = extract_stats_from_analysis(analysis)
        detections = mal + susp
        obj.detections = detections
        obj.scan_status = "SUSPICIOUS" if detections > 0 else "CLEAN"
        obj.scan_report = f"VT analysis: malicious={mal}, suspicious={susp}"
        obj.report_url = f"https://www.virustotal.com/gui/file/{sha256}"
        obj.save()
        return redirect("home")

    except Exception as e:
        obj.scan_status = "FAILED"
        obj.scan_report = str(e)
        obj.save()
        return redirect("home")


def refresh_status(request, file_id):
    obj = get_object_or_404(UploadedFile, id=file_id)

    if obj.scan_status not in ("SCANNING", "PENDING"):
        return redirect("home")

    api_key = settings.VT_API_KEY

    if not api_key or api_key == "dummy_key_for_now":
        obj.scan_status = "CLEAN"
        obj.provider = "MOCK_SCANNER"
        obj.scan_report = "Mock refresh successful."
        obj.save()
        return redirect("home")

    try:
        report = get_file_report(api_key, obj.file_hash)
        if report:
            mal, susp, harmless, link = extract_stats_from_file_report(report)
            detections = mal + susp
            obj.detections = detections
            obj.scan_status = "SUSPICIOUS" if detections > 0 else "CLEAN"
            obj.scan_report = f"VT stats: malicious={mal}, suspicious={susp}"
            obj.report_url = link
            obj.save()
            return redirect("home")

        obj.scan_status = "SCANNING"
        obj.scan_report = "Still scanning..."
        obj.save()
        return redirect("home")

    except Exception as e:
        obj.scan_status = "FAILED"
        obj.scan_report = str(e)
        obj.save()
        return redirect("home")


def download_report(request, file_id):
    obj = get_object_or_404(UploadedFile, id=file_id)

    response = HttpResponse(content_type="application/pdf")
    response["Content-Disposition"] = (
        f'attachment; filename="{obj.filename}_scan_report.pdf"'
    )

    doc = SimpleDocTemplate(response, pagesize=A4)
    styles = getSampleStyleSheet()

    elements = [
        Paragraph("Virus Scan Report", styles["Title"]),
        Spacer(1, 0.2 * inch),
    ]

    data = [
        ["File Name", obj.filename],
        ["SHA256", obj.file_hash],
        ["File Size", _human_size(obj.file_size)],
        ["Uploaded At", str(obj.uploaded_at)],
        ["Provider", obj.provider],
        ["Status", obj.scan_status],
        ["Detections", str(obj.detections)],
        ["Report URL", obj.report_url or "-"],
    ]

    table = Table(data, colWidths=[2 * inch, 4.5 * inch])
    table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )

    elements.extend(
        [
            table,
            Spacer(1, 0.3 * inch),
            Paragraph("<b>Scan Summary</b>", styles["Heading2"]),
            Paragraph(obj.scan_report or "-", styles["BodyText"]),
        ]
    )

    doc.build(elements)
    return response