"""
Ingestor for raw email files (.eml).
"""

from __future__ import annotations

import email
import logging
import time
from email import policy
from pathlib import Path

from dateutil import parser as date_parser

from vigil.ingestors.base import BaseIngestor
from vigil.models import LogEntry, LogType

logger = logging.getLogger("vigil.ingestors.email_parser")


class EmailParser(BaseIngestor):
    """
    Ingestor for raw email messages (.eml).

    Parses email headers, body content, and detects attachments.
    Prepares text for deep AI social engineering/phishing audits.
    """

    def can_ingest(self, filepath: Path) -> bool:
        # Check by extension or basic MIME header signatures
        if filepath.suffix.lower() not in (".eml", ".msg"):
            return False
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                head = [f.readline() for _ in range(5)]
            return self.detect_format(head)
        except Exception:
            return False

    def detect_format(self, sample_lines: list[str]) -> bool:
        combined = "".join(sample_lines).lower()
        # Common email headers
        return "from:" in combined and ("subject:" in combined or "date:" in combined or "to:" in combined)

    def ingest(self, filepath: Path) -> list[LogEntry]:
        source_name = filepath.name

        try:
            with open(filepath, "rb") as f:
                # Use standard Python email parser with default policy (SMTP/RFC822 rules)
                msg = email.message_from_binary_file(f, policy=policy.default)
        except Exception as e:
            logger.error(f"Failed to read/parse email {source_name}: {e}")
            return []

        # Extract headers
        sender = msg.get("from", "")
        receiver = msg.get("to", "")
        subject = msg.get("subject", "")
        date_str = msg.get("date", "")
        reply_to = msg.get("reply-to", "")
        return_path = msg.get("return-path", "")

        # Parse date
        timestamp = None
        if date_str:
            try:
                timestamp = date_parser.parse(str(date_str)).timestamp()
            except Exception:
                timestamp = time.time()

        # Extract body content
        body_text = ""
        html_text = ""
        attachments = []

        # Iterate through MIME parts
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = part.get_content_disposition()

            # Handle attachments
            if content_disposition == "attachment" or part.get_filename():
                filename = part.get_filename() or "unnamed_attachment"
                attachments.append({
                    "filename": filename,
                    "content_type": content_type,
                    "size": len(part.get_payload(decode=True) or b""),
                })
                continue

            # Handle textual body
            if content_type == "text/plain":
                try:
                    payload = part.get_payload(decode=True)
                    body_text += payload.decode(part.get_content_charset() or "utf-8", errors="ignore")
                except Exception:
                    pass
            elif content_type == "text/html":
                try:
                    payload = part.get_payload(decode=True)
                    html_text += payload.decode(part.get_content_charset() or "utf-8", errors="ignore")
                except Exception:
                    pass

        # Use plain text as primary, fall back to clean html text if plain text is empty
        final_body = body_text if body_text.strip() else html_text

        # Create structured metadata
        metadata = {
            "from": sender,
            "to": receiver,
            "subject": subject,
            "reply_to": reply_to,
            "return_path": return_path,
            "body": final_body,
            "attachments": attachments,
            "has_attachments": len(attachments) > 0,
        }

        # Build raw summary line
        raw_summary = (
            f"Email | From: {sender} | To: {receiver} | Subject: {subject} | "
            f"Attachments: {', '.join([a['filename'] for a in attachments]) or 'None'}"
        )

        entry = LogEntry(
            timestamp=timestamp,
            action="email_received",
            raw_line=raw_summary,
            line_number=0,
            source_file=source_name,
            log_type=LogType.EMAIL,
            metadata=metadata,
        )

        return [entry]
