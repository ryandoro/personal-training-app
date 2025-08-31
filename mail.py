# mail.py
import os
from typing import Optional
from flask import render_template
from postmarker.core import PostmarkClient
from datetime import date

FROM = os.getenv("POSTMARK_FROM_EMAIL", "no-reply@fitbaseai.com")
STREAM = os.getenv("POSTMARK_MESSAGE_STREAM", "outbound")
SERVER_TOKEN = os.getenv("POSTMARK_SERVER_TOKEN")

postmark = PostmarkClient(server_token=SERVER_TOKEN)


def send_email(*, to: str, subject: str, html: str, text: Optional[str] = None, **pm_kwargs):
    """Low-level sender via Postmark"""
    return postmark.emails.send(
        From=FROM,
        To=to,
        Subject=subject,
        HtmlBody=html,
        TextBody=text or None,
        MessageStream=STREAM,
        **pm_kwargs
    )


# ---------- high-level helpers ----------

def send_password_reset_email(*args, **kwargs):
    """
    Compatible with BOTH usages:
      - send_password_reset_email(email, reset_url)          # positional (your routes)
      - send_password_reset_email(to_email=..., reset_url=...)  # keyword
    """
    if args and not kwargs:
        # positional: (email, reset_url)
        to_email, reset_url = args[0], args[1]
    else:
        to_email = kwargs["to_email"]
        reset_url = kwargs["reset_url"]

    subject = "Reset your FitBaseAI password"
    html = render_template("email/reset_password.html", reset_url=reset_url)
    text = (
        "You requested a password reset for your FitBaseAI account.\n\n"
        f"Reset your password: {reset_url}\n\n"
        "If you didn’t request this, you can ignore this email."
    )
    return send_email(
        to=to_email, 
        subject=subject, 
        html=html,
        text=text,
        Tag="password-reset",
        TrackLinks="None"
    )


def send_invite_email(*, to_email: str, first_name: str, invite_url: str, admin_note: Optional[str] = None):
    subject = "Your FitBaseAI invite"
    html = render_template(
        "email/invite.html",
        first_name=first_name, invite_url=invite_url, admin_note=admin_note
    )
    return send_email(to=to_email, subject=subject, html=html)


def send_verification_email(*, to_email: str, first_name: str, verify_url: str, ttl_hours: int, current_year: int | None = None, resend_url: str | None = None):
    subject = "Welcome to FitBaseAI! - Verify your email"
    if current_year is None:
        current_year = date.today().year
    html = render_template(
        "email/verify_email.html", 
        first_name=first_name, 
        verify_url=verify_url, 
        ttl_hours=int(ttl_hours),
        current_year=current_year,
        resend_url=resend_url)
    return send_email(
        to=to_email, 
        subject=subject, 
        html=html)
