"""Отправка почты по SMTP (стандартная библиотека, блокирующий вызов выносится в поток).

Ошибки делятся на временные (сеть, 4xx — повторить позже) и постоянные (неверный пароль, 5xx на адрес — повтор бесполезен). «Принято сервером» — не доставка и не прочтение.
Пароль и содержимое писем в журналы не попадают."""
from __future__ import annotations

import asyncio
import re
import smtplib
import ssl
import uuid
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid

from .settings import SmtpSettings


@dataclass
class SendResult:
    ok: bool
    transient: bool = False
    error: str = ""
    refused: dict[str, str] = field(default_factory=dict)       # адрес → ответ сервера
    message_id: str = ""


def _scrub(text: str, password: str) -> str:
    t = str(text)
    if password:
        t = t.replace(password, "***")
    return re.sub(r"\s+", " ", t)[:400]


def _connect(cfg: SmtpSettings) -> smtplib.SMTP:
    ctx = ssl.create_default_context()
    if not cfg.verify_cert:
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    if cfg.security == "ssl":
        s: smtplib.SMTP = smtplib.SMTP_SSL(cfg.host, cfg.port, timeout=cfg.timeout_s, context=ctx)
    else:
        s = smtplib.SMTP(cfg.host, cfg.port, timeout=cfg.timeout_s)
    try:
        s.ehlo()
        if cfg.security == "starttls":
            s.starttls(context=ctx)
            s.ehlo()
        if cfg.username:
            s.login(cfg.username, cfg.password)
    except Exception:
        s.close()            # соединение не оставляем висеть при ошибке входа или TLS
        raise
    return s


def classify(exc: Exception, password: str = "") -> SendResult:
    msg = _scrub(exc, password)
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return SendResult(False, False, f"Сервер отклонил имя или пароль ({exc.smtp_code}). Проверьте учётные данные.")
    if isinstance(exc, UnicodeEncodeError):
        return SendResult(False, False, "Имя пользователя или пароль содержат символы вне ASCII, которые протокол SMTP AUTH библиотеки не передаёт. Используйте пароль из латинских символов и цифр.")
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        refused = {a: _scrub(v[1].decode(errors="replace") if isinstance(v[1], bytes) else v[1], password) for a, v in exc.recipients.items()}
        perm = all(500 <= v[0] < 600 for v in exc.recipients.values())
        return SendResult(False, not perm, "Сервер отклонил всех получателей", refused)
    if isinstance(exc, smtplib.SMTPResponseException):
        return SendResult(False, 400 <= exc.smtp_code < 500, f"Ответ сервера {exc.smtp_code}: {_scrub(exc.smtp_error.decode(errors='replace') if isinstance(exc.smtp_error, bytes) else exc.smtp_error, password)}")
    if isinstance(exc, (ssl.SSLError, ssl.CertificateError)):
        return SendResult(False, False, f"Ошибка TLS: {msg}. Проверьте режим шифрования, порт и сертификат сервера.")
    if isinstance(exc, (smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError, ConnectionError, TimeoutError, OSError)):
        return SendResult(False, True, f"Нет соединения с сервером почты: {msg}")
    return SendResult(False, True, f"Ошибка отправки: {type(exc).__name__}: {msg}")


def check_config(cfg: SmtpSettings) -> str | None:
    if not cfg.host:
        return "Не указан сервер SMTP"
    if not cfg.from_addr:
        return "Не указан адрес отправителя"
    return None


def _test_connection(cfg: SmtpSettings) -> SendResult:
    try:
        s = _connect(cfg)
        s.noop()
        s.quit()
        return SendResult(True)
    except Exception as exc:  # noqa: BLE001
        return classify(exc, cfg.password)


def _send(cfg: SmtpSettings, msg: EmailMessage, rcpts: list[str]) -> SendResult:
    try:
        s = _connect(cfg)
        try:
            refused = s.send_message(msg, from_addr=cfg.from_addr, to_addrs=rcpts)
        finally:
            try:
                s.quit()
            except Exception:  # noqa: BLE001
                pass
        bad = {a: _scrub(v[1].decode(errors="replace") if isinstance(v[1], bytes) else v[1], cfg.password) for a, v in (refused or {}).items()}
        return SendResult(True, refused=bad, message_id=msg["Message-ID"] or "")
    except Exception as exc:  # noqa: BLE001
        return classify(exc, cfg.password)


async def test_connection(cfg: SmtpSettings) -> SendResult:
    err = check_config(cfg)
    if err:
        return SendResult(False, False, err)
    return await asyncio.to_thread(_test_connection, cfg)


async def send(cfg: SmtpSettings, msg: EmailMessage, rcpts: list[str]) -> SendResult:
    err = check_config(cfg)
    if err:
        return SendResult(False, False, err)
    if not rcpts:
        return SendResult(False, False, "Нет получателей")
    return await asyncio.to_thread(_send, cfg, msg, rcpts)


def compose(cfg: SmtpSettings, *, to: list[str], cc: list[str], subject: str, text: str, html: str, attachments: list[tuple[str, bytes, str]] | None = None) -> EmailMessage:
    """Письмо: краткая сводка читается прямо в теле (текст и HTML), подробности — во вложениях."""
    msg = EmailMessage()
    msg["Subject"] = subject.replace("\r", " ").replace("\n", " ")[:200]
    msg["From"] = formataddr((cfg.from_name, cfg.from_addr))
    msg["To"] = ", ".join(to)
    if cc:
        msg["Cc"] = ", ".join(cc)
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(idstring=uuid.uuid4().hex[:12], domain=(cfg.from_addr.split("@")[-1] or "localhost"))
    msg["X-Auto-Response-Suppress"] = "All"
    msg["Auto-Submitted"] = "auto-generated"
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")
    for name, data, mime in attachments or []:
        main, _, sub = mime.partition("/")
        msg.add_attachment(data, maintype=main, subtype=sub or "octet-stream", filename=name)
    return msg
