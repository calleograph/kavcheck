"""Доверенные сертификаты удостоверяющих центров для LDAPS.

Принимаются PEM (один или несколько сертификатов, файлом или текстом) и DER. Перед сохранением сертификат разбирается: Subject, Issuer,
серийный номер, отпечаток SHA-256, срок действия, признак CA. Закрытые ключи и контейнеры с ключами (PKCS#12) отклоняются целиком:
такие данные не сохраняются и не журналируются."""
from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID

MAX_UPLOAD = 256 * 1024
MAX_CERTS = 20
_PEM = re.compile(rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.S)
_PRIVATE = re.compile(rb"PRIVATE KEY|ENCRYPTED PRIVATE|BEGIN RSA PRIVATE|BEGIN EC PRIVATE|BEGIN OPENSSH PRIVATE|BEGIN PGP", re.I)


class CertError(Exception):
    """Ошибка разбора сертификата: текст безопасен для показа."""


@dataclass
class CertInfo:
    subject: str
    issuer: str
    serial: str
    sha256: str
    not_before: datetime
    not_after: datetime
    is_ca: bool
    self_signed: bool
    pem: str

    def public(self) -> dict:
        now = datetime.now(timezone.utc)
        return {"subject": self.subject, "issuer": self.issuer, "serial": self.serial, "sha256": self.sha256, "not_before": self.not_before, "not_after": self.not_after,
                "is_ca": self.is_ca, "self_signed": self.self_signed, "expired": self.not_after < now, "not_yet_valid": self.not_before > now, "type": kind_label(self.is_ca, self.self_signed)}


def kind_label(is_ca: bool, self_signed: bool) -> str:
    if is_ca and self_signed:
        return "корневой CA (Root CA)"
    if is_ca:
        return "промежуточный CA (Intermediate CA)"
    return "самоподписанный сертификат (не CA)" if self_signed else "сертификат сервера (не CA)"


def _info(cert: x509.Certificate) -> CertInfo:
    der = cert.public_bytes(serialization.Encoding.DER)
    try:
        is_ca = bool(cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca)
    except x509.ExtensionNotFound:
        is_ca = False
    nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=timezone.utc)
    na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
    return CertInfo(subject=cert.subject.rfc4514_string(), issuer=cert.issuer.rfc4514_string(), serial=format(cert.serial_number, "X"),
                    sha256=hashlib.sha256(der).hexdigest(), not_before=nb, not_after=na, is_ca=is_ca, self_signed=cert.subject == cert.issuer,
                    pem=cert.public_bytes(serialization.Encoding.PEM).decode("ascii"))


def parse(data: bytes) -> list[CertInfo]:
    if not data or not data.strip():
        raise CertError("Файл пуст.")
    if len(data) > MAX_UPLOAD:
        raise CertError("Слишком большой файл для сертификата (больше 256 КБ).")
    if _PRIVATE.search(data):
        raise CertError("В данных есть закрытый ключ. Закрытые ключи загружать нельзя — загрузите только сертификат (открытую часть).")
    if data[:2] == b"\x30\x82" and b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x0c" in data[:200]:
        raise CertError("Это контейнер PKCS#12 (PFX) с закрытым ключом. Загрузите сертификат в формате PEM или DER.")
    blocks = _PEM.findall(data)
    certs: list[x509.Certificate] = []
    try:
        if blocks:
            for b in blocks[:MAX_CERTS + 1]:
                certs.append(x509.load_pem_x509_certificate(b))
        else:
            certs.append(x509.load_der_x509_certificate(data))
    except ValueError:
        raise CertError("Не удалось прочитать сертификат: ожидается PEM (-----BEGIN CERTIFICATE-----) или DER.") from None
    if len(certs) > MAX_CERTS:
        raise CertError(f"В одном файле больше {MAX_CERTS} сертификатов.")
    seen, out = set(), []
    for c in certs:
        i = _info(c)
        if i.sha256 not in seen:
            seen.add(i.sha256)
            out.append(i)
    return out


def decode_body(body: dict) -> bytes:
    """{"pem": "текст"} либо {"data_base64": "…"} (файл, в том числе DER)."""
    if isinstance(body.get("pem"), str) and body["pem"].strip():
        return body["pem"].encode("utf-8", "ignore")
    raw = body.get("data_base64")
    if isinstance(raw, str) and raw:
        try:
            return base64.b64decode(raw, validate=False)
        except Exception:  # noqa: BLE001
            raise CertError("Файл передан в неверной кодировке.") from None
    raise CertError("Вставьте сертификат текстом PEM или выберите файл.")
