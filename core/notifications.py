from dotenv import load_dotenv
load_dotenv()

import os
import smtplib
import urllib.parse
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")

def enviar_ticket_confirmacion(correo_destino: str, detalles_reserva: dict) -> dict:
    """
    Sends the official receipt / purchase confirmation for the commercial logistics
    to the user once the agent completes the autonomous purchase with APPROVE verdict.
    Includes 1-click Google Calendar button and interactive .ics attachment.
    """
    dest = (correo_destino or "").strip()
    if not dest or "@" not in dest:
        # Nunca auto-enviarse el recibo: sin correo del titular, no hay envío.
        print("[Ticket email] Skipped: the mandate has no cardholder email; not sending the receipt to the sender itself.")
        return {"status": 200, "message": "Skipped: no recipient email on the mandate.", "sent_to": None}

    pnr = detalles_reserva.get('pnr', 'PNR-VYA-849201')
    orden_id = detalles_reserva.get('orden_id', 'ORD-8492-1570')
    destino = detalles_reserva.get('destino') or detalles_reserva.get('route') or 'Vuelo Directo Buenos Aires (AEP) -> Córdoba (COR)'
    proveedor = detalles_reserva.get('proveedor') or detalles_reserva.get('merchant') or 'VuelaYa Travel & Logistics Inc.'
    precio = detalles_reserva.get('precio_total') or detalles_reserva.get('price') or 130.00
    moneda = detalles_reserva.get('moneda') or 'USD'
    pasajero = detalles_reserva.get('pasajero') or 'Marta (Titular Autorizante)'
    id_cliente = detalles_reserva.get('candidate_id') or 'mnd_live_8492'
    token_id = detalles_reserva.get('token_id', 'vtok_849201_4242')
    
    now_utc = datetime.now(timezone.utc)
    fecha_actual = now_utc.strftime("%A, %B %d, %Y")
    hora_actual = now_utc.strftime("%I:%M %p UTC")

    # Schedule calendar event (3 days ahead at 14:00 UTC)
    event_start = now_utc + timedelta(days=3)
    event_start = event_start.replace(hour=14, minute=0, second=0, microsecond=0)
    event_end = event_start + timedelta(hours=2)
    start_str = event_start.strftime("%Y%m%dT%H%M%SZ")
    end_str = event_end.strftime("%Y%m%dT%H%M%SZ")

    cal_title = f"✈️ Flight: {destino} [{pnr}]"
    cal_details = (
        f"Reservation confirmed autonomously by Saturday Agent (Aegis Zero-Trust).\n"
        f"Booking Code (PNR): {pnr}\n"
        f"Provider: {proveedor}\n"
        f"Passenger: {pasajero}\n"
        f"Total Charged: ${precio:.2f} {moneda}\n"
        f"Payment Method: Scoped Virtual Token ({token_id})\n"
        f"Security Seal: Ed25519 & Semantic Firewall Validated.\n\n"
        f"Online check-in available 24h before departure."
    )
    cal_location = f"{destino}"

    gcal_url = (
        f"https://calendar.google.com/calendar/render?action=TEMPLATE"
        f"&text={urllib.parse.quote(cal_title)}"
        f"&dates={start_str}/{end_str}"
        f"&details={urllib.parse.quote(cal_details)}"
        f"&location={urllib.parse.quote(cal_location)}"
    )

    msg = MIMEMultipart("mixed")
    msg['Subject'] = f"Reservation Confirmation & Receipt - {pnr} - Aegis Saturday Agent"
    msg['From'] = f"Saturday Agent <{SMTP_USER}>" if SMTP_USER else "Saturday Agent <aegis@zero-trust.protocol>"
    msg['To'] = dest

    # Formal HTML template — eCommerce / Travel Logistics style
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <style>
        body {{
          background-color: #121212;
          color: #e0e0e0;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
          margin: 0;
          padding: 20px;
        }}
        .container {{
          max-width: 650px;
          margin: 0 auto;
          background-color: #1a1a1a;
          border: 1px solid #333333;
          border-radius: 8px;
          padding: 28px;
          box-shadow: 0 8px 24px rgba(0,0,0,0.6);
        }}
        .section-title {{
          font-size: 1.15rem;
          font-weight: 700;
          color: #ffffff;
          margin-bottom: 4px;
          letter-spacing: -0.01em;
        }}
        .order-number {{
          font-size: 0.95rem;
          color: #a0a0a0;
          margin-bottom: 18px;
          padding-bottom: 12px;
          border-bottom: 1px solid #333333;
        }}
        .details-grid {{
          width: 100%;
          border-collapse: collapse;
          margin-bottom: 24px;
        }}
        .details-grid td {{
          padding: 7px 0;
          vertical-align: top;
          font-size: 0.9rem;
        }}
        .details-label {{
          width: 38%;
          color: #ffffff;
          font-weight: 700;
        }}
        .details-value {{
          width: 62%;
          color: #d0d0d0;
          line-height: 1.4;
        }}
        .divider {{
          border: 0;
          height: 1px;
          background: #333333;
          margin: 24px 0;
        }}
        .invoice-table {{
          width: 100%;
          border-collapse: collapse;
          margin: 18px 0;
          font-size: 0.82rem;
          border: 1px solid #333333;
        }}
        .invoice-table th {{
          background-color: #242424;
          color: #ffffff;
          padding: 8px 6px;
          text-align: left;
          border: 1px solid #333333;
          font-weight: 600;
        }}
        .invoice-table td {{
          padding: 8px 6px;
          border: 1px solid #333333;
          color: #cccccc;
        }}
        .text-right {{
          text-align: right;
        }}
        .total-row td {{
          background-color: #222222;
          font-weight: bold;
          color: #ffffff;
        }}
        .badge-zero-trust {{
          display: inline-block;
          background-color: #1e3a8a;
          color: #93c5fd;
          padding: 2px 8px;
          border-radius: 4px;
          font-size: 0.75rem;
          font-weight: 700;
          font-family: monospace;
        }}
        .footer {{
          margin-top: 24px;
          padding-top: 14px;
          border-top: 1px solid #2a2a2a;
          font-size: 0.72rem;
          color: #777777;
          line-height: 1.5;
        }}
        .pnr-box {{
          background-color: #202b3c;
          border: 1px solid #3b82f6;
          color: #60a5fa;
          padding: 4px 8px;
          border-radius: 4px;
          font-family: monospace;
          font-weight: bold;
        }}
        .calendar-btn {{
          display: inline-block;
          background-color: #2563eb;
          color: #ffffff !important;
          text-decoration: none;
          padding: 10px 18px;
          border-radius: 6px;
          font-size: 0.85rem;
          font-weight: 700;
          border: 1px solid #3b82f6;
          box-shadow: 0 4px 12px rgba(37,99,235,0.3);
          transition: background-color 0.2s;
        }}
      </style>
    </head>
    <body>
      <div class="container">
        
        <!-- SECCIÓN 1: DETALLES DE LA RESERVA DE LOGÍSTICA / VIAJE -->
        <div class="section-title">Autonomous Purchase Details & Confirmation</div>
        <div class="order-number">Reservation Code: <strong>{pnr}</strong></div>

        <table class="details-grid">
          <tr>
            <td class="details-label">Route / Description:</td>
            <td class="details-value"><strong>{destino}</strong><br><small style="color: #38bdf8;">Autonomous AI Purchase via Saturday Agent</small></td>
          </tr>
          <tr>
            <td class="details-label">Cardholder / Passenger:</td>
            <td class="details-value">{pasajero}</td>
          </tr>
          <tr>
            <td class="details-label">Mandate ID:</td>
            <td class="details-value"><code>{id_cliente}</code></td>
          </tr>
          <tr>
            <td class="details-label">PNR / Ticket Ref:</td>
            <td class="details-value"><span class="pnr-box">{pnr}</span></td>
          </tr>
          <tr>
            <td class="details-label">Date & Time:</td>
            <td class="details-value">{fecha_actual} - {hora_actual}</td>
          </tr>
          <tr>
            <td class="details-label">Merchant & Provider:</td>
            <td class="details-value">{proveedor} (Direct Check-in Enabled)</td>
          </tr>
        </table>

        <!-- BOTÓN GOOGLE CALENDAR -->
        <div style="text-align: center; margin: 18px 0 22px; padding: 14px; background-color: #1e2638; border-radius: 6px; border: 1px solid #2d3b55;">
          <div style="font-size: 0.82rem; color: #cbd5e1; margin-bottom: 10px;">
            🗓️ Sync this itinerary directly with your calendar:
          </div>
          <a href="{gcal_url}" target="_blank" class="calendar-btn">
            📅 Add to Google Calendar
          </a>
        </div>

        <hr class="divider">

        <!-- SECCIÓN 2: INVOICE / RECIBO DETALLADO -->
        <div class="section-title">Official Receipt & Tax Invoice</div>
        <div style="font-size: 0.85rem; color: #888; margin-bottom: 12px;">
          Invoice ID: <strong>{orden_id}</strong> &nbsp;|&nbsp; Transaction Date: <strong>{fecha_actual}</strong>
        </div>

        <table style="width: 100%; font-size: 0.8rem; margin-bottom: 12px; color: #aaa;">
          <tr>
            <td style="width: 50%;">
              <strong style="color: #fff;">Merchant / Issuer:</strong><br>
              {proveedor}<br>
              Aegis Protocol Zero-Trust Settlement<br>
              Merchant ID: <code>mch_vuelaya</code>
            </td>
            <td style="width: 50%;">
              <strong style="color: #fff;">Bill To:</strong><br>
              {pasajero}<br>
              Mandate Delegation: <code>{id_cliente}</code><br>
              Authorized Off-Session Purchase
            </td>
          </tr>
        </table>

        <table class="invoice-table">
          <thead>
            <tr>
              <th style="width: 8%;">Qty</th>
              <th style="width: 20%;">Item ID</th>
              <th style="width: 36%;">Description</th>
              <th style="width: 18%;">Holder</th>
              <th style="width: 9%;" class="text-right">Unit</th>
              <th style="width: 9%;" class="text-right">Amount</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>1</td>
              <td><code>FLT-COR-130</code></td>
              <td>{destino}<br><small style="color: #22c55e;">✓ Verified by Semantic Firewall</small></td>
              <td>{pasajero}</td>
              <td class="text-right">${precio:.2f}</td>
              <td class="text-right">${precio:.2f}</td>
            </tr>
            <tr>
              <td>1</td>
              <td><code>DLP-SCOPED</code></td>
              <td>Scoped Virtual Token (<span class="badge-zero-trust">{token_id}</span>)</td>
              <td>Stripe PCI Vault</td>
              <td class="text-right">$0.00</td>
              <td class="text-right">$0.00</td>
            </tr>
            <tr>
              <td>1</td>
              <td><code>TAX-VAT</code></td>
              <td>Tax Rate: 0.00% (Mandate Surcharge 0%)</td>
              <td>Exempt</td>
              <td class="text-right">$0.00</td>
              <td class="text-right">$0.00</td>
            </tr>
            <tr class="total-row">
              <td colspan="4" style="text-align: right;">Subtotal:</td>
              <td colspan="2" class="text-right">${precio:.2f} {moneda}</td>
            </tr>
            <tr class="total-row">
              <td colspan="4" style="text-align: right;">Shipping / Fees:</td>
              <td colspan="2" class="text-right">$0.00 {moneda}</td>
            </tr>
            <tr class="total-row" style="background-color: #1e3a8a; color: #ffffff; font-size: 0.95rem;">
              <td colspan="4" style="text-align: right;">TOTAL PAID (Off-Session):</td>
              <td colspan="2" class="text-right"><strong>${precio:.2f} {moneda}</strong></td>
            </tr>
          </tbody>
        </table>

        <!-- SECCIÓN 3: SELLO CRIPTOGRÁFICO ZERO-TRUST -->
        <div style="background-color: #182230; border: 1px solid #1e3a8a; border-radius: 6px; padding: 12px; margin-top: 16px;">
          <div style="font-size: 0.78rem; font-weight: bold; color: #60a5fa; margin-bottom: 4px;">
            🛡️ CRYPTOGRAPHIC SECURITY AUDIT (ZERO-TRUST)
          </div>
          <div style="font-size: 0.72rem; color: #94a3b8; line-height: 1.4;">
            • <strong>Digital Signature:</strong> Ed25519 Asymmetric Signature Validated.<br>
            • <strong>DLP Tokenization:</strong> PAN protected. Scoped Virtual Token rotated after settlement.<br>
            • <strong>Audit Ledger:</strong> SHA-256 Merkle Block append_entry recorded on immutable ledger.
          </div>
        </div>

        <div class="footer">
          <strong>Aegis Zero-Trust Autonomous Protocol</strong> &nbsp;|&nbsp; Saturday Agentic Commerce Engine<br>
          Fiscal receipt and commercial logistics confirmation issued autonomously under active mandate delegation.
        </div>

      </div>
    </body>
    </html>
    """

    # 1. Attach HTML body
    msg.attach(MIMEText(html, 'html', 'utf-8'))

    # 2. Attach interactive iCalendar (.ics) invitation for native detection in Gmail
    ics_content = f"""BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Aegis Protocol//Saturday Agent//EN
CALSCALE:GREGORIAN
METHOD:REQUEST
BEGIN:VEVENT
UID:aegis-{pnr}-{int(now_utc.timestamp())}@zero-trust.protocol
DTSTAMP:{now_utc.strftime('%Y%m%dT%H%M%SZ')}
DTSTART:{start_str}
DTEND:{end_str}
SUMMARY:✈️ Flight: {destino} [{pnr}]
DESCRIPTION:Reservation confirmed autonomously by Saturday Agent.\\nPNR: {pnr}\\nTotal: ${precio:.2f} {moneda}\\nZero-Trust Ed25519 Seal.
LOCATION:{destino}
STATUS:CONFIRMED
ORGANIZER;CN=Saturday Agent:mailto:{SMTP_USER or 'saturday.agentbuyer@gmail.com'}
ATTENDEE;ROLE=REQ-PARTICIPANT;PARTSTAT=ACCEPTED;CN={pasajero}:mailto:{dest}
END:VEVENT
END:VCALENDAR"""

    part_ics = MIMEText(ics_content, 'calendar; method=REQUEST; charset="utf-8"', 'utf-8')
    part_ics.add_header('Content-Disposition', 'attachment; filename="itinerary-saturday.ics"')
    msg.attach(part_ics)

    current_smtp_user = os.environ.get("SMTP_USER", "")
    current_smtp_pass = os.environ.get("SMTP_PASS", "")

    if current_smtp_user and current_smtp_pass:
        try:
            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
                server.login(current_smtp_user, current_smtp_pass)
                server.send_message(msg)
            print(f"[Gmail SMTP] Official receipt with Google Calendar sent successfully to {dest}")
            return {"status": 200, "message": "Official receipt sent successfully.", "sent_to": dest}
        except Exception as e:
            print(f"SMTP warning sending receipt to {dest}: {e}")
            return {"status": 500, "message": f"SMTP error: {e}", "sent_to": dest}

    print(f"[Local Mode] Receipt generated for {dest} (PNR: {pnr})")
    return {"status": 200, "message": "Receipt generated in local mode.", "sent_to": dest}


def enviar_token_otp(correo_destino: str, codigo_otp: str) -> dict:
    """
    Sends the 6-digit Zero-Trust security token (OTP) from saturday.agentbuyer@gmail.com
    to ANY destination email address.
    """
    dest = (correo_destino or "").strip().lower()
    if not dest or "@" not in dest:
        return {"status": 400, "message": "Invalid email address."}

    smtp_user = os.environ.get("SMTP_USER", "")
    smtp_pass = os.environ.get("SMTP_PASS", "")

    msg = MIMEText(
        f"🛡️ Zero-Trust Verification Code (Aegis):\n\n"
        f"Your 6-digit security token is: {codigo_otp}\n\n"
        f"This token expires in 10 minutes. Use it to authenticate your mandate with Saturday Agent.\n"
        f"Security Seal: Ed25519 & Zero-Trust MFA.",
        "plain",
        "utf-8"
    )
    msg["Subject"] = f"Aegis Security OTP: {codigo_otp}"
    msg["From"] = f"Saturday Agent <{smtp_user}>" if smtp_user else "Saturday Agent <saturday.agentbuyer@gmail.com>"
    msg["To"] = dest

    if smtp_user and smtp_pass:
        try:
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                server.login(smtp_user, smtp_pass)
                server.sendmail(smtp_user, [dest], msg.as_string())
            print(f"[Gmail SMTP OTP] Successfully sent OTP {codigo_otp} to {dest}")
            return {"status": 200, "message": f"OTP token sent to {dest}", "sent_via": "smtp"}
        except Exception as err:
            print(f"[Gmail SMTP ERROR] Failed to send OTP to {dest}: {err}")
            return {"status": 500, "message": str(err), "sent_via": "error"}

    return {"status": 200, "message": f"OTP generated in local mode for {dest}", "sent_via": "memory"}


def leer_correos_recibidos(limite: int = 10) -> dict:
    """
    Reads the latest incoming emails received at saturday.agentbuyer@gmail.com via IMAP SSL.
    Returns a list of parsed messages with sender, subject, date, and body preview.
    """
    import imaplib
    import email
    from email.header import decode_header

    smtp_user = os.environ.get("SMTP_USER", "")
    smtp_pass = os.environ.get("SMTP_PASS", "")

    if not (smtp_user and smtp_pass):
        return {
            "status": 200,
            "connected": False,
            "total_messages": 0,
            "messages": [],
            "message": "SMTP/IMAP credentials not configured in environment."
        }

    try:
        mail = imaplib.IMAP4_SSL("imap.gmail.com", 993)
        mail.login(smtp_user, smtp_pass)
        mail.select("inbox")

        status, response = mail.search(None, "ALL")
        if status != "OK":
            mail.logout()
            return {"status": 500, "message": "Failed to search inbox."}

        email_ids = response[0].split()
        total_inbox = len(email_ids)
        recent_ids = email_ids[-limite:] if total_inbox >= limite else email_ids
        recent_ids.reverse()

        mensajes_recibidos = []
        for e_id in recent_ids:
            res, data = mail.fetch(e_id, "(RFC822)")
            if res != "OK":
                continue

            raw_email = data[0][1]
            msg = email.message_from_bytes(raw_email)

            subject_raw, encoding = decode_header(msg.get("Subject", ""))[0]
            if isinstance(subject_raw, bytes):
                subject = subject_raw.decode(encoding if encoding else "utf-8", errors="ignore")
            else:
                subject = str(subject_raw)

            from_addr = msg.get("From", "")
            date_str = msg.get("Date", "")

            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get("Content-Disposition"))
                    if content_type == "text/plain" and "attachment" not in content_disposition:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body = payload.decode("utf-8", errors="ignore")
                            break
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    body = payload.decode("utf-8", errors="ignore")

            mensajes_recibidos.append({
                "id": e_id.decode("utf-8") if isinstance(e_id, bytes) else str(e_id),
                "from": from_addr,
                "subject": subject,
                "date": date_str,
                "snippet": body[:200].strip() if body else "",
            })

        mail.close()
        mail.logout()

        return {
            "status": 200,
            "connected": True,
            "account": smtp_user,
            "total_inbox": total_inbox,
            "returned_count": len(mensajes_recibidos),
            "messages": mensajes_recibidos
        }
    except Exception as e:
        print(f"[IMAP Receive ERROR] Failed reading inbox for {smtp_user}: {e}")
        return {
            "status": 500,
            "connected": False,
            "error": str(e),
            "messages": []
        }