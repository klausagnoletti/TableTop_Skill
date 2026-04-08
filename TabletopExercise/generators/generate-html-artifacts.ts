/**
 * HTML/CSS template renderer for UI-heavy artifact subtypes.
 *
 * AI diffusion models produce fuzzy, unreadable text when asked to render
 * phishing emails, ransomware notes, log viewers, etc. These templates inject
 * artifact_content verbatim so text is always accurate and legible at any zoom.
 *
 * Routing:
 *   HTML template  — phishing_email, ransomware_note, fraudulent_invoice,
 *                    network_capture, dark_web_listing, scada_interface
 *   AI provider    — usb_device, network_diagram, period_photograph,
 *                    portrait, location_illustration, cover_art
 */

import type { ImageSubtype, VisualStyle } from './schema.ts';

// ---------------------------------------------------------------------------
// HTML subtype set (caller checks this before deciding which path to take)
// ---------------------------------------------------------------------------

const HTML_SUBTYPES = new Set<ImageSubtype>([
  'phishing_email',
  'ransomware_note',
  'fraudulent_invoice',
  'network_capture',
  'dark_web_listing',
  'scada_interface',
  'browser_popup',
  'azure_ad_signin',
  'vpn_gateway_log',
  'windows_event_log',
  'edr_process_tree',
  'memory_forensics',
  'itsm_ticket',
  'threat_intel_report',
  'ti_enrichment',
  'dlp_dashboard',
  'reverse_engineering',
  'certificate_viewer',
]);

export function isHtmlSubtype(subtype: ImageSubtype): boolean {
  return HTML_SUBTYPES.has(subtype);
}

// ---------------------------------------------------------------------------
// Shared utility
// ---------------------------------------------------------------------------

function esc(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Normalise content so both real newlines and literal \n sequences split correctly. */
function splitLines(content: string): string[] {
  return content.replace(/\\n/g, '\n').split('\n').filter(l => l.trim());
}

/** Split content on '---' into sections; each section is an array of lines. */
function parseSections(content: string): string[][] {
  return content.replace(/\\n/g, '\n').split(/\n---\n/).map(
    section => section.split('\n').filter(l => l.trim())
  );
}

/** Parse pipe-delimited line into trimmed fields. */
function pipeFields(line: string): string[] {
  return line.split('|').map(f => f.trim());
}

// ---------------------------------------------------------------------------
// Phishing email — macOS/Outlook mail client chrome
// ---------------------------------------------------------------------------

function renderPhishingEmail(title: string, content: string): string {
  const lines = splitLines(content);
  const bodyHtml = lines.map(l => `<p>${esc(l)}</p>`).join('') || '<p>(no content)</p>';
  const previewText = esc(lines[0] ?? '');

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f0f0f0}
.client{display:flex;height:600px;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.2)}
.sidebar{width:200px;background:#2c2c2e;color:#aaa;font-size:12px;padding:16px 0;flex-shrink:0}
.sidebar .account{padding:8px 16px 16px;border-bottom:1px solid #3a3a3c}
.sidebar .account .name{color:#fff;font-weight:600;font-size:13px}
.folder{padding:6px 16px;cursor:pointer;display:flex;justify-content:space-between}
.folder.active{background:#3a3a3c;color:#fff;border-radius:4px;margin:0 8px;padding:6px 8px}
.badge{background:#3b82f6;color:#fff;border-radius:10px;padding:1px 6px;font-size:10px}
.list{width:260px;border-right:1px solid #e5e7eb;overflow-y:auto;flex-shrink:0}
.list-item{padding:12px 16px;border-bottom:1px solid #f3f4f6;cursor:pointer}
.list-item.selected{background:#eff6ff}
.list-item .sender{font-weight:600;font-size:13px;color:#111}
.list-item .subject{font-size:12px;color:#374151;margin-top:2px}
.list-item .preview{font-size:11px;color:#9ca3af;margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.list-item .time{float:right;font-size:11px;color:#9ca3af}
.email{flex:1;overflow-y:auto;padding:24px}
.email-header{border-bottom:1px solid #e5e7eb;padding-bottom:16px;margin-bottom:16px}
.email-subject{font-size:18px;font-weight:700;color:#111;margin-bottom:12px}
.meta{font-size:12px;color:#6b7280;line-height:1.8}
.meta .field{display:flex;gap:8px}
.meta .label{color:#9ca3af;width:50px;flex-shrink:0}
.from-domain{color:#ef4444;font-weight:600}
.warning-banner{background:#fef3c7;border:1px solid #fbbf24;border-radius:4px;padding:8px 12px;margin-bottom:16px;font-size:12px;color:#92400e;display:flex;gap:8px;align-items:center}
.email-body{font-size:14px;line-height:1.6;color:#374151}
.email-body p{margin-bottom:.8em}
.cta-button{display:inline-block;background:#2563eb;color:#fff;padding:10px 20px;border-radius:4px;text-decoration:none;font-weight:600;font-size:14px;margin:12px 0}
</style></head><body>
<div class="client">
  <div class="sidebar">
    <div class="account">
      <div class="name">user@company.com</div>
      <div style="font-size:11px;margin-top:2px">iCloud Mail</div>
    </div>
    <div class="folder active">Inbox <span class="badge">3</span></div>
    <div class="folder">Sent</div>
    <div class="folder">Drafts</div>
    <div class="folder">Junk Mail</div>
    <div class="folder">Trash</div>
  </div>
  <div class="list">
    <div class="list-item selected">
      <span class="time">10:34 AM</span>
      <div class="sender">IT Security Team</div>
      <div class="subject">${esc(title)}</div>
      <div class="preview">${previewText}</div>
    </div>
    <div class="list-item">
      <span class="time">Yesterday</span>
      <div class="sender">HR Department</div>
      <div class="subject">Q4 Review Reminder</div>
      <div class="preview">Please complete your self-assessment by...</div>
    </div>
    <div class="list-item">
      <span class="time">Mon</span>
      <div class="sender">IT Helpdesk</div>
      <div class="subject">Scheduled Maintenance</div>
      <div class="preview">Systems will be unavailable Saturday 2–4 AM...</div>
    </div>
  </div>
  <div class="email">
    <div class="email-header">
      <div class="email-subject">${esc(title)}</div>
      <div class="meta">
        <div class="field"><span class="label">From:</span> <span>IT-Security-Team@<span class="from-domain">it-security-company-alerts.net</span></span></div>
        <div class="field"><span class="label">To:</span> <span>user@company.com</span></div>
        <div class="field"><span class="label">Date:</span> <span>Today, 10:34 AM</span></div>
        <div class="field"><span class="label">Subject:</span> <span>${esc(title)}</span></div>
      </div>
    </div>
    <div class="warning-banner">&#9888; This message may be a phishing attempt. The sender domain does not match your organisation.</div>
    <div class="email-body">
      ${bodyHtml}
      <br><a class="cta-button" href="#">Verify Account Now &#8594;</a>
    </div>
  </div>
</div>
</body></html>`;
}

// ---------------------------------------------------------------------------
// Ransomware note — full-bleed dark splash screen
// ---------------------------------------------------------------------------

function renderRansomwareNote(title: string, content: string): string {
  const lines = splitLines(content);
  const bodyHtml = lines.map(l => `<div class="line">${esc(l)}</div>`).join('')
    || '<div class="line">All your files have been encrypted with military-grade encryption. Pay the ransom to recover them.</div>';

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a0a;color:#f0f0f0;font-family:'Courier New',Courier,monospace;min-height:600px;display:flex;align-items:center;justify-content:center}
.note{width:100%;max-width:700px;padding:40px}
.skull{font-size:60px;text-align:center;margin-bottom:20px}
h1{font-size:28px;color:#ef4444;text-transform:uppercase;letter-spacing:3px;text-align:center;margin-bottom:8px;text-shadow:0 0 20px rgba(239,68,68,.5)}
.subtitle{font-size:14px;color:#f97316;text-align:center;letter-spacing:2px;margin-bottom:32px}
.body{font-size:13px;line-height:1.8;color:#d1d5db;margin-bottom:28px}
.body .line{margin-bottom:4px}
.box{border:1px solid #374151;background:#111;border-radius:4px;padding:16px;margin-bottom:20px}
.box-label{font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px}
.box-value{font-size:12px;color:#10b981;word-break:break-all}
.timer{text-align:center;color:#ef4444;font-size:20px;letter-spacing:4px;margin:24px 0}
.timer-label{font-size:11px;color:#6b7280;text-align:center;text-transform:uppercase;letter-spacing:2px}
.footer{text-align:center;font-size:11px;color:#4b5563;margin-top:32px}
</style></head><body>
<div class="note">
  <div class="skull">&#9760;</div>
  <h1>${esc(title)}</h1>
  <div class="subtitle">&#9888; CRITICAL SECURITY ALERT &#9888;</div>
  <div class="body">${bodyHtml}</div>
  <div class="box">
    <div class="box-label">Bitcoin Payment Address</div>
    <div class="box-value">bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh</div>
  </div>
  <div class="box">
    <div class="box-label">Your Unique Decryption Key ID</div>
    <div class="box-value">DCRYPT-A7F3B9C2-E1D4F8A6</div>
  </div>
  <div class="timer-label">Time Remaining to Pay</div>
  <div class="timer">71:58:43</div>
  <div class="footer">Do not rename files &middot; Do not use third-party recovery tools &middot; Contact: support@darkmail.onion</div>
</div>
</body></html>`;
}

// ---------------------------------------------------------------------------
// Fraudulent invoice — white paper with invoice layout
// ---------------------------------------------------------------------------

function renderFraudulentInvoice(title: string, content: string): string {
  const contentHtml = esc(content.trim()) || 'Professional consulting services rendered per agreement.';

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Arial,sans-serif;background:#f8f8f8;padding:24px}
.page{background:#fff;max-width:680px;margin:0 auto;padding:40px;box-shadow:0 2px 8px rgba(0,0,0,.1)}
.header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:32px}
.logo-box{width:120px;height:50px;background:#e5e7eb;border:2px dashed #9ca3af;display:flex;align-items:center;justify-content:center;font-size:11px;color:#6b7280}
.invoice-title{text-align:right}
.invoice-title h1{font-size:32px;color:#1e3a8a;letter-spacing:2px}
.invoice-title .num{font-size:14px;color:#374151;margin-top:4px}
.parties{display:flex;gap:40px;margin-bottom:28px;font-size:13px}
.party h3{font-size:11px;text-transform:uppercase;color:#6b7280;letter-spacing:1px;margin-bottom:6px}
.party p{line-height:1.6;color:#374151}
.party .company{font-weight:700;color:#111}
table{width:100%;border-collapse:collapse;margin-bottom:20px;font-size:13px}
thead tr{background:#1e3a8a;color:#fff}
thead th{padding:8px 12px;text-align:left;font-weight:600}
tbody tr:nth-child(even){background:#f9fafb}
tbody td{padding:8px 12px;border-bottom:1px solid #e5e7eb;color:#374151}
.totals{margin-left:auto;width:260px;font-size:13px;border-collapse:collapse}
.totals td{padding:6px 12px}
.totals tr:last-child{background:#1e3a8a;color:#fff;font-weight:700;font-size:15px}
.bank{margin-top:24px;padding:16px;background:#eff6ff;border-left:4px solid #3b82f6;font-size:12px;color:#374151;line-height:1.8}
.bank h4{color:#1e40af;margin-bottom:6px}
.notes{margin-top:16px;font-size:12px;color:#374151;padding:12px;background:#f9fafb;border:1px solid #e5e7eb;border-radius:4px;line-height:1.6}
.footer{margin-top:24px;font-size:11px;color:#9ca3af;text-align:center;border-top:1px solid #e5e7eb;padding-top:12px}
</style></head><body>
<div class="page">
  <div class="header">
    <div class="logo-box">COMPANY LOGO</div>
    <div class="invoice-title">
      <h1>INVOICE</h1>
      <div class="num">Invoice #: INV-20847</div>
      <div class="num">Date: 28/02/2026</div>
      <div class="num">Due: 30/03/2026</div>
    </div>
  </div>
  <div class="parties">
    <div class="party">
      <h3>From</h3>
      <p class="company">GlobalTech Solutions Ltd</p>
      <p>123 Business Park<br>London, EC2A 4NE<br>VAT: GB123456789</p>
    </div>
    <div class="party">
      <h3>Bill To</h3>
      <p class="company">Your Company Inc.</p>
      <p>456 Corporate Drive<br>Manchester, M1 5AN</p>
    </div>
  </div>
  <div style="font-weight:600;font-size:14px;margin-bottom:8px;color:#111">${esc(title)}</div>
  <table>
    <thead>
      <tr><th>#</th><th>Description</th><th>Qty</th><th>Unit Price</th><th>Amount</th></tr>
    </thead>
    <tbody>
      <tr><td>1</td><td>Professional Services — Q1 Retainer</td><td>1</td><td>$4,750.00</td><td>$4,750.00</td></tr>
      <tr><td>2</td><td>Expenses &amp; Disbursements</td><td>1</td><td>$950.00</td><td>$950.00</td></tr>
    </tbody>
  </table>
  <table class="totals">
    <tr><td>Subtotal:</td><td style="text-align:right">$5,700.00</td></tr>
    <tr><td>VAT (20%):</td><td style="text-align:right">$1,140.00</td></tr>
    <tr><td>AMOUNT DUE:</td><td style="text-align:right">$6,840.00</td></tr>
  </table>
  <div class="notes"><strong>Notes:</strong> ${contentHtml}</div>
  <div class="bank">
    <h4>Payment Instructions</h4>
    Bank: HSBC UK &middot; Sort Code: 40-00-01 &middot; Account: 12345678<br>
    Reference: INV-20847 &middot; Payment due within 30 days
  </div>
  <div class="footer">Please make payment to the account above &middot; Late payments subject to 8% interest &middot; Registered in England &amp; Wales</div>
</div>
</body></html>`;
}

// ---------------------------------------------------------------------------
// Network capture — dark Wireshark/Splunk table
// ---------------------------------------------------------------------------

function renderNetworkCapture(title: string, content: string): string {
  const lines = splitLines(content);

  const protocols = ['TCP', 'TLS', 'HTTP', 'DNS', 'ICMP'] as const;
  const protocolColors: Record<string, string> = {
    TCP: '#dbeafe', TLS: '#d1fae5', HTTP: '#fef3c7', DNS: '#f3e8ff', ICMP: '#fee2e2',
  };

  const dataLines = lines.length > 0 ? lines : [
    'SYN -> 203.0.113.42:443 [suspicious outbound]',
    'TLS ClientHello -> 203.0.113.42:443',
    'HTTP GET /config.php?id=exfil HTTP/1.1',
    'DNS query: evil.example.com A?',
    'ICMP Echo Request -> 10.0.0.254',
    'HTTP POST /upload?token=abc123',
    'TCP FIN -> 203.0.113.42:443',
  ];

  const rows = dataLines.slice(0, 20).map((line, i) => {
    const ipMatch = line.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
    const src = ipMatch ? ipMatch[1] : `192.0.2.${10 + i}`;
    const dst = i % 3 === 0 ? '203.0.113.42' : `10.0.0.${i + 1}`;
    const proto = protocols[i % protocols.length];
    const bg = protocolColors[proto];
    const ts = (i * 0.347).toFixed(3);
    return `<tr style="background:${bg}">
      <td>${i + 1}</td><td>${ts}</td><td>${esc(src)}</td>
      <td>${esc(dst)}</td><td>${proto}</td>
      <td style="max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(line.slice(0, 80))}</td>
    </tr>`;
  });

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#1a1a2e;font-family:'Courier New',monospace;font-size:12px}
.toolbar{background:#16213e;padding:8px 16px;display:flex;gap:16px;align-items:center;border-bottom:1px solid #0f3460}
.toolbar .title{color:#a78bfa;font-weight:700;font-size:14px}
.btn{background:#0f3460;color:#94a3b8;padding:3px 10px;border-radius:3px;font-size:11px}
.filter-bar{background:#16213e;padding:6px 16px;display:flex;gap:8px;align-items:center;border-bottom:1px solid #1e293b}
.filter-bar input{background:#0f3460;border:1px solid #334155;color:#94a3b8;padding:4px 8px;border-radius:3px;font-size:11px;width:300px;font-family:inherit}
.apply{background:#7c3aed;color:#fff;padding:4px 10px;border-radius:3px;font-size:11px;cursor:pointer}
.stats{background:#16213e;padding:4px 16px;font-size:11px;color:#64748b;border-bottom:1px solid #1e293b}
table{width:100%;border-collapse:collapse}
thead tr{background:#0f3460}
thead th{color:#94a3b8;padding:6px 8px;text-align:left;font-size:11px;font-weight:600;border-right:1px solid #1e293b}
tbody tr{border-bottom:1px solid rgba(255,255,255,.05)}
tbody td{padding:4px 8px;color:#1e293b;font-size:11px}
.packet-detail{background:#0f1629;padding:12px 16px;border-top:2px solid #334155;color:#94a3b8;font-size:11px}
.packet-detail h3{color:#a78bfa;margin-bottom:8px;font-size:12px}
</style></head><body>
<div class="toolbar">
  <span class="title">Wireshark &#183; ${esc(title)}</span>
  <span class="btn">File</span><span class="btn">Edit</span><span class="btn">View</span>
  <span class="btn">Capture</span><span class="btn">Analyze</span>
  <span style="margin-left:auto;color:#ef4444;font-size:11px">&#9679; Live Capture</span>
</div>
<div class="filter-bar">
  <span style="color:#94a3b8;font-size:11px">Filter:</span>
  <input value="ip.addr == 203.0.113.0/24 or http">
  <span class="apply">Apply</span>
  <span class="btn" style="margin-left:8px">Clear</span>
</div>
<div class="stats">${rows.length} packets captured &middot; Elapsed: 00:04:23 &middot; Interface: eth0</div>
<table>
  <thead><tr><th>No.</th><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Info</th></tr></thead>
  <tbody>${rows.join('')}</tbody>
</table>
<div class="packet-detail">
  <h3>Packet Details</h3>
  <div>&gt; Frame 1 (54 bytes on wire)</div>
  <div>&gt; Ethernet II, Src: 00:11:22:33:44:55</div>
  <div>&gt; Internet Protocol, Src: 192.0.2.10, Dst: 203.0.113.42</div>
  <div>&gt; Transmission Control Protocol, Src Port: 54312, Dst Port: 443</div>
</div>
</body></html>`;
}

// ---------------------------------------------------------------------------
// Dark web listing — terminal green-on-black
// ---------------------------------------------------------------------------

function renderDarkWebListing(title: string, content: string): string {
  const lines = splitLines(content);
  const bodyHtml = lines.map(l => `<div class="line">${esc(l)}</div>`).join('')
    || '<div class="line">Sensitive corporate data available for purchase. Premium quality verified dump. Sample provided on request via secure channel.</div>';

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#000;color:#00ff41;font-family:'Courier New',Courier,monospace;font-size:13px;padding:16px;min-height:600px}
.prompt{color:#666;margin-bottom:8px}
.header{border:1px solid #00ff41;padding:12px;margin-bottom:16px}
.header-top{display:flex;justify-content:space-between;margin-bottom:8px}
.site-name{font-size:18px;font-weight:700;text-shadow:0 0 10px rgba(0,255,65,.5)}
.site-tag{color:#888;font-size:11px}
.nav{display:flex;gap:16px;font-size:11px;color:#00aa28;border-top:1px solid #003310;padding-top:8px;margin-top:8px}
.nav .active{color:#00ff41;text-decoration:underline}
.listing{border:1px solid #003310;padding:16px;margin-bottom:12px}
.listing-header{display:flex;justify-content:space-between;margin-bottom:12px}
.listing-title{color:#00ff41;font-size:16px;font-weight:700}
.listing-id{color:#666;font-size:11px}
.meta-row{display:flex;gap:24px;margin-bottom:12px;font-size:12px}
.meta-label{color:#555;text-transform:uppercase;font-size:10px;letter-spacing:1px}
.meta-value{color:#00cc33}
.meta-value.red{color:#ff4444}
.body{line-height:1.7;color:#00cc33;margin-bottom:12px}
.price-box{border:1px solid #00ff41;padding:12px;display:flex;justify-content:space-between;align-items:center}
.price{font-size:20px;font-weight:700}
.buy-btn{background:#00ff41;color:#000;padding:6px 20px;font-weight:700;font-size:12px;letter-spacing:1px}
.footer{color:#333;font-size:11px;margin-top:16px;border-top:1px solid #111;padding-top:8px}
.handle{color:#ff8c00}
.tag{background:#003310;color:#00aa28;padding:2px 6px;margin-right:4px;font-size:10px}
</style></head><body>
<div class="prompt">[tor@anon ~]$ lynx http://breach4sale7z2sxj.onion</div>
<div class="header">
  <div class="header-top">
    <div class="site-name">BreachMarket [v3.1]</div>
    <div class="site-tag">[ Verified &middot; PGP Required &middot; XMR Only ]</div>
  </div>
  <div style="color:#555;font-size:11px;margin-bottom:6px">Anonymous &middot; Secure &middot; No Logs &middot; Since 2019</div>
  <div class="nav">
    <span>Home</span><span>New Listings</span>
    <span class="active">Data Dumps</span>
    <span>Credentials</span><span>Contact</span>
  </div>
</div>
<div class="listing">
  <div class="listing-header">
    <div class="listing-title">${esc(title)}</div>
    <div class="listing-id">#LST-D4C9E2F1</div>
  </div>
  <div class="meta-row">
    <div><div class="meta-label">Seller</div><div class="meta-value handle">@d4rkspectr3</div></div>
    <div><div class="meta-label">Posted</div><div class="meta-value">2 days ago</div></div>
    <div><div class="meta-label">Views</div><div class="meta-value">847</div></div>
    <div><div class="meta-label">Verified</div><div class="meta-value red">&#10003; VERIFIED</div></div>
    <div><div class="meta-label">Escrow</div><div class="meta-value">Available</div></div>
  </div>
  <div style="margin-bottom:10px">
    <span class="tag">Corporate</span><span class="tag">Finance</span>
    <span class="tag">PII</span><span class="tag">Credentials</span>
  </div>
  <div class="body">${bodyHtml}</div>
  <div class="price-box">
    <div>
      <div style="font-size:11px;color:#555">ASKING PRICE</div>
      <div class="price">2.5 XMR</div>
    </div>
    <div class="buy-btn">[ BUY NOW ]</div>
  </div>
</div>
<div class="footer">[ Report &middot; PGP Key &middot; Dispute ] &middot; Use TAILS OS &middot; Route through 3+ hops</div>
</body></html>`;
}

// ---------------------------------------------------------------------------
// SCADA/ICS HMI interface — industrial control panel
// ---------------------------------------------------------------------------

function renderScadaInterface(title: string, content: string): string {
  const lines = splitLines(content);

  const severities = ['CRITICAL', 'WARNING', 'ALARM', 'WARNING'] as const;
  const severityColors: Record<string, string> = {
    CRITICAL: '#ef4444', WARNING: '#f59e0b', ALARM: '#f97316',
  };

  const dataLines = lines.length > 0 ? lines : [
    'Pressure sensor PV-101: value out of range (142.3 bar)',
    'Temperature TX-202 exceeds threshold: 87.4°C',
    'Flow meter FM-305: communication failure',
    'Valve V-107: position feedback mismatch',
  ];

  const alarmRows = dataLines.slice(0, 8).map((line, i) => {
    const sev = severities[i % severities.length];
    const color = severityColors[sev];
    const timeOffset = i * 73000;
    const t = new Date(1741356187000 - timeOffset);
    const timeStr = `${String(t.getUTCHours()).padStart(2,'0')}:${String(t.getUTCMinutes()).padStart(2,'0')}:${String(t.getUTCSeconds()).padStart(2,'0')}`;
    return `<tr>
      <td style="color:${color};font-weight:700">${sev}</td>
      <td>${esc(line.slice(0, 70))}</td>
      <td>${timeStr}</td>
      <td style="color:${color}">ACTIVE</td>
    </tr>`;
  });

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#2d2d2d;font-family:Arial,sans-serif;font-size:12px;color:#e0e0e0}
.titlebar{background:#1a1a1a;padding:6px 16px;display:flex;justify-content:space-between;align-items:center;border-bottom:2px solid #555}
.titlebar .logo{font-size:14px;font-weight:700;color:#f59e0b;letter-spacing:2px}
.status-ok{color:#22c55e}
.status-alarm{color:#ef4444}
.main{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;padding:12px}
.gauge-panel{background:#3a3a3a;border:1px solid #555;border-radius:4px;padding:12px}
.gauge-panel .title{font-size:11px;color:#aaa;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px}
.gauge{width:80px;height:80px;border-radius:50%;margin:0 auto 8px;display:flex;align-items:center;justify-content:center;font-size:16px;font-weight:700}
.gauge-ok{background:radial-gradient(circle,#16a34a,#15803d);color:#fff;box-shadow:0 0 15px rgba(22,163,74,.5)}
.gauge-warn{background:radial-gradient(circle,#d97706,#b45309);color:#fff;box-shadow:0 0 15px rgba(217,119,6,.5)}
.gauge-crit{background:radial-gradient(circle,#dc2626,#991b1b);color:#fff;box-shadow:0 0 15px rgba(220,38,38,.8)}
.gauge-label{text-align:center;font-size:11px;color:#aaa}
.gauge-value{text-align:center;font-size:13px;font-weight:700;color:#e0e0e0}
.process-panel{grid-column:1/-1;background:#3a3a3a;border:1px solid #555;border-radius:4px;padding:12px}
.process-panel h3{color:#f59e0b;font-size:13px;margin-bottom:8px;border-bottom:1px solid #555;padding-bottom:4px}
.alarm-table{width:100%;border-collapse:collapse;font-size:11px}
.alarm-table th{background:#1a1a1a;padding:5px 8px;text-align:left;color:#aaa;border-bottom:1px solid #555}
.alarm-table td{padding:5px 8px;border-bottom:1px solid #404040}
.hmi-title{grid-column:1/-1;background:#1a3a5c;border:1px solid #2563eb;border-radius:4px;padding:8px 16px;display:flex;justify-content:space-between;align-items:center}
.hmi-title h2{color:#60a5fa;font-size:15px;letter-spacing:1px}
.hmi-title .time{color:#94a3b8;font-size:11px}
</style></head><body>
<div class="titlebar">
  <div class="logo">&#9881; SCADA HMI v4.2</div>
  <div style="font-size:11px">
    <span class="status-alarm">&#9679; ALARM STATE</span>
    &middot; PLC: <span class="status-ok">ONLINE</span>
    &middot; Historian: <span class="status-ok">ONLINE</span>
  </div>
</div>
<div class="main">
  <div class="hmi-title">
    <h2>${esc(title)}</h2>
    <div class="time">Last Update: 14:23:07 &middot; Operator: OPS-02</div>
  </div>
  <div class="gauge-panel">
    <div class="title">Pressure PV-101</div>
    <div class="gauge gauge-crit">142</div>
    <div class="gauge-label">bar</div>
    <div class="gauge-value">OVER LIMIT</div>
  </div>
  <div class="gauge-panel">
    <div class="title">Temperature TX-202</div>
    <div class="gauge gauge-warn">87</div>
    <div class="gauge-label">&deg;C</div>
    <div class="gauge-value">HIGH</div>
  </div>
  <div class="gauge-panel">
    <div class="title">Flow FM-305</div>
    <div class="gauge gauge-ok">--</div>
    <div class="gauge-label">m&sup3;/h</div>
    <div class="gauge-value">COMM FAULT</div>
  </div>
  <div class="process-panel">
    <h3>Active Alarms &amp; Events</h3>
    <table class="alarm-table">
      <thead><tr><th>Severity</th><th>Description</th><th>Time</th><th>Status</th></tr></thead>
      <tbody>${alarmRows.join('')}</tbody>
    </table>
  </div>
</div>
</body></html>`;
}


// ---------------------------------------------------------------------------
// Browser popup -- fake software update / installer dialog
// ---------------------------------------------------------------------------

function renderBrowserPopup(title: string, content: string): string {
  const lines = splitLines(content);

  // Parse structure: first line = brand, second = product, rest = message + small print
  const brand = esc(lines[0] ?? title);
  const product = esc(lines[1] ?? '');

  // Find [ Button ] line if present
  const btnIdx = lines.findIndex((l, i) => i >= 2 && /^\[.+\]$/.test(l.trim()));
  const msgLines = btnIdx >= 0 ? lines.slice(2, btnIdx) : lines.slice(2, Math.max(2, lines.length - 2));
  const smallLines = btnIdx >= 0 ? lines.slice(btnIdx + 1) : lines.slice(Math.max(2, lines.length - 2));
  const btnLabel = btnIdx >= 0 ? esc(lines[btnIdx].replace(/^\[|\]$/g, '').trim()) : 'Install Now';

  // Extract domain for address bar (first URL-like token in content)
  const domainMatch = content.match(/(?:Download source|download source|Source):\s*(\S+)/i)
    ?? content.match(/([a-z0-9][a-z0-9-]*(?:\.[a-z]{2,}){1,3}\/\S*)/i)
    ?? content.match(/([a-z0-9][a-z0-9-]*\.[a-z]{2,}(?:\.[a-z]{2,})?)/i);
  const domain = domainMatch ? esc(domainMatch[1].split('\n')[0].trim()) : 'update-server.net';

  const msgHtml = msgLines.map(l => `<p>${esc(l)}</p>`).join('') || '<p>Update required to continue.</p>';
  const smallHtml = smallLines.map(l => `<div>${esc(l)}</div>`).join('');

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#e8e8e8;display:flex;align-items:center;justify-content:center;min-height:500px;font-family:Arial,sans-serif}
.popup{border:1px solid #cccccc;border-radius:8px;max-width:480px;width:100%;overflow:hidden;box-shadow:0 4px 16px rgba(0,0,0,.25)}
.titlebar{background:#f1f3f4;border-bottom:1px solid #cccccc;padding:.4rem .8rem;font-size:.78em;color:#555;display:flex;justify-content:space-between;align-items:center}
.close{color:#888;font-size:14px;cursor:default}
.body{padding:1.8rem 2rem 1.4rem;text-align:center;background:#fff}
.logo{font-size:1.6em;font-weight:700;color:#cc0000;letter-spacing:.05em;margin-bottom:.2rem}
.product{font-size:.9em;color:#666;margin-bottom:1rem}
.message{font-size:1em;margin-bottom:1.4rem;line-height:1.5;color:#222}
.message p{margin-bottom:.4em}
.button{display:inline-block;background:#cc0000;color:#fff;padding:.55rem 2rem;border-radius:4px;font-weight:700;font-size:.95em;text-decoration:none;cursor:default}
.smallprint{font-size:.65em;color:#999;margin-top:1rem;word-break:break-all;line-height:1.6}
</style></head><body>
<div class="popup">
  <div class="titlebar">
    <span>${domain}</span>
    <span class="close">&#10005;</span>
  </div>
  <div class="body">
    <div class="logo">${brand}</div>
    ${product ? `<div class="product">${product}</div>` : ''}
    <div class="message">${msgHtml}</div>
    <div class="button">${btnLabel}</div>
    ${smallHtml ? `<div class="smallprint">${smallHtml}</div>` : ''}
  </div>
</div>
</body></html>`;
}

// ---------------------------------------------------------------------------
// Azure AD Identity Protection — sign-in logs
// ---------------------------------------------------------------------------

function renderAzureAdSignin(title: string, content: string): string {
  const lines = splitLines(content);

  const defaultRows = [
    '2026-04-07 08:12:33|j.smith@contoso.com|Outlook Mobile|198.51.100.14|Success|Low|Password|Yes|Granted',
    '2026-04-07 08:15:01|a.jones@contoso.com|Azure Portal|203.0.113.88|Failure|High|Password|No|Blocked',
    '2026-04-07 08:22:47|m.chen@contoso.com|SharePoint Online|192.0.2.201|Success|None|FIDO2|Yes|Granted',
    '2026-04-07 08:31:19|j.smith@contoso.com|Teams|198.51.100.14|Success|Medium|Password|Yes|Granted',
    '2026-04-07 08:45:02|s.kumar@contoso.com|Exchange Online|203.0.113.42|Failure|High|Password|No|Blocked',
  ];

  const dataLines = lines.length > 0 ? lines : defaultRows;

  const riskColor = (r: string): string => {
    const rl = r.toLowerCase();
    if (rl === 'high') return '#e81123';
    if (rl === 'medium') return '#c19c00';
    if (rl === 'low') return '#107c10';
    return '#888';
  };

  const rows = dataLines.slice(0, 20).map((line, i) => {
    const f = pipeFields(line);
    const risk = f[5] ?? 'None';
    const bg = i % 2 === 0 ? '#fff' : '#f5f5f5';
    return `<tr style="background:${bg}">
      <td>${esc(f[0] ?? '')}</td><td>${esc(f[1] ?? '')}</td><td>${esc(f[2] ?? '')}</td>
      <td>${esc(f[3] ?? '')}</td><td>${esc(f[4] ?? '')}</td>
      <td><span style="background:${riskColor(risk)};color:#fff;padding:2px 8px;border-radius:3px;font-size:11px">${esc(risk)} Risk</span></td>
      <td>${esc(f[6] ?? '')}</td><td>${esc(f[7] ?? '')}</td><td>${esc(f[8] ?? '')}</td>
    </tr>`;
  });

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#fff;color:#111;font-family:'Segoe UI',sans-serif;font-size:13px;border:1px solid #ddd}
.breadcrumb{background:#f5f5f5;padding:10px 20px;font-size:12px;color:#555;border-bottom:1px solid #ddd}
.breadcrumb span{color:#0078d4}
.filter-bar{background:#fafafa;padding:8px 20px;display:flex;gap:12px;align-items:center;border-bottom:1px solid #ddd;font-size:12px;color:#555}
.filter-bar .pill{background:#eee;padding:3px 10px;border-radius:12px;font-size:11px;color:#333}
table{width:100%;border-collapse:collapse}
thead tr{background:#f5f5f5}
thead th{padding:8px 10px;text-align:left;font-size:11px;color:#222;font-weight:600;border-bottom:1px solid #ddd}
tbody td{padding:6px 10px;font-size:12px;color:#111;border-bottom:1px solid #ddd}
.title-bar{background:#0078d4;padding:12px 20px;color:#fff;font-weight:600;font-size:15px}
</style></head><body>
<div class="title-bar">${esc(title)}</div>
<div class="breadcrumb">Microsoft Entra ID &gt; <span>Sign-in logs</span></div>
<div class="filter-bar">
  <span>Filter:</span>
  <span class="pill">Last 24 hours</span>
  <span class="pill">All users</span>
  <span class="pill">All applications</span>
  <span style="margin-left:auto;color:#0078d4">${rows.length} results</span>
</div>
<table>
  <thead><tr><th>Date/Time</th><th>User</th><th>Application</th><th>IP Address</th><th>Status</th><th>Risk Level</th><th>Auth Method</th><th>MFA</th><th>Conditional Access</th></tr></thead>
  <tbody>${rows.join('')}</tbody>
</table>
</body></html>`;
}

// ---------------------------------------------------------------------------
// VPN Gateway Console — enterprise VPN log
// ---------------------------------------------------------------------------

function renderVpnGatewayLog(title: string, content: string): string {
  const lines = splitLines(content);

  const defaultRows = [
    '2026-04-07 07:59:12|jsmith|198.51.100.14|Kerberos|10.0.1.0/24|Connected',
    '2026-04-07 08:02:44|ajones|203.0.113.88|NTLM|10.0.2.0/24|Connected',
    '2026-04-07 08:15:33|mchen|192.0.2.201|Kerberos|10.0.1.0/24|Connected',
    '2026-04-07 08:31:01|ajones|203.0.113.88|NTLM|10.0.3.0/24|Disconnected',
    '2026-04-07 08:45:19|skumar|203.0.113.42|NTLM|10.0.1.0/24|Connected',
  ];

  const dataLines = lines.length > 0 ? lines : defaultRows;

  const rows = dataLines.slice(0, 20).map((line) => {
    const f = pipeFields(line);
    const authType = (f[3] ?? '').trim();
    const isNtlm = authType.toUpperCase() === 'NTLM';
    const status = (f[5] ?? '').trim().toLowerCase();
    const statusDot = status === 'connected' ? '#22c55e' : '#666';
    const rowBg = isNtlm ? 'rgba(210,153,34,0.12)' : 'transparent';
    const authColor = isNtlm ? '#d29922' : '#0066cc';
    return `<tr style="background:${rowBg}">
      <td>${esc(f[0] ?? '')}</td><td>${esc(f[1] ?? '')}</td><td>${esc(f[2] ?? '')}</td>
      <td style="color:${authColor};font-weight:600">${esc(authType)}</td>
      <td>${esc(f[4] ?? '')}</td>
      <td><span style="color:${statusDot};margin-right:6px">&#9679;</span>${esc(f[5] ?? '')}</td>
    </tr>`;
  });

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#fff;color:#111;font-family:'Courier New',monospace;font-size:12px;border:1px solid #ddd}
.header{background:#f5f5f5;padding:12px 20px;border-bottom:1px solid #ddd;display:flex;justify-content:space-between;align-items:center}
.header h1{font-size:14px;color:#0066cc;font-weight:700}
.header .gw{font-size:11px;color:#555}
table{width:100%;border-collapse:collapse}
thead tr{background:#f5f5f5}
thead th{padding:8px 10px;text-align:left;font-size:11px;color:#222;font-weight:600;border-bottom:1px solid #ddd}
tbody td{padding:6px 10px;font-size:12px;color:#111;border-bottom:1px solid #eee}
</style></head><body>
<div class="header">
  <h1>VPN Gateway Console &mdash; ${esc(title)}</h1>
  <div class="gw">Gateway: GW-PROD-01 &middot; Uptime: 47d 12h &middot; Active sessions: ${rows.length}</div>
</div>
<table>
  <thead><tr><th>Timestamp</th><th>Account</th><th>Source IP</th><th>Auth Type</th><th>Destination</th><th>Status</th></tr></thead>
  <tbody>${rows.join('')}</tbody>
</table>
</body></html>`;
}

// ---------------------------------------------------------------------------
// Windows Event Log — Event Viewer
// ---------------------------------------------------------------------------

function renderWindowsEventLog(title: string, content: string): string {
  const lines = splitLines(content);

  const defaultRows = [
    'Information|2026-04-07 08:00:12|Microsoft-Windows-Security-Auditing|4624|Logon',
    'Information|2026-04-07 08:00:14|Microsoft-Windows-Security-Auditing|4672|Special Logon',
    'Warning|2026-04-07 08:05:33|Microsoft-Windows-Security-Auditing|4625|Logon',
    'Error|2026-04-07 08:12:01|Microsoft-Windows-Security-Auditing|4625|Logon',
    'Information|2026-04-07 08:15:44|Microsoft-Windows-Security-Auditing|4634|Logoff',
  ];

  const eventLines: string[] = [];
  const detailLines: string[] = [];

  const dataLines = lines.length > 0 ? lines : defaultRows;
  for (const l of dataLines) {
    if (l.startsWith('DETAIL:')) {
      detailLines.push(l.slice(7).trim());
    } else {
      eventLines.push(l);
    }
  }

  const levelIcon = (lvl: string): string => {
    const ll = lvl.toLowerCase();
    if (ll === 'error') return '<span style="color:#e81123" title="Error">&#9940;</span>';
    if (ll === 'warning') return '<span style="color:#c19c00" title="Warning">&#9888;</span>';
    return '<span style="color:#0078d4" title="Information">&#8505;</span>';
  };

  const rows = eventLines.slice(0, 20).map((line) => {
    const f = pipeFields(line);
    return `<tr>
      <td>${levelIcon(f[0] ?? 'Information')} ${esc(f[0] ?? '')}</td>
      <td>${esc(f[1] ?? '')}</td><td>${esc(f[2] ?? '')}</td>
      <td>${esc(f[3] ?? '')}</td><td>${esc(f[4] ?? '')}</td>
    </tr>`;
  });

  const detailHtml = detailLines.length > 0
    ? detailLines.map(l => esc(l)).join('\n')
    : 'An account was successfully logged on.\n\nSubject:\n  Security ID: S-1-5-18\n  Account Name: SYSTEM\n\nLogon Type: 3 (Network)';

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',sans-serif;font-size:12px;background:#fff;display:flex;flex-direction:column;height:600px;border:1px solid #ddd}
.titlebar{background:#f0f0f0;padding:6px 12px;font-size:13px;font-weight:600;color:#1e1e1e;border-bottom:1px solid #ccc;display:flex;align-items:center;gap:8px}
.content{display:flex;flex:1;overflow:hidden}
.tree{width:160px;background:#f5f5f5;border-right:1px solid #ddd;padding:8px 0;font-size:12px;flex-shrink:0;overflow-y:auto}
.tree-item{padding:3px 12px;cursor:pointer;color:#333}
.tree-item.active{background:#cde;font-weight:600}
.tree-item.indent{padding-left:28px;font-size:11px}
.right{flex:1;display:flex;flex-direction:column;overflow:hidden}
table{width:100%;border-collapse:collapse;flex:1}
thead tr{background:#f0f0f0}
thead th{padding:5px 8px;text-align:left;font-size:11px;color:#333;font-weight:600;border-bottom:1px solid #ccc;position:sticky;top:0;background:#f0f0f0}
tbody{overflow-y:auto}
tbody tr{cursor:pointer}
tbody tr:hover{background:#e8f0fe}
tbody td{padding:4px 8px;font-size:11px;color:#333;border-bottom:1px solid #eee}
.detail{height:160px;border-top:2px solid #ccc;background:#f5f5f5;padding:10px 14px;overflow-y:auto}
.detail h4{font-size:12px;color:#333;margin-bottom:6px}
.detail pre{font-family:'Consolas',monospace;font-size:11px;color:#333;white-space:pre-wrap;line-height:1.5}
</style></head><body>
<div class="titlebar">&#128187; Event Viewer &mdash; ${esc(title)}</div>
<div class="content">
  <div class="tree">
    <div class="tree-item">Custom Views</div>
    <div class="tree-item">Windows Logs</div>
    <div class="tree-item indent">Application</div>
    <div class="tree-item indent active">Security</div>
    <div class="tree-item indent">Setup</div>
    <div class="tree-item indent">System</div>
    <div class="tree-item">Applications and Services</div>
  </div>
  <div class="right">
    <table>
      <thead><tr><th>Level</th><th>Date and Time</th><th>Source</th><th>Event ID</th><th>Task Category</th></tr></thead>
      <tbody>${rows.join('')}</tbody>
    </table>
    <div class="detail">
      <h4>Event Details</h4>
      <pre>${detailHtml}</pre>
    </div>
  </div>
</div>
</body></html>`;
}

// ---------------------------------------------------------------------------
// CrowdStrike Falcon — EDR Process Tree
// ---------------------------------------------------------------------------

function renderEdrProcessTree(title: string, content: string): string {
  const lines = splitLines(content);

  const defaultLines = [
    'explorer.exe (PID 1024) -- Windows Explorer',
    '  cmd.exe (PID 4812) -- C:\\Windows\\System32\\cmd.exe',
    '    powershell.exe (PID 5920) -- powershell -enc SQBFAFgA... [SUSPICIOUS]',
    '      rundll32.exe (PID 6104) -- rundll32 C:\\Users\\Public\\payload.dll,Start [MALICIOUS]',
  ];

  const dataLines = lines.length > 0 ? lines : defaultLines;

  const treeNodes = dataLines.slice(0, 20).map((line) => {
    const stripped = line.replace(/\t/g, '  ');
    const leadingSpaces = stripped.match(/^(\s*)/)?.[1].length ?? 0;
    const depth = Math.floor(leadingSpaces / 2);
    const text = stripped.trim();

    let badge = '';
    let badgeBg = '';
    let cleanText = text;
    if (text.includes('[MALICIOUS]')) {
      badge = 'MALICIOUS';
      badgeBg = '#ff4d4f';
      cleanText = text.replace('[MALICIOUS]', '').trim();
    } else if (text.includes('[SUSPICIOUS]')) {
      badge = 'SUSPICIOUS';
      badgeBg = '#d29922';
      cleanText = text.replace('[SUSPICIOUS]', '').trim();
    }

    const pidMatch = cleanText.match(/\(PID\s*(\d+)\)/);
    const pid = pidMatch ? pidMatch[1] : '';
    const parts = cleanText.split('--');
    const procName = esc(parts[0]?.replace(/\(PID\s*\d+\)/, '').trim() ?? '');
    const cmdLine = esc(parts[1]?.trim() ?? '');

    return `<div style="padding:4px 0 4px ${depth * 24}px;border-left:${depth > 0 ? '2px solid #ddd' : 'none'};margin-left:${depth > 0 ? (depth - 1) * 24 + 11 : 0}px;font-family:'Courier New',monospace;font-size:12px">
      <span style="color:#111;font-weight:600">${procName}</span>
      ${pid ? `<span style="color:#555;font-size:11px;margin-left:6px">(PID ${esc(pid)})</span>` : ''}
      ${cmdLine ? `<span style="color:#555;font-size:11px;margin-left:8px;max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:inline-block;vertical-align:bottom">${cmdLine}</span>` : ''}
      ${badge ? `<span style="background:${badgeBg};color:#fff;padding:1px 8px;border-radius:3px;font-size:10px;font-weight:700;margin-left:8px">${badge}</span>` : ''}
    </div>`;
  });

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#fff;color:#111;font-family:'Segoe UI',sans-serif;font-size:13px;border:1px solid #ddd}
.header{background:#f5f5f5;padding:12px 20px;border-bottom:2px solid #cc0000;display:flex;justify-content:space-between;align-items:center}
.header h1{font-size:14px;color:#cc0000;font-weight:700}
.header .sub{font-size:11px;color:#555}
.breadcrumb{background:#fafafa;padding:8px 20px;font-size:12px;color:#555;border-bottom:1px solid #ddd}
.breadcrumb span{color:#cc0000}
.tree{padding:16px 20px}
.meta{padding:12px 20px;background:#fafafa;border-bottom:1px solid #ddd;font-size:11px;color:#555;display:flex;gap:24px}
.meta .label{color:#555}
</style></head><body>
<div class="header">
  <h1>&#9872; CrowdStrike Falcon</h1>
  <div class="sub">Endpoint Detection &amp; Response</div>
</div>
<div class="breadcrumb">Detections &gt; <span>Process Tree</span> &gt; ${esc(title)}</div>
<div class="meta">
  <div><span class="label">Host:</span> WS-PC0142</div>
  <div><span class="label">Detection:</span> ${esc(title)}</div>
  <div><span class="label">Severity:</span> <span style="color:#cc0000">Critical</span></div>
  <div><span class="label">Time:</span> 2026-04-07 08:15:33 UTC</div>
</div>
<div class="tree">
${treeNodes.join('\n')}
</div>
</body></html>`;
}

// ---------------------------------------------------------------------------
// Volatility — Memory Forensics Terminal
// ---------------------------------------------------------------------------

function renderMemoryForensics(title: string, content: string): string {
  const sections = parseSections(content);

  const defaultSections = [
    [
      'vol.py -f memory.dmp windows.pslist',
      'PID    PPID   Name              Threads  Handles  SessionId',
      '4      0      System            142      1680     0',
      '416    4      smss.exe          2        29       0',
      '556    548    csrss.exe         12       512      0',
      '4812   1024   cmd.exe           1        24       1',
      '5920   4812   powershell.exe    8        312      1',
      '6104   5920   rundll32.exe      3        87       1',
    ],
    [
      'vol.py -f memory.dmp windows.netscan',
      'Offset           Proto  LocalAddr       LocalPort  ForeignAddr      ForeignPort  State        PID   Owner',
      '0x7d8a3010       TCPv4  10.0.0.42       49673      203.0.113.42     443          ESTABLISHED  6104  rundll32.exe',
      '0x7d8b1240       TCPv4  10.0.0.42       49801      198.51.100.14    80           CLOSE_WAIT   5920  powershell.exe',
      '0x7d8c0880       UDPv4  10.0.0.42       137        *                *                         4     System',
    ],
  ];

  const dataSections = sections.length > 0 && sections[0].length > 0 ? sections : defaultSections;

  const sectionHtml = dataSections.map((sec) => {
    if (sec.length === 0) return '';
    const cmd = sec[0];
    const output = sec.slice(1);
    return `<div style="margin-bottom:20px">
      <div style="color:#006600;font-weight:700;margin-bottom:4px">$ ${esc(cmd)}</div>
      ${output.map(l => `<div style="color:#111">${esc(l)}</div>`).join('\n')}
    </div>`;
  }).join('');

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#fff;color:#006600;font-family:'Courier New',monospace;font-size:12px;padding:16px;min-height:600px;border:1px solid #ddd}
.title{color:#006600;font-size:14px;font-weight:700;margin-bottom:4px}
.subtitle{color:#555;font-size:11px;margin-bottom:16px}
.prompt{color:#555;margin-bottom:16px;font-size:11px}
.output{white-space:pre;line-height:1.5;font-size:12px}
</style></head><body>
<div class="title">Volatility 3 Framework &mdash; ${esc(title)}</div>
<div class="subtitle">Memory forensics analysis output</div>
<div class="prompt">[analyst@forensics ~]$ # Memory image analysis</div>
<div class="output">
${sectionHtml}
</div>
</body></html>`;
}

// ---------------------------------------------------------------------------
// ServiceNow — ITSM Ticket
// ---------------------------------------------------------------------------

function renderItsmTicket(title: string, content: string): string {
  const sections = parseSections(content);

  const defaultSections = [
    [
      'Number: INC0012847',
      'Priority: P2',
      'State: In Progress',
      'Category: Security',
      'Assigned To: SOC Tier 2 - M. Chen',
      'Caller: J. Smith',
      'Short Description: Suspicious outbound connections detected from WS-PC0142',
      'Configuration Item: WS-PC0142',
      'Impact: 2 - Medium',
      'Urgency: 1 - High',
    ],
    [
      '2026-04-07 08:45 - SOC Tier 1 (A. Jones): Alert received from SIEM. Suspicious outbound traffic to 203.0.113.42 on port 443. Escalating to Tier 2.',
      '2026-04-07 09:10 - SOC Tier 2 (M. Chen): Confirmed C2 beaconing pattern. Isolating endpoint WS-PC0142. Initiating IR playbook.',
      '2026-04-07 09:30 - SOC Tier 2 (M. Chen): Memory dump acquired. EDR process tree shows rundll32.exe loading suspicious DLL.',
    ],
  ];

  const dataSections = sections.length > 0 && sections[0].length > 0 ? sections : defaultSections;

  const fields = dataSections[0] ?? [];
  const activities = dataSections[1] ?? [];

  const priorityMatch = fields.find(l => l.toLowerCase().startsWith('priority'))?.split(':')[1]?.trim() ?? 'P3';
  const priorityColor = (p: string): string => {
    if (p.startsWith('P1')) return '#e81123';
    if (p.startsWith('P2')) return '#f59e0b';
    if (p.startsWith('P3')) return '#c19c00';
    return '#107c10';
  };

  const ticketNumber = fields.find(l => l.toLowerCase().startsWith('number'))?.split(':')[1]?.trim() ?? 'INC0000000';

  const fieldRows = fields.map((line) => {
    const idx = line.indexOf(':');
    if (idx < 0) return '';
    const label = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    return `<div class="field"><div class="field-label">${esc(label)}</div><div class="field-value">${esc(value)}</div></div>`;
  }).join('');

  const activityHtml = activities.map((line) => {
    return `<div class="activity-item"><div class="activity-dot"></div><div class="activity-text">${esc(line)}</div></div>`;
  }).join('');

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#f5f5f5;font-family:'Segoe UI',sans-serif;font-size:13px;color:#333;border:1px solid #ddd}
.header{background:#293e40;padding:14px 20px;display:flex;justify-content:space-between;align-items:center}
.header h1{font-size:15px;color:#fff;font-weight:600}
.header .badge{padding:3px 12px;border-radius:3px;font-size:12px;font-weight:700;color:#fff}
.card{background:#fff;margin:16px 20px;border-radius:4px;box-shadow:0 1px 3px rgba(0,0,0,.1);padding:20px}
.card h2{font-size:14px;color:#293e40;margin-bottom:14px;border-bottom:1px solid #e5e7eb;padding-bottom:8px}
.fields{display:grid;grid-template-columns:1fr 1fr;gap:10px 24px}
.field{display:flex;gap:8px}
.field-label{color:#6b7280;font-size:12px;min-width:140px;text-align:right;flex-shrink:0}
.field-value{color:#111;font-size:12px;font-weight:500}
.activity-section{margin-top:16px}
.activity-item{display:flex;gap:12px;padding:8px 0;border-left:2px solid #293e40;margin-left:8px;padding-left:16px;position:relative}
.activity-dot{width:10px;height:10px;background:#293e40;border-radius:50%;position:absolute;left:-6px;top:12px;flex-shrink:0}
.activity-text{font-size:12px;line-height:1.5;color:#333}
</style></head><body>
<div class="header">
  <h1>&#9776; ServiceNow &mdash; ${esc(ticketNumber)}: ${esc(title)}</h1>
  <span class="badge" style="background:${priorityColor(priorityMatch)}">${esc(priorityMatch)}</span>
</div>
<div class="card">
  <h2>Incident Details</h2>
  <div class="fields">${fieldRows}</div>
</div>
<div class="card">
  <h2>Activity Log</h2>
  <div class="activity-section">${activityHtml}</div>
</div>
</body></html>`;
}

// ---------------------------------------------------------------------------
// Threat Intel Report — TLP-Classified Advisory
// ---------------------------------------------------------------------------

function renderThreatIntelReport(title: string, content: string): string {
  const sections = parseSections(content);

  const defaultSections = [
    [
      'TLP:AMBER',
      'ADVISORY REFERENCE: TI-2026-0407-001',
      'DATE: 2026-04-07',
      'ISSUING AUTHORITY: Cyber Threat Intelligence Division',
    ],
    [
      'EXECUTIVE SUMMARY',
      'A sophisticated threat actor group tracked as VOLT CRANE has been observed targeting critical infrastructure organizations using a novel supply chain compromise technique.',
    ],
    [
      'INDICATORS OF COMPROMISE',
      'C2 Domain: update-service.example.com',
      'C2 IP: 203.0.113.42',
      'Payload Hash (SHA256): e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      'Staging IP: 198.51.100.14',
    ],
    [
      'RECOMMENDED ACTIONS',
      'Block listed IOCs at network perimeter.',
      'Hunt for listed process indicators across endpoints.',
      'Review supply chain access for affected vendors.',
    ],
  ];

  const dataSections = sections.length > 0 && sections[0].length > 0 ? sections : defaultSections;

  const tlpLine = (dataSections[0]?.[0] ?? 'TLP:AMBER').toUpperCase();
  const tlpLevel = tlpLine.replace('TLP:', '').replace('TLP', '').trim() || 'AMBER';
  const tlpColors: Record<string, { bg: string; fg: string }> = {
    RED: { bg: '#ff0000', fg: '#fff' },
    AMBER: { bg: '#ffc000', fg: '#000' },
    GREEN: { bg: '#33ff00', fg: '#000' },
    WHITE: { bg: '#ffffff', fg: '#000' },
  };
  const tlp = tlpColors[tlpLevel] ?? tlpColors['AMBER'];
  const tlpBorder = tlpLevel === 'WHITE' ? 'border:1px solid #999;' : '';

  const bodyHtml = dataSections.map((sec, si) => {
    if (si === 0) {
      // First section: header info (skip TLP line)
      return sec.slice(1).map(l => `<div style="font-size:13px;color:#333;margin-bottom:4px">${esc(l)}</div>`).join('');
    }
    const heading = sec[0] ?? '';
    const isHeading = heading === heading.toUpperCase() || heading.endsWith(':');
    const headingHtml = isHeading
      ? `<h3 style="font-size:14px;text-transform:uppercase;font-weight:700;color:#1a1a1a;border-bottom:2px solid #333;padding-bottom:4px;margin:20px 0 10px">${esc(heading)}</h3>`
      : `<p style="margin-bottom:6px">${esc(heading)}</p>`;
    const restHtml = sec.slice(isHeading ? 1 : 0).map(l => `<p style="font-size:13px;line-height:1.6;margin-bottom:6px">${esc(l)}</p>`).join('');
    return headingHtml + restHtml;
  }).join('');

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#fff;font-family:Georgia,'Times New Roman',serif;font-size:13px;color:#333;border:1px solid #ddd}
.tlp-banner{padding:10px 20px;text-align:center;font-weight:700;font-size:14px;letter-spacing:2px}
.title-section{padding:20px 40px;border-bottom:1px solid #ddd}
.title-section h1{font-size:20px;color:#1a1a1a;margin-bottom:8px}
.body-content{padding:20px 40px;min-height:400px}
.footer{padding:12px 40px;border-top:1px solid #ddd;text-align:center;font-size:11px;font-weight:700;letter-spacing:2px}
</style></head><body>
<div class="tlp-banner" style="background:${tlp.bg};color:${tlp.fg};${tlpBorder}">TLP:${esc(tlpLevel)} &mdash; DISTRIBUTION RESTRICTED</div>
<div class="title-section">
  <h1>${esc(title)}</h1>
</div>
<div class="body-content">
${bodyHtml}
</div>
<div class="footer" style="background:${tlp.bg};color:${tlp.fg};${tlpBorder}">TLP:${esc(tlpLevel)}</div>
</body></html>`;
}

// ---------------------------------------------------------------------------
// Threat Intel Enrichment — TI Platform Dashboard
// ---------------------------------------------------------------------------

function renderTiEnrichment(title: string, content: string): string {
  const sections = parseSections(content);

  const defaultSections = [
    [
      'Indicator: 203.0.113.42',
      'Type: IPv4 Address',
      'Reputation Score: 87',
      'Verdict: Malicious',
      'First Seen: 2026-03-15',
      'Last Seen: 2026-04-07',
      'Country: Unknown (VPN/Proxy)',
    ],
    [
      'WHOIS Information',
      'Registrar|Registration Date|Expiry|Name Server',
      'Example Registrar|2025-12-01|2026-12-01|ns1.example.com',
    ],
    [
      'Associated Malware',
      'Family|Confidence|Source',
      'VOLT CRANE RAT|High|Internal Sandbox',
      'CobaltStrike Beacon|Medium|VirusTotal',
    ],
    [
      'Related Indicators',
      'Indicator|Type|Relationship',
      'update-service.example.com|Domain|Resolves To',
      '198.51.100.14|IPv4|Same Campaign',
    ],
  ];

  const dataSections = sections.length > 0 && sections[0].length > 0 ? sections : defaultSections;

  // Parse first section for header info
  const headerFields = dataSections[0] ?? [];
  const indicator = headerFields.find(l => l.toLowerCase().startsWith('indicator'))?.split(':').slice(1).join(':').trim() ?? title;
  const scoreStr = headerFields.find(l => l.toLowerCase().includes('score'))?.split(':').slice(1).join(':').trim() ?? '0';
  const score = parseInt(scoreStr, 10) || 0;
  const verdict = headerFields.find(l => l.toLowerCase().startsWith('verdict'))?.split(':').slice(1).join(':').trim() ?? 'Unknown';
  const scoreColor = score > 70 ? '#e81123' : score > 30 ? '#d29922' : '#107c10';

  const headerKV = headerFields.map((l) => {
    const idx = l.indexOf(':');
    if (idx < 0) return '';
    return `<div style="margin-bottom:4px"><span style="color:#555;font-size:11px">${esc(l.slice(0, idx).trim())}:</span> <span style="color:#111;font-size:12px">${esc(l.slice(idx + 1).trim())}</span></div>`;
  }).join('');

  const panelHtml = dataSections.slice(1).map((sec) => {
    const panelTitle = sec[0] ?? 'Details';
    const hasTable = (sec[1] ?? '').includes('|');
    let inner = '';
    if (hasTable) {
      const headers = pipeFields(sec[1] ?? '');
      const rows = sec.slice(2, 12).map(l => {
        const f = pipeFields(l);
        return `<tr>${f.map(v => `<td style="padding:4px 8px;border-bottom:1px solid #ddd;font-size:11px;color:#111">${esc(v)}</td>`).join('')}</tr>`;
      }).join('');
      inner = `<table style="width:100%;border-collapse:collapse"><thead><tr>${headers.map(h => `<th style="padding:4px 8px;text-align:left;font-size:11px;color:#222;border-bottom:1px solid #ddd">${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows}</tbody></table>`;
    } else {
      inner = sec.slice(1).map(l => {
        const idx = l.indexOf(':');
        if (idx >= 0) return `<div style="margin-bottom:3px"><span style="color:#555;font-size:11px">${esc(l.slice(0, idx).trim())}:</span> <span style="color:#111;font-size:12px">${esc(l.slice(idx + 1).trim())}</span></div>`;
        return `<div style="color:#111;font-size:12px">${esc(l)}</div>`;
      }).join('');
    }
    return `<div style="background:#f5f5f5;border:1px solid #ddd;border-radius:6px;padding:12px;margin-bottom:12px">
      <div style="font-size:12px;font-weight:600;color:#6a3dbd;margin-bottom:8px;border-bottom:1px solid #ddd;padding-bottom:6px">${esc(panelTitle)}</div>
      ${inner}
    </div>`;
  }).join('');

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#fff;color:#111;font-family:'Segoe UI',sans-serif;font-size:13px;border:1px solid #ddd}
.header{background:#f5f5f5;padding:16px 20px;border-bottom:1px solid #ddd;display:flex;align-items:center;gap:20px}
.score-circle{width:64px;height:64px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:22px;font-weight:700;color:#fff;flex-shrink:0}
.header-info{flex:1}
.tabs{background:#fafafa;padding:0 20px;display:flex;gap:0;border-bottom:1px solid #ddd}
.tab{padding:10px 16px;font-size:12px;color:#555;cursor:pointer}
.tab.active{color:#6a3dbd;border-bottom:2px solid #6a3dbd}
.panels{padding:16px 20px;display:grid;grid-template-columns:1fr 1fr;gap:12px}
</style></head><body>
<div class="header">
  <div class="score-circle" style="background:${scoreColor}">${score}</div>
  <div class="header-info">
    <div style="font-size:16px;font-weight:700;color:#111;margin-bottom:4px">${esc(indicator)}</div>
    <span style="background:${scoreColor};color:#fff;padding:2px 10px;border-radius:3px;font-size:11px;font-weight:600">${esc(verdict)}</span>
    <div style="margin-top:8px">${headerKV}</div>
  </div>
</div>
<div class="tabs">
  <div class="tab active">Overview</div>
  <div class="tab">WHOIS</div>
  <div class="tab">Malware</div>
  <div class="tab">Network</div>
  <div class="tab">Raw Data</div>
</div>
<div class="panels">
${panelHtml}
</div>
</body></html>`;
}

// ---------------------------------------------------------------------------
// DLP Dashboard — Data Loss Prevention Management Console
// ---------------------------------------------------------------------------

function renderDlpDashboard(title: string, content: string): string {
  const lines = splitLines(content);

  const defaultLines = [
    'STAT:Total Alerts|142',
    'STAT:Blocked|87',
    'STAT:Allowed|41',
    'STAT:Exceptions|14',
    '2026-04-07 08:12|PCI-DSS Credit Card Pattern|Block|2.3 MB|j.smith@contoso.com|Blocked',
    '2026-04-07 08:18|PII SSN Detection|Block|450 KB|a.jones@contoso.com|Blocked',
    '2026-04-07 08:25|Source Code Upload|Allow|12 MB|m.chen@contoso.com|Allowed (Exception)',
    '2026-04-07 08:31|Confidential Label|Encrypt|1.1 MB|s.kumar@contoso.com|Encrypted',
    '2026-04-07 08:45|Large File Transfer|Block|89 MB|j.smith@contoso.com|Blocked',
  ];

  const dataLines = lines.length > 0 ? lines : defaultLines;

  const statLines = dataLines.filter(l => l.startsWith('STAT:'));
  const alertLines = dataLines.filter(l => !l.startsWith('STAT:'));

  const statColors = ['#3b82f6', '#e81123', '#107c10', '#d29922'];
  const stats = statLines.slice(0, 4).map((line, i) => {
    const f = pipeFields(line.replace('STAT:', ''));
    return `<div style="flex:1;background:#fff;border-radius:6px;padding:16px;border-top:3px solid ${statColors[i]}">
      <div style="font-size:11px;color:#6b7280;text-transform:uppercase">${esc(f[0] ?? '')}</div>
      <div style="font-size:28px;font-weight:700;color:#1e293b;margin-top:4px">${esc(f[1] ?? '0')}</div>
    </div>`;
  }).join('');

  const actionColor = (a: string): string => {
    const al = a.toLowerCase();
    if (al === 'block') return '#e81123';
    if (al === 'allow') return '#107c10';
    if (al === 'encrypt') return '#3b82f6';
    return '#888';
  };

  const rows = alertLines.slice(0, 20).map((line) => {
    const f = pipeFields(line);
    const action = f[2] ?? '';
    return `<tr>
      <td>${esc(f[0] ?? '')}</td><td>${esc(f[1] ?? '')}</td>
      <td><span style="background:${actionColor(action)};color:#fff;padding:2px 8px;border-radius:3px;font-size:11px">${esc(action)}</span></td>
      <td>${esc(f[3] ?? '')}</td><td>${esc(f[4] ?? '')}</td><td>${esc(f[5] ?? '')}</td>
    </tr>`;
  }).join('');

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#f8fafc;font-family:'Segoe UI',sans-serif;font-size:13px;display:flex;min-height:600px;border:1px solid #ddd}
.sidebar{width:200px;background:#f0f0f0;padding:16px 0;flex-shrink:0;border-right:1px solid #ddd}
.sidebar h2{color:#555;font-size:11px;text-transform:uppercase;letter-spacing:1px;padding:0 16px;margin-bottom:12px}
.sidebar .item{padding:8px 16px;color:#555;font-size:12px;cursor:pointer}
.sidebar .item.active{background:#ddd;color:#111;font-weight:600}
.main{flex:1;padding:20px}
.main h1{font-size:16px;color:#1e293b;margin-bottom:16px}
.stats{display:flex;gap:12px;margin-bottom:20px}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:6px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.08)}
thead tr{background:#f1f5f9}
thead th{padding:8px 10px;text-align:left;font-size:11px;color:#222;font-weight:600;border-bottom:1px solid #ddd}
tbody td{padding:6px 10px;font-size:12px;color:#111;border-bottom:1px solid #f1f5f9}
</style></head><body>
<div class="sidebar">
  <h2>DLP Policies</h2>
  <div class="item active">All Alerts</div>
  <div class="item">PCI-DSS Rules</div>
  <div class="item">PII Protection</div>
  <div class="item">Source Code</div>
  <div class="item">Confidential</div>
  <div class="item">Large Transfers</div>
</div>
<div class="main">
  <h1>&#128274; ${esc(title)}</h1>
  <div class="stats">${stats}</div>
  <table>
    <thead><tr><th>Timestamp</th><th>Rule</th><th>Action</th><th>Volume</th><th>Account</th><th>Result</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>
</div>
</body></html>`;
}

// ---------------------------------------------------------------------------
// Reverse Engineering — IDA Pro / Ghidra Disassembly
// ---------------------------------------------------------------------------

function renderReverseEngineering(title: string, content: string): string {
  const sections = parseSections(content);

  const defaultSections = [
    [
      'sub_401000  main',
      'sub_401120  decrypt_config',
      'sub_4012A0  http_beacon',
      'sub_401400  exfil_data',
      'sub_401580  anti_debug',
    ],
    [
      '0x00401120  55              push    ebp                  ; Function prologue',
      '0x00401121  89E5            mov     ebp, esp',
      '0x00401123  83EC20          sub     esp, 0x20            ; Allocate local vars',
      '0x00401126  C745FC00000000  mov     dword [ebp-4], 0     ; Initialize counter',
      '0x0040112D  8B4508          mov     eax, [ebp+8]         ; Load config ptr',
      '0x00401130  8945F8          mov     [ebp-8], eax',
      '0x00401133  EB1A            jmp     0x40114F             ; Jump to decrypt loop',
      '0x00401135  8B45F8          mov     eax, [ebp-8]',
      '0x00401138  0345FC          add     eax, [ebp-4]',
      '0x0040113B  0FB600          movzx   eax, byte [eax]      ; Read encrypted byte',
      '0x0040113E  3455            xor     al, 0x55             ; XOR decrypt key=0x55',
    ],
    [
      'String: "http://203.0.113.42/beacon"  @ 0x00405010',
      'String: "Mozilla/5.0 (compatible)"    @ 0x00405040',
      'String: "config.encrypted"            @ 0x00405080',
      'Import: kernel32.VirtualAlloc         @ 0x00406000',
      'Import: ws2_32.connect               @ 0x00406008',
      'Import: wininet.HttpSendRequestA     @ 0x00406010',
    ],
  ];

  const dataSections = sections.length > 0 && sections[0].length > 0 ? sections : defaultSections;

  const funcList = (dataSections[0] ?? []).slice(0, 20);
  const disasmLines = (dataSections[1] ?? []).slice(0, 20);
  const stringsLines = (dataSections[2] ?? []).slice(0, 20);

  const funcHtml = funcList.map((l, i) => {
    const parts = l.trim().split(/\s+/);
    const addr = parts[0] ?? '';
    const name = parts.slice(1).join(' ') || addr;
    const active = i === 1;
    return `<div style="padding:3px 8px;font-size:11px;cursor:pointer;${active ? 'background:#cde;color:#111' : 'color:#111'}">${esc(addr)} <span style="color:#7a6b2a">${esc(name)}</span></div>`;
  }).join('');

  const disasmHtml = disasmLines.map((l) => {
    // Parse: 0xADDRESS  bytes  mnemonic  operands  ; comment
    const commentIdx = l.indexOf(';');
    const comment = commentIdx >= 0 ? l.slice(commentIdx) : '';
    const mainPart = commentIdx >= 0 ? l.slice(0, commentIdx) : l;
    const parts = mainPart.trim().split(/\s{2,}/);
    const addr = parts[0] ?? '';
    const bytes = parts[1] ?? '';
    const rest = parts.slice(2).join('  ');
    const mnMatch = rest.match(/^(\S+)\s*(.*)/);
    const mnemonic = mnMatch?.[1] ?? rest;
    const operands = mnMatch?.[2] ?? '';

    return `<div style="display:flex;gap:0;font-size:12px;line-height:1.6">
      <span style="color:#0066cc;min-width:100px;display:inline-block">${esc(addr)}</span>
      <span style="color:#888;min-width:120px;display:inline-block">${esc(bytes)}</span>
      <span style="color:#7a6b2a;min-width:70px;display:inline-block">${esc(mnemonic)}</span>
      <span style="color:#111;flex:1">${esc(operands)}</span>
      ${comment ? `<span style="color:#4a7a4a;margin-left:8px">${esc(comment)}</span>` : ''}
    </div>`;
  }).join('');

  const stringsHtml = stringsLines.map(l => `<div style="font-size:11px;color:#a05a2c;line-height:1.6">${esc(l)}</div>`).join('');

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#fff;color:#111;font-family:'Courier New',monospace;font-size:12px;display:grid;grid-template-columns:180px 1fr;grid-template-rows:auto 1fr auto;height:600px;border:1px solid #ddd}
.toolbar{grid-column:1/-1;background:#f5f5f5;padding:6px 12px;display:flex;gap:12px;align-items:center;border-bottom:1px solid #ddd;font-size:12px}
.toolbar .title{color:#7a6b2a;font-weight:700}
.toolbar .btn{color:#555;font-size:11px}
.func-list{background:#f5f5f5;border-right:1px solid #ddd;overflow-y:auto;padding:4px 0}
.func-list h3{font-size:11px;color:#555;padding:6px 8px;border-bottom:1px solid #ddd}
.disasm{overflow:auto;padding:8px 12px;background:#fafafa}
.strings{grid-column:1/-1;border-top:1px solid #ddd;background:#f5f5f5;padding:8px 12px;max-height:150px;overflow-y:auto}
.strings h3{font-size:11px;color:#555;margin-bottom:6px}
</style></head><body>
<div class="toolbar">
  <span class="title">IDA Pro &mdash; ${esc(title)}</span>
  <span class="btn">File</span><span class="btn">Edit</span><span class="btn">View</span>
  <span class="btn">Debug</span><span class="btn">Options</span>
</div>
<div class="func-list">
  <h3>Functions</h3>
  ${funcHtml}
</div>
<div class="disasm">
${disasmHtml}
</div>
<div class="strings">
  <h3>Strings / Imports</h3>
  ${stringsHtml}
</div>
</body></html>`;
}

// ---------------------------------------------------------------------------
// Certificate Viewer — X.509 Certificate Details
// ---------------------------------------------------------------------------

function renderCertificateViewer(title: string, content: string): string {
  const lines = splitLines(content);

  const defaultLines = [
    'Subject: CN=update-service.example.com, O=Example Corp, C=US',
    'Issuer: CN=DigiCert SHA2 Extended Validation Server CA, O=DigiCert Inc, C=US',
    'Serial Number: 0A:1B:2C:3D:4E:5F:6A:7B',
    'Valid From: 2025-12-01 00:00:00 UTC',
    'Valid To: 2026-12-01 23:59:59 UTC',
    'Signature Algorithm: SHA256withRSA',
    'Key Size: 2048 bit',
    'Key Usage: Digital Signature, Key Encipherment',
    'Extended Key Usage: Server Authentication',
    'Subject Alternative Names: update-service.example.com, *.example.com',
    'Fingerprint (SHA-256): AB:CD:EF:12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A:AB:CD:EF:12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A',
    'Status: Valid',
    'CHAIN:update-service.example.com (Leaf)',
    'CHAIN:DigiCert SHA2 Extended Validation Server CA (Intermediate)',
    'CHAIN:DigiCert Root CA (Root - Trusted)',
  ];

  const dataLines = lines.length > 0 ? lines : defaultLines;

  const fieldLines = dataLines.filter(l => !l.startsWith('CHAIN:'));
  const chainLines = dataLines.filter(l => l.startsWith('CHAIN:')).map(l => l.slice(6).trim());

  const statusLine = fieldLines.find(l => l.toLowerCase().startsWith('status'))?.split(':').slice(1).join(':').trim() ?? '';
  const isValid = statusLine.toLowerCase().includes('valid') && !statusLine.toLowerCase().includes('invalid') && !statusLine.toLowerCase().includes('expired');

  const fieldHtml = fieldLines.map((l) => {
    const idx = l.indexOf(':');
    if (idx < 0) return '';
    const label = l.slice(0, idx).trim();
    const value = l.slice(idx + 1).trim();
    let valueStyle = 'color:#111';
    if (label.toLowerCase() === 'status') {
      valueStyle = isValid ? 'color:#107c10;font-weight:600' : 'color:#e81123;font-weight:600';
    }
    return `<div style="display:flex;gap:12px;padding:5px 0;border-bottom:1px solid #f0f0f0">
      <div style="min-width:200px;text-align:right;color:#6b7280;font-size:12px;flex-shrink:0">${esc(label)}</div>
      <div style="${valueStyle};font-size:12px;word-break:break-all">${label.toLowerCase() === 'status' ? (isValid ? '&#10003; ' : '&#10007; ') : ''}${esc(value)}</div>
    </div>`;
  }).join('');

  const chainHtml = chainLines.length > 0
    ? chainLines.map((c, i) => `<div style="display:flex;align-items:center;padding:6px 0 6px ${i * 24}px;${i > 0 ? 'border-left:2px solid #3b82f6;margin-left:' + ((i - 1) * 24 + 11) + 'px' : ''}">
        <span style="color:#3b82f6;margin-right:8px;font-size:14px">&#9679;</span>
        <span style="font-size:12px;color:#333">${esc(c)}</span>
      </div>`).join('')
    : '';

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#f8f8f8;font-family:'Segoe UI',sans-serif;font-size:13px;padding:24px}
.card{background:#fff;max-width:700px;margin:0 auto;border:1px solid #ddd;border-radius:6px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.08)}
.card-header{padding:16px 20px;border-bottom:1px solid #eee;display:flex;align-items:center;gap:12px}
.lock{font-size:28px}
.card-header h1{font-size:16px;color:#111;font-weight:600}
.card-header .status{font-size:12px;margin-top:2px}
.fields{padding:16px 20px}
.chain-section{padding:16px 20px;border-top:1px solid #eee}
.chain-section h3{font-size:13px;color:#333;margin-bottom:10px}
</style></head><body>
<div class="card">
  <div class="card-header">
    <div class="lock">${isValid ? '&#128274;' : '&#128275;'}</div>
    <div>
      <h1>${esc(title)}</h1>
      <div class="status" style="color:${isValid ? '#107c10' : '#e81123'}">${isValid ? '&#10003; Certificate Valid' : '&#10007; Certificate Invalid / Expired'}</div>
    </div>
  </div>
  <div class="fields">${fieldHtml}</div>
  ${chainHtml ? `<div class="chain-section"><h3>Certificate Chain</h3>${chainHtml}</div>` : ''}
</div>
</body></html>`;
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/**
 * Returns a self-contained HTML string for UI-heavy artifact subtypes,
 * or null if the subtype should be rendered by an AI image provider.
 */
export function htmlArtifactForSubtype(
  subtype: ImageSubtype,
  title: string,
  content: string,
  _style?: VisualStyle,
): string | null {
  switch (subtype) {
    case 'phishing_email':     return renderPhishingEmail(title, content);
    case 'ransomware_note':    return renderRansomwareNote(title, content);
    case 'fraudulent_invoice': return renderFraudulentInvoice(title, content);
    case 'network_capture':    return renderNetworkCapture(title, content);
    case 'dark_web_listing':   return renderDarkWebListing(title, content);
    case 'scada_interface':    return renderScadaInterface(title, content);
    case 'browser_popup':      return renderBrowserPopup(title, content);
    case 'azure_ad_signin':      return renderAzureAdSignin(title, content);
    case 'vpn_gateway_log':      return renderVpnGatewayLog(title, content);
    case 'windows_event_log':    return renderWindowsEventLog(title, content);
    case 'edr_process_tree':     return renderEdrProcessTree(title, content);
    case 'memory_forensics':     return renderMemoryForensics(title, content);
    case 'itsm_ticket':          return renderItsmTicket(title, content);
    case 'threat_intel_report':  return renderThreatIntelReport(title, content);
    case 'ti_enrichment':        return renderTiEnrichment(title, content);
    case 'dlp_dashboard':        return renderDlpDashboard(title, content);
    case 'reverse_engineering':  return renderReverseEngineering(title, content);
    case 'certificate_viewer':   return renderCertificateViewer(title, content);
    default:                   return null;
  }
}
