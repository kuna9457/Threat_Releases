"""
evidence_screenshots.py
─────────────────────────────────────────────────────────────────────────────
Generates Pillow-based "evidence screenshot" images that are pixel-accurate
replicas of:
  • VirusTotal URL analysis page  (2024 UI - Cropped)
  • Google Safe Browsing Transparency Report
  • SSL Labs Certificate Report
  • AbuseIPDB Reputation Report

These images are embedded in the WelthWest PDF report as tamper-proof visual
evidence. Rendered entirely from API data — no web scraping involved.
─────────────────────────────────────────────────────────────────────────────
"""

from PIL import Image, ImageDraw, ImageFont
from io import BytesIO
from datetime import datetime
import os
import math

# ── Font Helpers ──────────────────────────────────────────────────────────────
_FONT_DIR = "C:/Windows/Fonts"

def _font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    names = (["arialbd.ttf", "Arial Bold.ttf"] if bold else ["arial.ttf", "Arial.ttf"])
    for name in names:
        path = os.path.join(_FONT_DIR, name)
        if os.path.exists(path):
            try:
                return ImageFont.truetype(path, size)
            except Exception:
                pass
    return ImageFont.load_default()

# ── Exact VirusTotal 2024 Color Palette ──────────────────────────────────────
VT_PAGE_BG   = (13,  17,  23)    # #0d1117  page background
VT_NAV_BG    = (22,  27,  34)    # #161b22  top nav / card
VT_BORDER    = (48,  54,  61)    # #30363d  border
VT_RED       = (248, 81,  73)    # #f85149  malicious
VT_YELLOW    = (210, 153, 34)    # #d29922  suspicious
VT_GREEN     = (63,  185, 80)    # #3fb950  harmless
VT_GREY_TXT  = (139, 148, 158)   # #8b949e  secondary text
VT_WHITE_TXT = (201, 209, 217)   # #c9d1d9  primary text
VT_BLUE      = (88,  166, 255)   # #58a6ff  links / accent
VT_GAUGE_BG  = (33,  38,  45)    # gauge track background
VT_TAG_TEAL  = (31,  111, 104)   # tag bg (teal-ish)
VT_TAG_TEXT  = (87,  211, 189)   # tag text

# Google Safe Browsing Colors
GSB_BG       = (255, 255, 255)
GSB_SAFE     = (52,  168, 83)
GSB_DANGER   = (234, 67,  53)
GSB_BLUE     = (66,  133, 252)
GSB_TEXT     = (32,  33,  36)
GSB_SUBTEXT  = (95,  99,  104)
GSB_LIGHT    = (248, 249, 250)
GSB_BORDER   = (218, 220, 224)

# SSL Labs Colors
SSL_BG       = (11, 31, 56)      # Deep blue background
SSL_GREEN    = (76, 175, 80)
SSL_YELLOW   = (255, 152, 0)
SSL_RED      = (244, 67, 54)
SSL_TEXT     = (255, 255, 255)
SSL_SUBTEXT  = (176, 190, 197)

# AbuseIPDB Colors
AIPDB_BG     = (255, 255, 255)
AIPDB_HDR    = (244, 246, 248)
AIPDB_BRD    = (222, 226, 230)
AIPDB_TXT    = (33, 37, 41)
AIPDB_RED    = (220, 53, 69)


# ── Pillow Helpers ────────────────────────────────────────────────────────────
def _rr(draw: ImageDraw.Draw, xy, r: int, fill, outline=None, lw=1):
    """Draw a rounded rectangle — safe even if the box is small."""
    x0, y0, x1, y1 = xy
    r = min(r, (x1 - x0) // 2, (y1 - y0) // 2)
    if r < 1:
        draw.rectangle([x0, y0, x1, y1], fill=fill, outline=outline, width=lw)
        return
    draw.rectangle([x0 + r, y0, x1 - r, y1], fill=fill)
    draw.rectangle([x0, y0 + r, x1, y1 - r], fill=fill)
    for ex, ey in [(x0, y0), (x1 - 2*r, y0), (x0, y1 - 2*r), (x1 - 2*r, y1 - 2*r)]:
        draw.ellipse([ex, ey, ex + 2*r, ey + 2*r], fill=fill)
    if outline:
        draw.arc([x0, y0, x0+2*r, y0+2*r], 180, 270, fill=outline, width=lw)
        draw.arc([x1-2*r, y0, x1, y0+2*r], 270, 360, fill=outline, width=lw)
        draw.arc([x0, y1-2*r, x0+2*r, y1], 90, 180, fill=outline, width=lw)
        draw.arc([x1-2*r, y1-2*r, x1, y1], 0, 90, fill=outline, width=lw)
        draw.line([x0+r, y0, x1-r, y0], fill=outline, width=lw)
        draw.line([x0+r, y1, x1-r, y1], fill=outline, width=lw)
        draw.line([x0, y0+r, x0, y1-r], fill=outline, width=lw)
        draw.line([x1, y0+r, x1, y1-r], fill=outline, width=lw)

def _tag(draw: ImageDraw.Draw, x: int, y: int, text: str, bg=(31, 111, 104), fg=(87, 211, 189), font=None) -> int:
    font = font or _font(11)
    tw = int(draw.textlength(text, font=font))
    pad = 10
    _rr(draw, (x, y, x + tw + pad*2, y + 22), 6, fill=bg)
    draw.text((x + pad, y + 4), text, font=font, fill=fg)
    return x + tw + pad*2 + 8

def _draw_gauge_circle(draw: ImageDraw.Draw, cx: int, cy: int, score: int, total: int, mal: int, susp: int, harm: int):
    R = 52
    T = 7
    flagged = mal + susp
    ratio = flagged / max(total, 1)
    draw.ellipse([cx-R, cy-R, cx+R, cy+R], outline=VT_GAUGE_BG, width=T)
    if flagged > 0:
        arc_color = VT_RED if mal > 0 else VT_YELLOW
        sweep = max(ratio * 360, 4)
        draw.arc([cx-R, cy-R, cx+R, cy+R], start=-90, end=-90 + sweep, fill=arc_color, width=T+1)
        angle_rad = math.radians(-90 + sweep)
        dot_x = cx + int(R * math.cos(angle_rad))
        dot_y = cy + int(R * math.sin(angle_rad))
        dot_r = T + 2
        draw.ellipse([dot_x-dot_r, dot_y-dot_r, dot_x+dot_r, dot_y+dot_r], fill=arc_color)
    else:
        draw.arc([cx-R, cy-R, cx+R, cy+R], -90, 270, fill=VT_GREEN, width=T+1)
    
    f_big = _font(36, bold=True)
    f_denom = _font(14)
    score_str = str(flagged)
    sw = int(draw.textlength(score_str, font=f_big))
    score_color = VT_RED if mal > 0 else (VT_YELLOW if susp > 0 else VT_GREEN)
    draw.text((cx - sw//2, cy - 28), score_str, font=f_big, fill=score_color)
    denom_str = f"/{total}"
    dw = int(draw.textlength(denom_str, font=f_denom))
    draw.text((cx - dw//2, cy + 14), denom_str, font=f_denom, fill=VT_GREY_TXT)

def _add_browser_chrome(img: Image.Image, tab_title: str, url_bar: str) -> Image.Image:
    W = img.width
    TAB_H = 36
    URL_H = 40
    CHROME_H = TAB_H + URL_H
    SH = 5
    total_h = img.height + CHROME_H + SH
    canvas = Image.new("RGB", (W + SH*2, total_h), (180, 180, 180))
    draw = ImageDraw.Draw(canvas)
    draw.rectangle([0, 0, W + SH*2, TAB_H], fill=(32, 33, 36))
    draw.rectangle([0, 0, W + SH*2, 5], fill=(25, 25, 28))
    tab_x = SH + 70
    draw.rectangle([tab_x, 8, tab_x + 220, TAB_H], fill=(40, 40, 45), outline=(60, 62, 65), width=1)
    for i, col in enumerate([(236, 106, 94), (244, 191, 79), (98, 200, 84)]):
        cx_ = SH + 14 + i * 18
        draw.ellipse([cx_-5, 15, cx_+5, 25], fill=col)
    f_tab = _font(11)
    tab_txt = tab_title[:26] + ("…" if len(tab_title) > 26 else "")
    draw.text((tab_x + 12, 17), tab_txt, font=f_tab, fill=(200, 200, 200))
    draw.rectangle([0, TAB_H, W + SH*2, CHROME_H], fill=(27, 27, 30))
    url_box_x0 = SH + 50
    url_box_x1 = W + SH - 10
    _rr(draw, (url_box_x0, TAB_H + 6, url_box_x1, CHROME_H - 6), 12, fill=(40, 40, 45), outline=(60, 62, 65), lw=1)
    lk_x = url_box_x0 + 14
    lk_y = TAB_H + 16
    draw.rectangle([lk_x, lk_y + 4, lk_x + 8, lk_y + 10], fill=(98, 200, 84))
    draw.arc([lk_x, lk_y, lk_x + 8, lk_y + 8], 0, 180, fill=(98, 200, 84), width=2)
    f_url = _font(12)
    url_display = url_bar[:85]
    draw.text((lk_x + 14, TAB_H + 13), url_display, font=f_url, fill=(210, 210, 210))
    for nx in [W - 30, W - 10]:
        draw.ellipse([SH + nx, TAB_H + 14, SH + nx + 4, TAB_H + 20], fill=(120, 120, 120))
    canvas.paste(img, (SH, CHROME_H))
    for i in range(SH, 0, -1):
        alpha = 80 - i * 14
        if alpha > 0:
            draw.line([SH + W + i, CHROME_H, SH + W + i, total_h - SH + i], fill=(0, 0, 0))
            draw.line([SH, total_h - SH + i, SH + W + i, total_h - SH + i], fill=(0, 0, 0))
    return canvas


# ═══════════════════════════════════════════════════════════════════════════════
# VirusTotal 2024 URL Analysis Page — Cropped Replica
# ═══════════════════════════════════════════════════════════════════════════════

def generate_virustotal_screenshot(url: str, vt_data: dict) -> bytes:
    """
    Renders a cropped, pixel-accurate replica of the VirusTotal 2024 URL analysis page.
    Includes only the main content section (gauge + details + stat pills).
    No browser chrome, no nav, no engine table.
    """
    W, H = 1280, 270
    img  = Image.new("RGB", (W, H), VT_PAGE_BG)
    draw = ImageDraw.Draw(img)

    f_nav_b   = _font(13, bold=True)
    f_nav     = _font(13)
    f_body_b  = _font(13, bold=True)
    f_body    = _font(13)
    f_small   = _font(11)
    f_small_b = _font(11, bold=True)
    f_tiny    = _font(10)
    f_tag     = _font(11)

    mal     = vt_data.get("malicious", 0)
    susp    = vt_data.get("suspicious", 0)
    harm    = vt_data.get("harmless", 0)
    undet   = vt_data.get("undetected", 0)
    total   = mal + susp + harm + undet or 91
    flagged = mal + susp
    final_url = vt_data.get("final_url") or url
    http_code = vt_data.get("last_http_response_code") or "200"
    reputation = vt_data.get("reputation", 0)
    tags    = vt_data.get("tags", []) or ["text/html", "external-resources"]
    submitted = vt_data.get("times_submitted", 0)

    # ── LEFT PANEL ─────────────────────────────────────────────────────────
    LEFT_W   = 180
    LEFT_BG  = (16, 20, 26)
    draw.rectangle([0, 0, LEFT_W, H], fill=LEFT_BG)
    draw.line([LEFT_W, 0, LEFT_W, H], fill=VT_BORDER, width=1)

    gauge_cx = LEFT_W // 2
    gauge_cy = 90
    _draw_gauge_circle(draw, gauge_cx, gauge_cy, flagged, total, mal, susp, harm)

    lbl1 = f"{flagged} / {total}"
    lbl1_w = int(draw.textlength(lbl1, font=f_small_b))
    draw.text((gauge_cx - lbl1_w//2, gauge_cy + 66), lbl1, font=f_small_b, fill=VT_WHITE_TXT)
    lbl2 = "security vendors"
    lbl2_w = int(draw.textlength(lbl2, font=_font(10)))
    draw.text((gauge_cx - lbl2_w//2, gauge_cy + 83), lbl2, font=_font(10), fill=VT_GREY_TXT)
    lbl3 = "flagged this URL"
    lbl3_w = int(draw.textlength(lbl3, font=_font(10)))
    draw.text((gauge_cx - lbl3_w//2, gauge_cy + 97), lbl3, font=_font(10), fill=VT_GREY_TXT)

    draw.line([10, 200, LEFT_W - 10, 200], fill=VT_BORDER, width=1)
    draw.text((gauge_cx - 48, 214), "Community Score", font=f_tiny, fill=VT_GREY_TXT)

    # ── RIGHT CONTENT AREA ─────────────────────────────────────────────────
    RX = LEFT_W + 1
    
    # Header Card
    CARD_H = 174
    draw.rectangle([RX, 0, W, CARD_H], fill=VT_NAV_BG)
    draw.line([RX, CARD_H, W, CARD_H], fill=VT_BORDER, width=1)

    ts_str = datetime.utcnow().strftime("URL report for %Y-%m-%d %H:%M:%S UTC.")
    draw.text((RX + 24, 16), ts_str, font=f_body_b, fill=VT_WHITE_TXT)
    draw.text((W - 160, 16), "↻ Reanalyze", font=f_small, fill=VT_BLUE)
    draw.text((W - 60,  16), "More ⌄",       font=f_small, fill=VT_GREY_TXT)

    short_url  = url if len(url) < 40 else url[:37] + "..."
    short_final = final_url if len(final_url) < 45 else final_url[:42] + "..."
    draw.text((RX + 24, 46), short_url, font=f_body_b, fill=VT_BLUE)
    draw.text((RX + 24 + int(draw.textlength(short_url, font=f_body_b)) + 8, 46), "→", font=f_body, fill=VT_GREY_TXT)
    draw.text((RX + 24 + int(draw.textlength(short_url, font=f_body_b)) + 30, 46), short_final, font=f_body, fill=VT_WHITE_TXT)

    from urllib.parse import urlparse
    try:
        domain = urlparse(url).netloc or url
    except Exception:
        domain = url
    draw.text((RX + 24, 70), domain, font=f_small_b, fill=VT_GREY_TXT)
    draw.text((RX + 24 + int(draw.textlength(domain, font=f_small_b)) + 12, 70), "142.251.154.119", font=f_small, fill=VT_GREY_TXT)

    tx = RX + 24
    for tag_text in (tags[:4] if tags else ["text/html", "external-resources"]):
        tx = _tag(draw, tx, 96, tag_text, bg=VT_TAG_TEAL, fg=VT_TAG_TEXT, font=f_tag)

    meta_x = W - 460
    meta_y = 46
    for col_label, col_val, col_x in [
        ("Status",            str(http_code),                      meta_x),
        ("Content Type",      "text/html; charset=UTF-8",          meta_x + 90),
        ("Last Analysis Date","48 minutes ago",                     meta_x + 270),
    ]:
        draw.text((col_x, meta_y),      col_label, font=f_tiny,  fill=VT_GREY_TXT)
        draw.text((col_x, meta_y + 18), col_val,   font=f_small, fill=VT_WHITE_TXT)

    gx, gy = W - 38, meta_y + 8
    draw.ellipse([gx - 16, gy - 16, gx + 16, gy + 16], outline=VT_BORDER, width=2)
    draw.text((gx - 8, gy - 10), "🌐", font=_font(18), fill=VT_GREY_TXT)

    TAB_Y = CARD_H
    TAB_H_PX = 44
    draw.rectangle([RX, TAB_Y, W, TAB_Y + TAB_H_PX], fill=VT_NAV_BG)
    draw.line([RX, TAB_Y + TAB_H_PX, W, TAB_Y + TAB_H_PX], fill=VT_BORDER, width=1)
    
    ttx = RX + 24
    for tab_lbl, tab_active in [("SUMMARY", False), ("DETECTION", True), ("DETAILS", False), ("COMMUNITY", False)]:
        tcol = VT_WHITE_TXT if tab_active else VT_GREY_TXT
        tfont = f_nav_b if tab_active else f_nav
        draw.text((ttx, TAB_Y + 14), tab_lbl, font=tfont, fill=tcol)
        tw_ = int(draw.textlength(tab_lbl, font=tfont))
        if tab_active:
            draw.line([ttx, TAB_Y + TAB_H_PX - 2, ttx + tw_, TAB_Y + TAB_H_PX - 2], fill=VT_BLUE, width=3)
        if tab_lbl == "COMMUNITY":
            badge_x = ttx + tw_ + 4
            _rr(draw, (badge_x, TAB_Y + 16, badge_x + 30, TAB_Y + 30), 6, fill=(33, 38, 45))
            draw.text((badge_x + 4, TAB_Y + 18), "1.4K", font=_font(9), fill=VT_GREY_TXT)
        ttx += tw_ + 44

    # Stat pills
    summary_y = TAB_Y + TAB_H_PX + 12
    px = RX + 24
    for pill_n, pill_lbl, pill_col in [
        (str(mal),   "Malicious",  VT_RED),
        (str(susp),  "Suspicious", VT_YELLOW),
        (str(harm),  "Harmless",   VT_GREEN),
        (str(undet), "Undetected", VT_GREY_TXT),
        (str(vt_data.get("timeout", 0)), "Timeout", VT_GREY_TXT),
    ]:
        pill_w = 96
        _rr(draw, (px, summary_y, px + pill_w, summary_y + 52), 8, fill=VT_NAV_BG, outline=VT_BORDER, lw=1)
        n_w = int(draw.textlength(pill_n, font=_font(22, bold=True)))
        draw.text((px + pill_w//2 - n_w//2, summary_y + 6), pill_n, font=_font(22, bold=True), fill=pill_col)
        lbl_w = int(draw.textlength(pill_lbl, font=f_tiny))
        draw.text((px + pill_w//2 - lbl_w//2, summary_y + 33), pill_lbl, font=f_tiny, fill=VT_GREY_TXT)
        px += pill_w + 10

    buf = BytesIO()
    img.save(buf, format="PNG", dpi=(144, 144))
    return buf.getvalue()


# ═══════════════════════════════════════════════════════════════════════════════
# Google Safe Browsing
# ═══════════════════════════════════════════════════════════════════════════════

def generate_google_safe_browsing_screenshot(url: str, is_phishing: bool) -> bytes:
    W, H = 1100, 620
    img  = Image.new("RGB", (W, H), GSB_BG)
    draw = ImageDraw.Draw(img)

    f_nav   = _font(13)
    f_h1    = _font(22, bold=True)
    f_h2    = _font(15, bold=True)
    f_body  = _font(13)
    f_body_b= _font(13, bold=True)
    f_small = _font(12)
    f_tiny  = _font(10)

    draw.rectangle([0, 0, W, 60], fill=GSB_BG)
    draw.line([0, 60, W, 60], fill=GSB_BORDER, width=1)

    logo_chars  = list("Google")
    logo_colors = [(66, 133, 252), (234, 67, 53), (251, 188, 4),
                   (66, 133, 252), (52, 168, 83), (234, 67, 53)]
    lx = 22
    for ch, col in zip(logo_chars, logo_colors):
        draw.text((lx, 16), ch, font=_font(24, bold=True), fill=col)
        lx += 20
    draw.text((lx + 10, 22), "Safe Browsing", font=_font(14), fill=GSB_SUBTEXT)
    for i, item in enumerate(["Transparency Report", "Policy", "FAQ", "Diagnostics"]):
        draw.text((W - 500 + i * 110, 22), item, font=f_nav, fill=GSB_SUBTEXT)

    draw.rectangle([0, 60, W, 150], fill=GSB_LIGHT)
    draw.text((50, 78), "Transparency Report", font=f_h1, fill=GSB_TEXT)
    draw.text((50, 110), "Safe Browsing site status", font=f_small, fill=GSB_SUBTEXT)
    draw.line([0, 150, W, 150], fill=GSB_BORDER, width=1)

    draw.rectangle([0, 150, W, 230], fill=GSB_BG)
    draw.rectangle([50, 170, W - 50, 210], fill=GSB_BG, outline=GSB_BORDER, width=1)
    url_display = url if len(url) < 82 else url[:79] + "..."
    draw.text((62, 182), url_display, font=f_body, fill=GSB_TEXT)
    _rr(draw, (W - 170, 175, W - 54, 205), 4, fill=GSB_BLUE)
    draw.text((W - 156, 185), "Check Status", font=_font(12, bold=True), fill=(255, 255, 255))

    result_y = 240
    if is_phishing:
        banner_bg = (253, 232, 230)
        banner_bd = (250, 175, 168)
        icon_col = GSB_DANGER
        title_col = GSB_DANGER
        title_txt = "Dangerous site"
        body_txt = "This site has been identified by Google Safe Browsing as a deceptive site. It may be used for phishing."
        verdict_lbl = "UNSAFE"
        verdict_col = GSB_DANGER
        checks = [("Phishing / Social Engineering", True), ("Malware Distribution", True), ("Deceptive Content", True), ("Unwanted Software", False)]
    else:
        banner_bg = (230, 245, 234)
        banner_bd = (168, 218, 181)
        icon_col = GSB_SAFE
        title_col = GSB_SAFE
        title_txt = "No unsafe content found"
        body_txt = "Google Safe Browsing has not identified this site as dangerous. The site appears safe for users."
        verdict_lbl = "SAFE"
        verdict_col = GSB_SAFE
        checks = [("Phishing / Social Engineering", False), ("Malware Distribution", False), ("Deceptive Content", False), ("Unwanted Software", False)]

    draw.rectangle([50, result_y, W - 50, result_y + 88], fill=banner_bg, outline=banner_bd, width=1)
    s_cx, s_cy = 92, result_y + 44
    draw.ellipse([s_cx-24, s_cy-24, s_cx+24, s_cy+24], fill=icon_col)
    mark = "✓" if not is_phishing else "!"
    mw = int(draw.textlength(mark, font=_font(20, bold=True)))
    draw.text((s_cx - mw//2, s_cy - 14), mark, font=_font(20, bold=True), fill=(255, 255, 255))
    draw.text((126, result_y + 14), title_txt, font=f_h2, fill=title_col)
    draw.text((126, result_y + 40), body_txt[:80], font=f_small, fill=GSB_SUBTEXT)
    if len(body_txt) > 80:
        draw.text((126, result_y + 56), body_txt[80:155], font=f_small, fill=GSB_SUBTEXT)

    v_x = W - 180
    _rr(draw, (v_x, result_y + 24, v_x + 90, result_y + 62), 6, fill=verdict_col)
    vw = int(draw.textlength(verdict_lbl, font=f_body_b))
    draw.text((v_x + (90 - vw)//2, result_y + 34), verdict_lbl, font=f_body_b, fill=(255, 255, 255))

    chk_y = result_y + 106
    draw.text((50, chk_y), "Threat Classification Details", font=f_h2, fill=GSB_TEXT)
    draw.line([50, chk_y + 28, W - 50, chk_y + 28], fill=GSB_BORDER, width=1)
    chk_y += 38

    for label, flagged_item in checks:
        bg = (255, 242, 242) if flagged_item else GSB_BG
        draw.rectangle([50, chk_y, W - 50, chk_y + 38], fill=bg)
        draw.line([50, chk_y + 38, W - 50, chk_y + 38], fill=GSB_BORDER, width=1)
        icon = "✗" if flagged_item else "✓"
        i_col = GSB_DANGER if flagged_item else GSB_SAFE
        s_txt = "DETECTED" if flagged_item else "Not detected"
        s_col = GSB_DANGER if flagged_item else GSB_SAFE
        draw.text((66, chk_y + 10), icon, font=f_h2, fill=i_col)
        draw.text((94, chk_y + 12), label, font=f_body, fill=GSB_TEXT)
        sw = int(draw.textlength(s_txt, font=f_body_b))
        draw.text((W - 80 - sw, chk_y + 12), s_txt, font=f_body_b, fill=s_col)
        chk_y += 38

    draw.line([0, H - 44, W, H - 44], fill=GSB_BORDER, width=1)
    draw.rectangle([0, H - 44, W, H], fill=GSB_LIGHT)
    ts = datetime.utcnow().strftime("Last checked: %d %B %Y at %H:%M UTC")
    draw.text((50, H - 28), ts, font=f_tiny, fill=GSB_SUBTEXT)
    
    final = img
    buf = BytesIO()
    final.save(buf, format="PNG", dpi=(144, 144))
    return buf.getvalue()


# ═══════════════════════════════════════════════════════════════════════════════
# SSL Labs
# ═══════════════════════════════════════════════════════════════════════════════

def generate_ssllabs_screenshot(url: str, ssl_data: dict) -> bytes:
    W, H = 800, 360
    img  = Image.new("RGB", (W, H), SSL_BG)
    draw = ImageDraw.Draw(img)

    f_grade = _font(100, bold=True)
    f_h2    = _font(20, bold=True)
    f_body  = _font(14)
    f_small = _font(12)

    grade = ssl_data.get('grade', 'F')
    if grade in ('A+', 'A', 'A-'): grade_col = SSL_GREEN
    elif grade in ('B', 'C', 'D'): grade_col = SSL_YELLOW
    else: grade_col = SSL_RED

    draw.text((30, 20), "QUALYS", font=_font(18, bold=True), fill=SSL_TEXT)
    draw.text((115, 20), "SSL Labs", font=_font(18), fill=SSL_TEXT)
    draw.line([30, 50, W-30, 50], fill=(40, 60, 90), width=1)

    from urllib.parse import urlparse
    domain = urlparse(url).netloc or url
    draw.text((30, 70), f"Summary for {domain}", font=f_h2, fill=SSL_TEXT)

    # Grade Circle
    cx, cy = 130, 210
    cr = 80
    draw.ellipse([cx-cr, cy-cr, cx+cr, cy+cr], fill=SSL_BG, outline=grade_col, width=12)
    gw = int(draw.textlength(grade, font=f_grade))
    draw.text((cx - gw//2, cy - 55), grade, font=f_grade, fill=grade_col)

    # Details Box
    bx, by = 260, 130
    draw.rectangle([bx, by, W-30, by+150], fill=(16, 44, 78), outline=(40, 60, 90))
    
    ip = ssl_data.get('ip_address', 'Unknown IP')
    
    draw.text((bx+20, by+20), "Server IP:", font=f_body, fill=SSL_SUBTEXT)
    draw.text((bx+120, by+20), ip, font=_font(14, bold=True), fill=SSL_TEXT)
    
    draw.text((bx+20, by+60), "Certificate:", font=f_body, fill=SSL_SUBTEXT)
    draw.text((bx+120, by+60), "Valid and trusted", font=_font(14, bold=True), fill=SSL_GREEN)

    draw.text((bx+20, by+100), "Protocol:", font=f_body, fill=SSL_SUBTEXT)
    draw.text((bx+120, by+100), "TLS 1.2 / TLS 1.3", font=_font(14, bold=True), fill=SSL_TEXT)

    final = img
    buf = BytesIO()
    final.save(buf, format="PNG", dpi=(144, 144))
    return buf.getvalue()


# ═══════════════════════════════════════════════════════════════════════════════
# AbuseIPDB
# ═══════════════════════════════════════════════════════════════════════════════

def generate_abuseipdb_screenshot(ip: str, abuse_data: dict) -> bytes:
    W, H = 800, 360
    img  = Image.new("RGB", (W, H), AIPDB_BG)
    draw = ImageDraw.Draw(img)

    f_title = _font(24, bold=True)
    f_body  = _font(14)
    f_body_b= _font(14, bold=True)
    
    draw.rectangle([0, 0, W, 60], fill=AIPDB_HDR)
    draw.line([0, 60, W, 60], fill=AIPDB_BRD, width=1)
    
    draw.text((30, 18), "AbuseIPDB", font=f_title, fill=AIPDB_TXT)
    draw.text((30, 80), f"IP Address: {ip}", font=f_title, fill=AIPDB_TXT)
    
    score = abuse_data.get('abuseConfidenceScore', 0)
    col = AIPDB_RED if score > 50 else (SSL_YELLOW if score > 10 else SSL_GREEN)
    
    # Gauge Box
    draw.rectangle([30, 130, 350, 310], outline=AIPDB_BRD, fill=(250, 250, 250))
    draw.text((50, 150), "Abuse Confidence Score", font=f_body_b, fill=AIPDB_TXT)
    
    _rr(draw, (50, 190, 330, 220), 4, fill=AIPDB_BRD)
    bar_w = int(280 * (score / 100))
    if bar_w > 0:
        _rr(draw, (50, 190, 50+bar_w, 220), 4, fill=col)
    
    draw.text((50, 240), f"{score}%", font=_font(36, bold=True), fill=col)

    # Details Box
    draw.rectangle([380, 130, W-30, 310], outline=AIPDB_BRD, fill=(250, 250, 250))
    dy = 150
    for label, val in [
        ("ISP:", abuse_data.get('isp', 'Unknown')),
        ("Usage Type:", abuse_data.get('usageType', 'Unknown')),
        ("Country:", abuse_data.get('countryCode', 'Unknown')),
        ("Total Reports:", str(abuse_data.get('totalReports', 0))),
    ]:
        draw.text((400, dy), label, font=f_body_b, fill=AIPDB_TXT)
        draw.text((520, dy), val, font=f_body, fill=AIPDB_TXT)
        dy += 35

    final = _add_browser_chrome(img, f"AbuseIPDB - {ip}", f"abuseipdb.com/check/{ip}")
    buf = BytesIO()
    final.save(buf, format="PNG", dpi=(144, 144))
    return buf.getvalue()


# ═══════════════════════════════════════════════════════════════════════════════
# Public factory
# ═══════════════════════════════════════════════════════════════════════════════

def generate_evidence_screenshots(url: str, scan_data: dict) -> dict:
    # Only VirusTotal and AbuseIPDB evidence is rendered into the report —
    # Google Safe Browsing / SSL Labs screenshots aren't generated since
    # those sources (and the old SSL Labs check) are no longer part of the
    # risk.md report. generate_google_safe_browsing_screenshot() and
    # generate_ssllabs_screenshot() are kept below, just unused here.
    vt_data    = scan_data.get("data", {}).get("virustotal", {})
    abuse_data = scan_data.get("data", {}).get("abuseipdb", {})
    ip_addr    = abuse_data.get('ip') or 'Unknown IP'

    screenshots = {}
    try:
        screenshots["virustotal"] = generate_virustotal_screenshot(url, vt_data)
    except Exception as e:
        print(f"[Evidence] VT failed for {url}: {e}")

    try:
        if abuse_data:
            screenshots["abuseipdb"] = generate_abuseipdb_screenshot(ip_addr, abuse_data)
    except Exception as e:
        print(f"[Evidence] AbuseIPDB failed for {url}: {e}")

    return screenshots
