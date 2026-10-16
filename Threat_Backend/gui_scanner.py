"""
gui_scanner.py — Enterprise-grade CustomTkinter GUI Dashboard for ThreatScanner.

Opens as a windowed (non-console) application.
Shortcuts created by the installer will point here.
The CLI version (cli_scanner.py) remains separately accessible.
"""

import sys
import os
import threading
from datetime import datetime

# Ensure 'app' module can be imported when run from the dist directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Apply SSL fix for corporate proxies (e.g. Zscaler on bank laptops)
try:
    from app.utils.ssl_patch import apply_ssl_patch
    apply_ssl_patch()
except Exception:
    pass

import customtkinter as ctk
from tkinter import filedialog, messagebox

import fonts
from updater import check_for_updates
from version import APP_VERSION

# ─── Theme ────────────────────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ── Palette (ICICI brand navy/orange, refined for an enterprise dashboard) ────
ORANGE       = "#F37224"
ORANGE_HOVER = "#D9631A"
NAVY         = "#1C3E73"
NAVY_HOVER   = "#16305C"
RED          = "#EF4444"
GREEN        = "#22C55E"
BLUE         = "#3B82F6"

BG          = "#0B1220"   # app background
SURFACE     = "#101A2E"   # header / footer surface
CARD        = "#161F35"   # card panels
INSET       = "#0B1220"   # recessed inputs (text boxes, entries)
BORDER      = "#26314A"   # card / divider borders
BORDER_SOFT = "#1E2A42"
TEXT        = "#F1F5F9"
MUTED       = "#8C99B4"

APP_FONT = fonts.FONT_FAMILY_FALLBACK  # resolved to Mulish at runtime if available


def F(size: int, weight: str = "normal") -> ctk.CTkFont:
    """Shorthand for a UI-scale font using the resolved brand typeface."""
    return ctk.CTkFont(family=APP_FONT, size=size, weight=weight)


# ─────────────────────────────────────────────────────────────────────────────
class ThreatScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Load + resolve the bundled Mulish font before any widget is built.
        fonts.load_custom_fonts()
        global APP_FONT
        APP_FONT = fonts.resolve_family(self)

        self.title(f"URL Threat Scanner  v{APP_VERSION}")
        self.geometry("1080x760")
        self.minsize(900, 640)
        self.configure(fg_color=BG)

        # Set window icon if available
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "Installer", "app_icon.ico")
        if os.path.exists(icon_path):
            try:
                self.iconbitmap(icon_path)
            except Exception:
                pass

        self._build_ui()

        # Run update check in background so UI doesn't block
        threading.Thread(target=self._background_update_check, daemon=True).start()

    # ── Background update check ───────────────────────────────────────────────
    def _background_update_check(self):
        check_for_updates(
            current_version=APP_VERSION,
            silent=True,
            log_callback=lambda msg: self.after(0, self._append_log, msg),
        )

    # ── Manual "Check for Updates" button ─────────────────────────────────────
    def _check_updates_clicked(self):
        self.update_btn.configure(state="disabled", text="Checking…")
        self._append_log("[*] Checking for updates (manual)…")
        threading.Thread(target=self._manual_update_check, daemon=True).start()

    def _manual_update_check(self):
        # If an update is found, check_for_updates() launches the installer
        # and calls sys.exit(0) itself, so anything after this line only
        # runs when we're already up to date or the check failed.
        check_for_updates(
            current_version=APP_VERSION,
            silent=True,
            log_callback=lambda msg: self.after(0, self._append_log, msg),
        )
        self.after(0, self._manual_update_check_done)

    def _manual_update_check_done(self):
        self.update_btn.configure(state="normal", text="⟳  Check for Updates")
        messagebox.showinfo(
            "Check for Updates",
            f"You're up to date on version {APP_VERSION}.\n\n"
            "(If a newer version was found it is installing now — the app "
            "will close automatically to complete the update.)",
        )

    # ── UI Construction ───────────────────────────────────────────────────────
    def _build_ui(self):
        self._build_header()

        # ── Main layout: left panel + right log ───────────────────────────────
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=20, pady=(14, 8))
        body.columnconfigure(0, weight=3)
        body.columnconfigure(1, weight=2)
        body.rowconfigure(0, weight=1)

        self._build_left_panel(body)
        self._build_right_panel(body)

        self._build_footer()

    def _build_header(self):
        header = ctk.CTkFrame(self, fg_color=SURFACE, corner_radius=0, height=72)
        header.pack(fill="x", side="top")
        header.pack_propagate(False)

        # ── Brand mark + title ────────────────────────────────────────────────
        brand = ctk.CTkFrame(header, fg_color="transparent")
        brand.pack(side="left", padx=(24, 0), fill="y")

        mark = ctk.CTkFrame(brand, fg_color=ORANGE, corner_radius=10, width=40, height=40)
        mark.pack(side="left", pady=16)
        mark.pack_propagate(False)
        ctk.CTkLabel(mark, text="🛡", font=F(18), text_color="white").place(relx=0.5, rely=0.5, anchor="center")

        titles = ctk.CTkFrame(brand, fg_color="transparent")
        titles.pack(side="left", padx=(12, 0), pady=10)
        ctk.CTkLabel(
            titles,
            text="URL Threat Scanner",
            font=F(19, "bold"),
            text_color="white",
            anchor="w",
        ).pack(anchor="w")
        ctk.CTkLabel(
            titles,
            text="Enterprise Security Assessment Platform",
            font=F(11),
            text_color=MUTED,
            anchor="w",
        ).pack(anchor="w")

        # ── Right-side actions ────────────────────────────────────────────────
        right_header = ctk.CTkFrame(header, fg_color="transparent")
        right_header.pack(side="right", padx=24)

        version_chip = ctk.CTkFrame(right_header, fg_color=CARD, corner_radius=6, border_width=1, border_color=BORDER)
        version_chip.pack(side="left", padx=(0, 12))
        ctk.CTkLabel(
            version_chip,
            text=f"v{APP_VERSION}",
            font=F(11, "bold"),
            text_color="#93C5FD",
        ).pack(padx=10, pady=4)

        self.update_btn = self._outline_button(
            right_header, text="⟳  Check for Updates", command=self._check_updates_clicked, width=150,
        )
        self.update_btn.pack(side="left", padx=(0, 8))

        self._outline_button(
            right_header, text="ℹ  About", command=self._show_about, width=80,
        ).pack(side="left")

    def _outline_button(self, parent, text, command, width=100):
        return ctk.CTkButton(
            parent,
            text=text,
            width=width,
            height=30,
            fg_color="transparent",
            border_color=BORDER,
            border_width=1,
            text_color=TEXT,
            hover_color=CARD,
            font=F(11, "bold"),
            corner_radius=7,
            command=command,
        )

    def _build_footer(self):
        footer = ctk.CTkFrame(self, fg_color=SURFACE, corner_radius=0, height=30)
        footer.pack(fill="x", side="bottom")
        footer.pack_propagate(False)

        ctk.CTkLabel(
            footer,
            text="ICICI Bank — Information Security Group",
            font=F(10),
            text_color=MUTED,
        ).pack(side="left", padx=20)

        ctk.CTkLabel(
            footer,
            text=f"© {datetime.now().year} · For authorised internal use only",
            font=F(10),
            text_color=MUTED,
        ).pack(side="right", padx=20)

    def _build_left_panel(self, parent):
        # Scrollable so fields/buttons never overlap or get clipped when the
        # window is resized smaller than the content's natural height —
        # it scrolls instead of overlapping.
        panel = ctk.CTkScrollableFrame(
            parent,
            fg_color=CARD,
            corner_radius=14,
            border_width=1,
            border_color=BORDER,
            label_text="",
        )
        panel.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        panel.columnconfigure(0, weight=1)

        # ── Section: URL Input ────────────────────────────────────────────────
        self._section_label(panel, "URLs to Scan", row=0)

        self.url_box = ctk.CTkTextbox(
            panel,
            height=150,
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=INSET,
            border_color=BORDER,
            border_width=1,
            text_color=TEXT,
            corner_radius=8,
        )
        self.url_box.grid(row=1, column=0, padx=18, pady=(6, 2), sticky="ew")
        self.url_box.insert("end", "https://example.com\nhttps://another-url.com")

        ctk.CTkLabel(
            panel,
            text="Enter one URL per line",
            font=F(11),
            text_color=MUTED,
        ).grid(row=2, column=0, padx=20, sticky="w", pady=(0, 8))

        # ── OR: load from file ────────────────────────────────────────────────
        self._outline_button(
            panel, text="📂  Load from urls.txt", command=self._load_from_file, width=170,
        ).grid(row=3, column=0, padx=18, pady=(0, 14), sticky="w")

        # ── Scan button (kept near the top so it stays reachable at any
        #    window size, instead of scrolling off the bottom of the panel) ──
        self.scan_btn = ctk.CTkButton(
            panel,
            text="▶   Run Threat Scan",
            command=self._start_scan,
            height=48,
            fg_color=ORANGE,
            hover_color=ORANGE_HOVER,
            text_color="white",
            font=F(15, "bold"),
            corner_radius=10,
        )
        self.scan_btn.grid(row=4, column=0, padx=18, pady=(0, 8), sticky="ew")

        # ── Progress bar ──────────────────────────────────────────────────────
        self.progress = ctk.CTkProgressBar(panel, fg_color=BORDER, progress_color=ORANGE, corner_radius=4, height=6)
        self.progress.set(0)
        self.progress.grid(row=5, column=0, padx=18, pady=(0, 12), sticky="ew")

        # ── Divider ───────────────────────────────────────────────────────────
        ctk.CTkFrame(panel, height=1, fg_color=BORDER_SOFT).grid(row=6, column=0, sticky="ew", padx=18, pady=6)

        # ── Section: Report Details ───────────────────────────────────────────
        self._section_label(panel, "Report Details", row=7)

        self.app_name_var = ctk.StringVar()
        self.can_id_var   = ctk.StringVar()
        self.server_ip_var = ctk.StringVar()
        self.request_id_var = ctk.StringVar()

        fields = [
            ("Application Name",         self.app_name_var,   "e.g. Net Banking Portal"),
            ("CAN ID",                   self.can_id_var,     "e.g. CAN-12345"),
            ("Server IP (optional)",     self.server_ip_var,  "e.g. 10.0.0.1"),
            ("Request ID (optional)",    self.request_id_var, "e.g. SN1, SN2, SN3"),
        ]
        for i, (label, var, placeholder) in enumerate(fields):
            ctk.CTkLabel(
                panel,
                text=label,
                font=F(12),
                text_color=MUTED,
                anchor="w",
            ).grid(row=8 + i * 2, column=0, padx=20, pady=(8, 0), sticky="w")
            ctk.CTkEntry(
                panel,
                textvariable=var,
                placeholder_text=placeholder,
                fg_color=INSET,
                border_color=BORDER,
                border_width=1,
                text_color=TEXT,
                font=F(12),
                height=36,
                corner_radius=8,
            ).grid(row=9 + i * 2, column=0, padx=18, pady=(3, 0), sticky="ew")

        # ── Final comment ─────────────────────────────────────────────────────
        ctk.CTkLabel(
            panel,
            text="Final Assessment Comment",
            font=F(12),
            text_color=MUTED,
            anchor="w",
        ).grid(row=16, column=0, padx=20, pady=(10, 0), sticky="w")

        self.comment_box = ctk.CTkTextbox(
            panel,
            height=80,
            font=F(12),
            fg_color=INSET,
            border_color=BORDER,
            border_width=1,
            text_color=TEXT,
            corner_radius=8,
        )
        self.comment_box.grid(row=17, column=0, padx=18, pady=(3, 16), sticky="ew")

    def _build_right_panel(self, parent):
        panel = ctk.CTkFrame(parent, fg_color=CARD, corner_radius=14, border_width=1, border_color=BORDER)
        panel.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        panel.columnconfigure(0, weight=1)
        panel.rowconfigure(1, weight=1)

        # Header row
        hdr = ctk.CTkFrame(panel, fg_color="transparent")
        hdr.grid(row=0, column=0, padx=16, pady=(16, 8), sticky="ew")
        hdr.columnconfigure(0, weight=1)

        ctk.CTkLabel(
            hdr,
            text="Scan Activity Log",
            font=F(13, "bold"),
            text_color=TEXT,
            anchor="w",
        ).grid(row=0, column=0, sticky="w")

        ctk.CTkButton(
            hdr,
            text="Clear",
            width=60,
            height=26,
            fg_color="transparent",
            border_color=BORDER,
            border_width=1,
            text_color=MUTED,
            hover_color=BG,
            font=F(11),
            corner_radius=6,
            command=self._clear_log,
        ).grid(row=0, column=1, sticky="e")

        self.log_box = ctk.CTkTextbox(
            panel,
            font=ctk.CTkFont(family="Consolas", size=11),
            fg_color=INSET,
            text_color="#CBD5E1",
            border_width=1,
            border_color=BORDER_SOFT,
            corner_radius=10,
            wrap="word",
            state="disabled",
        )
        self.log_box.grid(row=1, column=0, padx=12, pady=(0, 12), sticky="nsew")

        # Status / result badge at bottom
        status_bar = ctk.CTkFrame(panel, fg_color="transparent")
        status_bar.grid(row=2, column=0, padx=16, pady=(0, 14), sticky="ew")

        self.status_label = ctk.CTkLabel(
            status_bar,
            text="●  Ready",
            font=F(12, "bold"),
            text_color=GREEN,
            anchor="w",
        )
        self.status_label.pack(anchor="w")

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _section_label(self, parent, text: str, row: int):
        wrap = ctk.CTkFrame(parent, fg_color="transparent")
        wrap.grid(row=row, column=0, padx=18, pady=(16, 6), sticky="w")
        ctk.CTkFrame(wrap, width=4, height=16, fg_color=ORANGE, corner_radius=2).pack(side="left", padx=(0, 8))
        ctk.CTkLabel(
            wrap,
            text=text,
            font=F(13, "bold"),
            text_color=TEXT,
        ).pack(side="left")

    def _append_log(self, msg: str):
        self.log_box.configure(state="normal")
        self.log_box.insert("end", msg + "\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def _clear_log(self):
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.configure(state="disabled")

    def _show_about(self):
        about_window = ctk.CTkToplevel(self)
        about_window.title("About URL Threat Scanner")
        about_window.geometry("420x360")
        about_window.resizable(False, False)
        about_window.attributes("-topmost", True)
        about_window.configure(fg_color=BG)

        # Center the window
        about_window.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() // 2) - (420 // 2)
        y = self.winfo_y() + (self.winfo_height() // 2) - (360 // 2)
        about_window.geometry(f"+{x}+{y}")

        content = ctk.CTkFrame(about_window, fg_color=CARD, corner_radius=12, border_width=1, border_color=BORDER)
        content.pack(fill="both", expand=True, padx=16, pady=16)

        mark = ctk.CTkFrame(content, fg_color=ORANGE, corner_radius=12, width=52, height=52)
        mark.pack(pady=(24, 10))
        mark.pack_propagate(False)
        ctk.CTkLabel(mark, text="🛡", font=F(22), text_color="white").place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(content, text="URL Threat Scanner", font=F(17, "bold"), text_color=TEXT).pack()
        ctk.CTkLabel(content, text="Enterprise Security Assessment Platform", font=F(11), text_color=MUTED).pack(pady=(2, 14))

        ctk.CTkFrame(content, height=1, fg_color=BORDER_SOFT).pack(fill="x", padx=24, pady=(0, 12))

        info = [
            ("Version", f"{APP_VERSION}"),
            ("Developed by", "Kunal Kumar"),
            ("Developed date", "Sept 2026"),
            ("Authorised to use", "ICICI Bank Members"),
        ]

        for label, val in info:
            row = ctk.CTkFrame(content, fg_color="transparent")
            row.pack(fill="x", padx=30, pady=4)
            ctk.CTkLabel(row, text=label, font=F(12, "bold"), text_color=MUTED, width=130, anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=val, font=F(12), text_color=TEXT, anchor="w").pack(side="left")

        ctk.CTkButton(
            content, text="Close", width=110, height=34,
            fg_color=NAVY, hover_color=NAVY_HOVER, font=F(12, "bold"),
            command=about_window.destroy
        ).pack(pady=(18, 10))

    def _load_from_file(self):
        path = filedialog.askopenfilename(
            title="Select URL list file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "r") as f:
                content = f.read()
            self.url_box.delete("1.0", "end")
            self.url_box.insert("end", content)
            self._append_log(f"[*] Loaded URLs from: {path}")
        except Exception as e:
            messagebox.showerror("Load Error", str(e))

    # ── Scan Orchestration ────────────────────────────────────────────────────
    def _start_scan(self):
        # Collect URLs
        raw = self.url_box.get("1.0", "end").strip()
        urls = [u.strip() for u in raw.splitlines() if u.strip()]
        if not urls:
            messagebox.showwarning("No URLs", "Please enter at least one URL to scan.")
            return

        # Collect metadata
        app_name    = self.app_name_var.get().strip() or None
        can_id      = self.can_id_var.get().strip() or None
        server_ip   = self.server_ip_var.get().strip() or None
        request_id  = self.request_id_var.get().strip() or None
        final_comment = self.comment_box.get("1.0", "end").strip() or ""

        # Disable button, reset progress
        self.scan_btn.configure(state="disabled", text="⏳  Scanning…")
        self.progress.set(0)
        self.status_label.configure(text=f"●  Scanning… (0/{len(urls)})", text_color=ORANGE)
        self._clear_log()
        self._append_log(f"[*] Starting scan for {len(urls)} URL(s)…")

        # Run in background thread so UI stays responsive
        threading.Thread(
            target=self._run_scan,
            args=(urls, app_name, can_id, server_ip, request_id, final_comment),
            daemon=True,
        ).start()

    def _run_scan(self, urls, app_name, can_id, server_ip, request_id, final_comment):
        try:
            from concurrent.futures import ThreadPoolExecutor, as_completed
            from app.services.scanner import scan_url_service
            from app.services.pdf_report import generate_pdf_report

            total = len(urls)
            self.after(0, self._append_log, f"[*] Scanning {total} URL(s) — respecting API rate limits…")

            results_by_index = {}
            done_count = 0
            with ThreadPoolExecutor(max_workers=min(20, total), thread_name_prefix="gui-scan") as executor:
                future_to_index = {
                    executor.submit(scan_url_service, url): i for i, url in enumerate(urls)
                }
                for future in as_completed(future_to_index):
                    idx = future_to_index[future]
                    url = urls[idx]
                    try:
                        result = future.result()
                        results_by_index[idx] = result
                        level = result.get("final_risk_level", "Unknown")
                        log_line = f"[+] {url} — {level}"
                    except Exception as exc:
                        results_by_index[idx] = {"url": url, "final_risk_level": "Unknown", "error": str(exc)}
                        log_line = f"[-] {url} — failed: {exc}"

                    done_count += 1
                    self.after(0, self._append_log, f"[{done_count}/{total}] {log_line}")
                    self.after(0, self.progress.set, done_count / total)
                    self.after(0, self.status_label.configure, {"text": f"●  Scanning… ({done_count}/{total})"})

            results = [results_by_index[i] for i in range(total)]
            self.after(0, self._append_log, f"[+] Scans complete for {len(results)} URL(s).")
            self.after(0, self._append_log, "[*] Generating PDF report…")

            pdf_bytes = generate_pdf_report(
                results,
                final_comment=final_comment,
                app_name=app_name,
                can_id=can_id,
                server_ip=server_ip,
                request_id=request_id,
            )

            # Ask user where to save
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            default_name = f"threat_report_{timestamp}.pdf"

            def _save_dialog():
                save_path = filedialog.asksaveasfilename(
                    title="Save Threat Report",
                    initialfile=default_name,
                    defaultextension=".pdf",
                    filetypes=[("PDF files", "*.pdf")],
                )
                if save_path:
                    with open(save_path, "wb") as f:
                        f.write(pdf_bytes)
                    self._append_log(f"[+] Report saved to: {save_path}")
                    self.status_label.configure(text="●  Report Saved", text_color=GREEN)
                else:
                    self._append_log("[!] Save cancelled.")
                    self.status_label.configure(text="●  Done (not saved)", text_color=MUTED)

            self.after(0, _save_dialog)

        except Exception as exc:
            self.after(0, self._append_log, f"[-] Error: {exc}")
            self.after(0, self.status_label.configure, {"text": f"●  Error: {exc}", "text_color": RED})
        finally:
            self.after(0, self._scan_done)

    def _scan_done(self):
        self.progress.stop()
        self.progress.set(1)
        self.scan_btn.configure(state="normal", text="▶   Run Threat Scan")


# ─── Entry Point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = ThreatScannerApp()
    app.mainloop()
