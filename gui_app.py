#!/usr/bin/env python3
"""
=================================================================
   PII GUARDIAN v3.0 — Modern Enterprise Desktop Application
   India Regulatory Focus | 100% Offline Data Discovery
=================================================================
"""

from __future__ import annotations

import os
import sys
import time
import queue
import json
import threading
import subprocess
import pathlib
import datetime
import customtkinter as ctk

# Import scanner core engine
import pii_scanner_india as scanner

# Import new modules
try:
    from report.heatmap_generator import generate_heatmap
    HAS_HEATMAP = True
except ImportError:
    HAS_HEATMAP = False

try:
    from connectors.connector_registry import list_connector_types, connector_for_target
    HAS_CONNECTORS = True
except ImportError:
    HAS_CONNECTORS = False

# Configure CustomTkinter design system
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class PIIGuardianApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window Configuration
        self.title("PII Guardian v3.0 — Enterprise Data Discovery & Compliance")
        self.geometry("1180x820")
        self.minsize(1040, 720)
        self.configure(fg_color="#0B0F19")  # Deep Cyber Slate background

        # State Variables
        default_target = scanner.DEFAULT_TARGET.resolve() if scanner.DEFAULT_TARGET.exists() else pathlib.Path.cwd()
        self.target_path_var = ctk.StringVar(value=str(default_target))
        self.output_dir_var = ctk.StringVar(value=str(scanner.DEFAULT_REPORTS_DIR.resolve()))
        self.filter_var = ctk.StringVar()
        self.filter_var.trace_add("write", self._on_filter_changed)
        self._filter_timer = None

        self.is_scanning = False
        self.scan_thread = None
        self.ui_queue = queue.Queue()
        self.start_time: float = 0.0
        self.timer_running = False

        self.all_findings = []
        self.all_file_audit = []
        self.latest_report_path = ""
        self.latest_heatmap_path = ""
        self._db_config = None
        self.MAX_UI_CARDS = 150
        self.displayed_finding_cards = 0
        self.show_cap_banner = False

        # Build UI Architecture
        self._build_ui()
        self.after(100, self._process_queue)
        self._check_engine_status()

    # ===================================================================
    # UI CONSTRUCTION (EXECUTIVE DESIGN SYSTEM)
    # ===================================================================
    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        # ---------------------------------------------------------------
        # 1. HEADER BANNER (#0B0F19 background with glowing accents)
        # ---------------------------------------------------------------
        header_frame = ctk.CTkFrame(self, fg_color="#0F172A", corner_radius=0, height=80, border_width=1, border_color="#1E293B")
        header_frame.grid(row=0, column=0, sticky="ew", padx=0, pady=0)
        header_frame.grid_columnconfigure(0, weight=1)

        # Left Branding
        brand_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        brand_frame.grid(row=0, column=0, sticky="w", padx=24, pady=12)

        header_title = ctk.CTkLabel(
            brand_frame,
            text="🛡️ PII GUARDIAN",
            font=ctk.CTkFont(family="Segoe UI", size=22, weight="bold"),
            text_color="#38BDF8"
        )
        header_title.pack(side="left", anchor="w")

        version_pill = ctk.CTkLabel(
            brand_frame,
            text="v3.0.0 PRO",
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            fg_color="#0284C7",
            text_color="#FFFFFF",
            corner_radius=4,
            padx=6,
            pady=2
        )
        version_pill.pack(side="left", padx=8)

        header_subtitle = ctk.CTkLabel(
            brand_frame,
            text="Enterprise Offline Data Discovery • DPDP Act 2023 | RBI | SEBI | CERT-In Focus",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color="#94A3B8"
        )
        header_subtitle.pack(anchor="w", pady=(2, 0))

        # Right Status Badges (Pill Indicators)
        status_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        status_frame.grid(row=0, column=1, sticky="e", padx=24, pady=12)

        self.ner_badge = ctk.CTkLabel(
            status_frame,
            text="🧠 NER: INITIALIZING...",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            fg_color="#1E293B",
            text_color="#38BDF8",
            corner_radius=6,
            padx=12,
            pady=6
        )
        self.ner_badge.pack(side="left", padx=4)

        self.ocr_badge = ctk.CTkLabel(
            status_frame,
            text="📷 OCR: READY",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            fg_color="#1E293B",
            text_color="#10B981",
            corner_radius=6,
            padx=12,
            pady=6
        )
        self.ocr_badge.pack(side="left", padx=4)

        offline_badge = ctk.CTkLabel(
            status_frame,
            text="🔒 100% AIR-GAPPED",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            fg_color="#1E293B",
            text_color="#F59E0B",
            corner_radius=6,
            padx=12,
            pady=6
        )
        offline_badge.pack(side="left", padx=4)

        # ---------------------------------------------------------------
        # 2. CONTROLS FRAME (Scan Target & Output Directories)
        # ---------------------------------------------------------------
        ctrl_frame = ctk.CTkFrame(self, fg_color="#111827", corner_radius=12, border_width=1, border_color="#1F2937")
        ctrl_frame.grid(row=1, column=0, sticky="ew", padx=20, pady=(16, 8))
        ctrl_frame.grid_columnconfigure(1, weight=1)

        # Target Path Input Row
        lbl_target = ctk.CTkLabel(ctrl_frame, text="Scan Target:", font=ctk.CTkFont(size=12, weight="bold"), text_color="#E2E8F0")
        lbl_target.grid(row=0, column=0, padx=(18, 8), pady=14, sticky="w")

        entry_target = ctk.CTkEntry(
            ctrl_frame,
            textvariable=self.target_path_var,
            font=ctk.CTkFont(size=12),
            fg_color="#1F2937",
            border_color="#374151",
            text_color="#F8FAFC",
            height=36
        )
        entry_target.grid(row=0, column=1, padx=6, pady=14, sticky="ew")

        btn_browse_folder = ctk.CTkButton(
            ctrl_frame,
            text="📁 Browse Directory",
            width=130,
            height=36,
            fg_color="#1E293B",
            hover_color="#334155",
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._browse_target_folder
        )
        btn_browse_folder.grid(row=0, column=2, padx=4, pady=14)

        btn_browse_file = ctk.CTkButton(
            ctrl_frame,
            text="📄 Single File",
            width=110,
            height=36,
            fg_color="#1E293B",
            hover_color="#334155",
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._browse_target_file
        )
        btn_browse_file.grid(row=0, column=3, padx=(4, 18), pady=14)

        # Output Path Input Row
        lbl_out = ctk.CTkLabel(ctrl_frame, text="Report Dir:", font=ctk.CTkFont(size=12, weight="bold"), text_color="#E2E8F0")
        lbl_out.grid(row=1, column=0, padx=(18, 8), pady=(0, 14), sticky="w")

        entry_out = ctk.CTkEntry(
            ctrl_frame,
            textvariable=self.output_dir_var,
            font=ctk.CTkFont(size=12),
            fg_color="#1F2937",
            border_color="#374151",
            text_color="#F8FAFC",
            height=36
        )
        entry_out.grid(row=1, column=1, padx=6, pady=(0, 14), sticky="ew")

        btn_browse_out = ctk.CTkButton(
            ctrl_frame,
            text="📂 Output Dir",
            width=130,
            height=36,
            fg_color="#1E293B",
            hover_color="#334155",
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._browse_output_folder
        )
        btn_browse_out.grid(row=1, column=2, padx=4, pady=(0, 14))

        # Main Action Button (Glowing Gradient Style)
        self.btn_action = ctk.CTkButton(
            ctrl_frame,
            text="⚡ START DISCOVERY SCAN",
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#0284C7",
            hover_color="#0369A1",
            height=36,
            command=self._toggle_scan
        )
        self.btn_action.grid(row=1, column=3, padx=(4, 18), pady=(0, 14), sticky="ew")

        # ---------------------------------------------------------------
        # 3. METRICS DASHBOARD (4 Executive KPI Cards)
        # ---------------------------------------------------------------
        metrics_frame = ctk.CTkFrame(self, fg_color="transparent")
        metrics_frame.grid(row=2, column=0, sticky="ew", padx=20, pady=4)
        metrics_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        # Card 1: Files Scanned
        card1 = ctk.CTkFrame(metrics_frame, fg_color="#111827", corner_radius=10, border_width=1, border_color="#1F2937")
        card1.grid(row=0, column=0, padx=(0, 6), pady=0, sticky="ew")
        ctk.CTkLabel(card1, text="📁 FILES SCANNED", font=ctk.CTkFont(size=10, weight="bold"), text_color="#94A3B8").pack(anchor="w", padx=14, pady=(10, 0))
        self.val_files = ctk.CTkLabel(card1, text="0 / 0", font=ctk.CTkFont(size=22, weight="bold"), text_color="#38BDF8")
        self.val_files.pack(anchor="w", padx=14, pady=(2, 10))

        # Card 2: Total Findings
        card2 = ctk.CTkFrame(metrics_frame, fg_color="#111827", corner_radius=10, border_width=1, border_color="#1F2937")
        card2.grid(row=0, column=1, padx=6, pady=0, sticky="ew")
        ctk.CTkLabel(card2, text="🔍 TOTAL PII FINDINGS", font=ctk.CTkFont(size=10, weight="bold"), text_color="#94A3B8").pack(anchor="w", padx=14, pady=(10, 0))
        self.val_findings = ctk.CTkLabel(card2, text="0", font=ctk.CTkFont(size=22, weight="bold"), text_color="#F59E0B")
        self.val_findings.pack(anchor="w", padx=14, pady=(2, 10))

        # Card 3: High Risk Count
        card3 = ctk.CTkFrame(metrics_frame, fg_color="#111827", corner_radius=10, border_width=1, border_color="#1F2937")
        card3.grid(row=0, column=2, padx=6, pady=0, sticky="ew")
        ctk.CTkLabel(card3, text="🚨 HIGH RISK ALERTS", font=ctk.CTkFont(size=10, weight="bold"), text_color="#94A3B8").pack(anchor="w", padx=14, pady=(10, 0))
        self.val_high_risk = ctk.CTkLabel(card3, text="0", font=ctk.CTkFont(size=22, weight="bold"), text_color="#EF4444")
        self.val_high_risk.pack(anchor="w", padx=14, pady=(2, 10))

        # Card 4: Elapsed Time
        card4 = ctk.CTkFrame(metrics_frame, fg_color="#111827", corner_radius=10, border_width=1, border_color="#1F2937")
        card4.grid(row=0, column=3, padx=(6, 0), pady=0, sticky="ew")
        ctk.CTkLabel(card4, text="⏱️ ELAPSED TIME", font=ctk.CTkFont(size=10, weight="bold"), text_color="#94A3B8").pack(anchor="w", padx=14, pady=(10, 0))
        self.val_timer = ctk.CTkLabel(card4, text="0.0s", font=ctk.CTkFont(size=22, weight="bold"), text_color="#10B981")
        self.val_timer.pack(anchor="w", padx=14, pady=(2, 10))

        # Progress Bar & Active File Banner
        prog_container = ctk.CTkFrame(self, fg_color="#111827", corner_radius=10, border_width=1, border_color="#1F2937")
        prog_container.grid(row=2, column=0, sticky="ew", padx=20, pady=(60, 4))
        prog_container.grid_columnconfigure(0, weight=1)

        self.lbl_status = ctk.CTkLabel(
            prog_container, text="Ready. Select target and click START DISCOVERY SCAN.", font=ctk.CTkFont(size=12), text_color="#CBD5E1"
        )
        self.lbl_status.pack(anchor="w", padx=14, pady=(8, 4))

        self.progress_bar = ctk.CTkProgressBar(prog_container, height=8, progress_color="#0284C7")
        self.progress_bar.set(0.0)
        self.progress_bar.pack(fill="x", padx=14, pady=(0, 10))

        # ---------------------------------------------------------------
        # 4. TABBED WORKSPACE (Findings, Audit Log, Terminal)
        # ---------------------------------------------------------------
        self.tabview = ctk.CTkTabview(
            self,
            fg_color="#111827",
            segmented_button_fg_color="#0F172A",
            segmented_button_selected_color="#0284C7",
            segmented_button_selected_hover_color="#0369A1"
        )
        self.tabview.grid(row=3, column=0, sticky="nsew", padx=20, pady=(6, 12))

        tab_findings = self.tabview.add("🔍 PII Findings")
        tab_audit = self.tabview.add("📊 File Audit Log")
        tab_logs = self.tabview.add("📜 Live Terminal Stream")

        # ----- TAB 1: FINDINGS -----
        tab_findings.grid_columnconfigure(0, weight=1)
        tab_findings.grid_rowconfigure(1, weight=1)

        filter_frame = ctk.CTkFrame(tab_findings, fg_color="transparent")
        filter_frame.grid(row=0, column=0, sticky="ew", padx=6, pady=(6, 6))
        filter_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(filter_frame, text="Filter Results:", font=ctk.CTkFont(size=12, weight="bold"), text_color="#E2E8F0").grid(row=0, column=0, padx=6, sticky="w")
        entry_filter = ctk.CTkEntry(
            filter_frame,
            textvariable=self.filter_var,
            placeholder_text="Filter by PII tag (e.g. AADHAAR, PAN), file name, or keyword...",
            font=ctk.CTkFont(size=12),
            fg_color="#1F2937",
            border_color="#374151",
            text_color="#F8FAFC"
        )
        entry_filter.grid(row=0, column=1, padx=6, sticky="ew")

        # Scrollable List Frame
        self.findings_scroll = ctk.CTkScrollableFrame(tab_findings, fg_color="#0B0F19", corner_radius=8)
        self.findings_scroll.grid(row=1, column=0, sticky="nsew", padx=6, pady=6)
        self.findings_scroll.grid_columnconfigure(0, weight=1)

        self._show_empty_findings_message()

        # ----- TAB 2: AUDIT LOG -----
        tab_audit.grid_columnconfigure(0, weight=1)
        tab_audit.grid_rowconfigure(0, weight=1)

        self.audit_scroll = ctk.CTkScrollableFrame(tab_audit, fg_color="#0B0F19", corner_radius=8)
        self.audit_scroll.grid(row=0, column=0, sticky="nsew", padx=6, pady=6)
        self.audit_scroll.grid_columnconfigure(0, weight=1)

        # ----- TAB 3: TERMINAL -----
        tab_logs.grid_columnconfigure(0, weight=1)
        tab_logs.grid_rowconfigure(0, weight=1)

        self.txt_logs = ctk.CTkTextbox(
            tab_logs,
            font=ctk.CTkFont(family="Consolas", size=11),
            fg_color="#050811",
            text_color="#38BDF8",
            border_width=1,
            border_color="#1F2937"
        )
        self.txt_logs.grid(row=0, column=0, sticky="nsew", padx=6, pady=6)

        # ---------------------------------------------------------------
        # 5. BOTTOM ACTION BAR
        # ---------------------------------------------------------------
        action_bar = ctk.CTkFrame(self, fg_color="transparent")
        action_bar.grid(row=4, column=0, sticky="ew", padx=20, pady=(0, 14))

        self.btn_open_excel = ctk.CTkButton(
            action_bar,
            text="📊 Open Excel Audit Report",
            state="disabled",
            fg_color="#10B981",
            hover_color="#059669",
            text_color="#000000",
            text_color_disabled="#475569",
            font=ctk.CTkFont(size=12, weight="bold"),
            height=36,
            command=self._open_excel_report
        )
        self.btn_open_excel.pack(side="left", padx=(0, 10))

        self.btn_open_heatmap = ctk.CTkButton(
            action_bar,
            text="🔥 Open Heatmap",
            state="disabled",
            fg_color="#F59E0B",
            hover_color="#D97706",
            text_color="#000000",
            text_color_disabled="#475569",
            font=ctk.CTkFont(size=12, weight="bold"),
            height=36,
            command=self._open_heatmap
        )
        self.btn_open_heatmap.pack(side="left", padx=4)

        self.btn_open_folder = ctk.CTkButton(
            action_bar,
            text="📂 Open Output Directory",
            fg_color="#1E293B",
            hover_color="#334155",
            font=ctk.CTkFont(size=12, weight="bold"),
            height=36,
            command=self._open_reports_folder
        )
        self.btn_open_folder.pack(side="left", padx=4)

        self.btn_db_scan = ctk.CTkButton(
            action_bar,
            text="🗄️ DB Scan Config",
            fg_color="#1E293B",
            hover_color="#334155",
            font=ctk.CTkFont(size=12, weight="bold"),
            height=36,
            command=self._open_db_config
        )
        self.btn_db_scan.pack(side="right", padx=(4, 0))

    # ===================================================================
    # EVENT HANDLERS & DIALOGS
    # ===================================================================
    def _browse_target_folder(self):
        folder = ctk.filedialog.askdirectory(title="Select Directory to Scan")
        if folder:
            self.target_path_var.set(folder)

    def _browse_target_file(self):
        file_path = ctk.filedialog.askopenfilename(
            title="Select Single File to Scan",
            filetypes=[("Supported Files", "*.pdf *.docx *.xlsx *.csv *.txt *.png *.jpg *.jpeg *.pptx"), ("All Files", "*.*")]
        )
        if file_path:
            self.target_path_var.set(file_path)

    def _browse_output_folder(self):
        folder = ctk.filedialog.askdirectory(title="Select Output Directory for Reports")
        if folder:
            self.output_dir_var.set(folder)

    def _check_engine_status(self):
        def check():
            nlp, model_name = scanner.get_nlp()
            has_spacy = scanner.HAS_SPACY
            has_ocr = scanner.HAS_PIL and scanner.HAS_TESSERACT
            self.ui_queue.put(("ENGINE_STATUS", (has_spacy, model_name, has_ocr)))
        threading.Thread(target=check, daemon=True).start()

    # ===================================================================
    # ASYNC SCAN WORKER
    # ===================================================================
    def _toggle_scan(self):
        if self.is_scanning:
            self.is_scanning = False
            self.lbl_status.configure(text="Cancelling scan process...")
            self.btn_action.configure(state="disabled")
            return

        target_path = self.target_path_var.get().strip()
        if not target_path or not os.path.exists(target_path):
            self.lbl_status.configure(text="❌ Error: Target path does not exist!")
            return

        out_dir = self.output_dir_var.get().strip()
        if not out_dir:
            out_dir = str(scanner.DEFAULT_REPORTS_DIR.resolve())
            self.output_dir_var.set(out_dir)

        # Reset state
        self.is_scanning = True
        self.all_findings.clear()
        self.all_file_audit.clear()
        self.displayed_finding_cards = 0
        self.show_cap_banner = False
        self._clear_findings_scroll()
        self._clear_audit_scroll()

        self.btn_action.configure(text="⏹️ STOP SCAN", fg_color="#DC2626", hover_color="#B91C1C")
        self.btn_open_excel.configure(state="disabled")
        self.val_files.configure(text="0 / 0")
        self.val_findings.configure(text="0")
        self.val_high_risk.configure(text="0")
        self.progress_bar.set(0.0)
        self.txt_logs.delete("1.0", "end")

        self.start_time = time.perf_counter()
        self.timer_running = True
        self._update_timer()

        self.lbl_status.configure(text=f"Scanning target: {target_path}...")

        # Start background worker thread
        self.scan_thread = threading.Thread(
            target=self._run_scan_worker, args=(target_path, out_dir), daemon=True
        )
        self.scan_thread.start()

    def _update_timer(self):
        if self.timer_running:
            elapsed = time.perf_counter() - self.start_time
            self.val_timer.configure(text=f"{elapsed:.1f}s")
            self.after(250, self._update_timer)

    def _run_scan_worker(self, target_path: str, output_dir: str):
        import concurrent.futures
        import hashlib

        def log(msg):
            self.ui_queue.put(("LOG", msg))

        log("=================================================================")
        log(f"   {scanner.TOOL_NAME} v{scanner.TOOL_VERSION}")
        log("   India Regulatory Focus | 100% Air-Gapped Offline Execution")
        log("=================================================================")
        log(f"Target Path : {target_path}")
        log(f"Output Dir  : {output_dir}\n")

        target = pathlib.Path(target_path)
        files_to_scan = []
        if target.is_file():
            files_to_scan = [target]
        else:
            for root, dirs, filenames in os.walk(target):
                dirs[:] = [d for d in dirs if not d.startswith(".")]
                for fn in filenames:
                    if not fn.startswith("~$") and pathlib.Path(fn).suffix.lower() in scanner.SCAN_EXTENSIONS:
                        files_to_scan.append(pathlib.Path(root) / fn)

        total_files = len(files_to_scan)
        log(f"[+] Found {total_files} file(s) to scan in target directory.\n")

        all_findings = []
        file_audit = []
        completed_count = 0

        # Multi-threaded parallel file processing
        max_workers = min(8, max(2, (os.cpu_count() or 4)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_file = {
                executor.submit(scanner.scan_single_file, fp, target): fp for fp in files_to_scan
            }

            for future in concurrent.futures.as_completed(future_to_file):
                if not self.is_scanning:
                    log("\n[!] Scan cancelled by user.")
                    executor.shutdown(wait=False, cancel_futures=True)
                    break

                completed_count += 1
                fp = future_to_file[future]
                try:
                    file_findings, audit_record = future.result()
                except Exception as ex:
                    rel = str(fp.relative_to(target)) if fp.is_relative_to(target) else str(fp)
                    file_findings = []
                    audit_record = {
                        "file_name": fp.name, "file_path": str(fp), "relative_path": rel,
                        "file_type": fp.suffix.lstrip(".").upper(), "file_size": 0,
                        "last_modified": "N/A", "sha256": "ERROR", "status": "SKIPPED",
                        "reason": f"Read error: {str(ex)}", "pii_tags": "", "pii_count": 0,
                        "risk_score": "N/A", "embedded_images": 0
                    }

                rel = audit_record["relative_path"]
                pii_count = audit_record["pii_count"]

                all_findings.extend(file_findings)
                file_audit.append(audit_record)

                self.ui_queue.put(("PROGRESS", (completed_count, total_files, rel)))
                log(f"[{completed_count}/{total_files}] {'[!] PII' if pii_count > 0 else '[OK] Clean'} {rel} ({pii_count} findings)")
                self.ui_queue.put(("BATCH_FINDINGS", (file_findings, audit_record)))

        # Phase 2: Excel Report
        saved_report = ""
        if all_findings or file_audit:
            log("\n[+] Generating Excel Audit Report...")
            report_file = os.path.join(output_dir, scanner.REPORT_FILENAME)
            saved_report = scanner.generate_report(all_findings, file_audit, report_file, target_path)
            log(f"[OK] Excel Report saved: {saved_report}")
            self.ui_queue.put(("REPORT_SAVED", saved_report))

        # Phase 2b: Heatmap (Feature 9)
        heatmap_file = None
        if HAS_HEATMAP and all_findings:
            log("\n[+] Generating Sensitivity Heatmap...")
            try:
                session_id = hashlib.md5(str(datetime.datetime.now()).encode()).hexdigest()
                heatmap_file = generate_heatmap(all_findings, output_dir, session_id)
                if heatmap_file:
                    log(f"[OK] Heatmap saved: {heatmap_file}")
                    self.ui_queue.put(("HEATMAP_SAVED", heatmap_file))
            except Exception as e:
                log(f"[-] Heatmap error: {e}")

        # Phase 1b: Database Connector scan (Feature 1)
        if HAS_CONNECTORS and hasattr(self, '_db_config') and self._db_config:
            db_config = self._db_config
            log(f"\n[+] Running database connector: {db_config.get('name', db_config.get('type', 'unknown'))}")
            try:
                resolved = connector_for_target(db_config)
                if resolved:
                    conn_cls, _ = resolved
                    conn = conn_cls(db_config, scanner._ScannerHelper())
                    conn_findings = conn.run()
                    if conn_findings:
                        all_findings.extend(conn_findings)
                        log(f"[OK] {len(conn_findings)} PII finding(s) from database connector")
                        for cf in conn_findings:
                            self.ui_queue.put(("BATCH_FINDINGS", ([cf], {
                                "file_name": cf.get("file_name", "db"),
                                "status": "PII_DETECTED", "pii_count": 1,
                                "file_type": "DATABASE", "file_size": 0,
                                "last_modified": "", "sha256": "",
                                "relative_path": cf.get("file_name", "db"),
                                "risk_score": cf.get("sensitivity", "MEDIUM"),
                                "pii_tags": cf.get("tag", "PII"),
                                "embedded_images": 0,
                            })))
            except Exception as e:
                log(f"[-] Connector error: {e}")

        self.ui_queue.put(("SCAN_COMPLETE", None))

    # ===================================================================
    # QUEUE MESSAGE DISPATCHER (MAIN UI THREAD)
    # ===================================================================
    def _process_queue(self):
        try:
            while True:
                msg_type, payload = self.ui_queue.get_nowait()

                if msg_type == "ENGINE_STATUS":
                    has_spacy, model_name, has_ocr = payload
                    if has_spacy:
                        self.ner_badge.configure(text=f"🧠 NER: ACTIVE ({model_name})", text_color="#10B981")
                    else:
                        self.ner_badge.configure(text="🧠 NER: DISABLED", text_color="#EF4444")
                    if has_ocr:
                        self.ocr_badge.configure(text="📷 OCR: READY", text_color="#10B981")
                    else:
                        self.ocr_badge.configure(text="📷 OCR: OFF", text_color="#94A3B8")

                elif msg_type == "LOG":
                    self.txt_logs.insert("end", payload + "\n")
                    self.txt_logs.see("end")

                elif msg_type == "PROGRESS":
                    idx, total, current_file = payload
                    pct = idx / total if total > 0 else 1.0
                    self.progress_bar.set(pct)
                    self.lbl_status.configure(text=f"Scanning [{idx}/{total}]: {current_file}")
                    self.val_files.configure(text=f"{idx} / {total}")

                elif msg_type == "BATCH_FINDINGS":
                    new_findings, file_info = payload
                    self.all_findings.extend(new_findings)
                    self.all_file_audit.append(file_info)

                    # Update Dashboard KPI Cards
                    high_count = sum(1 for f in self.all_findings if f["sensitivity"] == "HIGH")
                    self.val_findings.configure(text=str(len(self.all_findings)))
                    self.val_high_risk.configure(text=str(high_count))

                    # Incremental Card Appends
                    filter_text = self.filter_var.get().strip().lower()
                    for f in new_findings:
                        if not filter_text:
                            self._append_finding_card(f)
                        else:
                            searchable = f"{f['tag']} {f['file_name']} {f['sensitivity']} {f['masked_value']} {f['context']}".lower()
                            if filter_text in searchable:
                                self._append_finding_card(f)

                    self._append_audit_card(file_info)

                elif msg_type == "REPORT_SAVED":
                    self.latest_report_path = payload
                    self.btn_open_excel.configure(state="normal", text_color="#000000")

                elif msg_type == "HEATMAP_SAVED":
                    self.latest_heatmap_path = payload
                    self.btn_open_heatmap.configure(state="normal", text_color="#000000")

                elif msg_type == "SCAN_COMPLETE":
                    self.is_scanning = False
                    self.timer_running = False
                    self.btn_action.configure(text="⚡ START DISCOVERY SCAN", state="normal", fg_color="#0284C7", hover_color="#0369A1")
                    self.lbl_status.configure(text=f"✅ Scan Complete! {len(self.all_findings)} PII findings detected in {self.val_timer.cget('text')}.")

        except queue.Empty:
            pass

        self.after(100, self._process_queue)

    # ===================================================================
    # RENDERING METHODS (INCREMENTAL CARD VIEW & TABLES)
    # ===================================================================
    def _clear_findings_scroll(self):
        for widget in self.findings_scroll.winfo_children():
            widget.destroy()

    def _clear_audit_scroll(self):
        for widget in self.audit_scroll.winfo_children():
            widget.destroy()

    def _show_empty_findings_message(self):
        self._clear_findings_scroll()

        empty_box = ctk.CTkFrame(self.findings_scroll, fg_color="transparent")
        empty_box.pack(expand=True, fill="both", pady=60)

        ctk.CTkLabel(
            empty_box,
            text="🛡️ No Scan Findings Yet",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="#94A3B8"
        ).pack(pady=(0, 4))

        ctk.CTkLabel(
            empty_box,
            text="Select a target directory or file above and click 'START DISCOVERY SCAN' to run the offline engine.",
            font=ctk.CTkFont(size=12),
            text_color="#64748B"
        ).pack()

    def _on_filter_changed(self, *args):
        if self._filter_timer is not None:
            self.after_cancel(self._filter_timer)
        self._filter_timer = self.after(300, self._render_findings)

    def _render_findings(self):
        self._clear_findings_scroll()
        self.displayed_finding_cards = 0
        self.show_cap_banner = False

        filter_text = self.filter_var.get().strip().lower()

        filtered = []
        for f in self.all_findings:
            if not filter_text:
                filtered.append(f)
            else:
                searchable = f"{f['tag']} {f['file_name']} {f['sensitivity']} {f['masked_value']} {f['context']}".lower()
                if filter_text in searchable:
                    filtered.append(f)

        if not filtered:
            lbl = ctk.CTkLabel(
                self.findings_scroll,
                text="No findings match your filter criteria." if self.all_findings else "No PII findings detected.",
                text_color="#64748B",
                font=ctk.CTkFont(size=13)
            )
            lbl.pack(pady=40)
            return

        for f in filtered:
            self._append_finding_card(f)

    def _append_finding_card(self, f: dict):
        if self.displayed_finding_cards >= self.MAX_UI_CARDS:
            if not self.show_cap_banner:
                self.show_cap_banner = True
                banner = ctk.CTkFrame(self.findings_scroll, fg_color="#1E293B", corner_radius=6)
                banner.pack(fill="x", padx=4, pady=8)
                ctk.CTkLabel(
                    banner,
                    text=f"ℹ️ Displaying top {self.MAX_UI_CARDS} UI cards for high performance. Full results recorded in memory & Excel report.",
                    font=ctk.CTkFont(size=11, weight="bold"),
                    text_color="#38BDF8"
                ).pack(padx=12, pady=8)
            return

        card = ctk.CTkFrame(self.findings_scroll, fg_color="#111827", corner_radius=8, border_width=1, border_color="#1F2937")
        card.pack(fill="x", padx=4, pady=5)
        card.grid_columnconfigure(1, weight=1)

        sens = f.get("sensitivity", "LOW")
        badge_color = "#DC2626" if sens == "HIGH" else "#F59E0B" if sens == "MEDIUM" else "#10B981"

        tag_badge = ctk.CTkLabel(
            card,
            text=f.get("tag", "PII"),
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color=badge_color,
            text_color="#FFFFFF",
            corner_radius=4,
            width=115,
            height=28
        )
        tag_badge.grid(row=0, column=0, padx=12, pady=10, sticky="n")

        info_frame = ctk.CTkFrame(card, fg_color="transparent")
        info_frame.grid(row=0, column=1, sticky="ew", padx=6, pady=8)
        info_frame.grid_columnconfigure(0, weight=1)

        file_line = f"📄 {f.get('relative_path', f.get('file_name', ''))} (Line {f.get('line_number', 0)})"
        ctk.CTkLabel(
            info_frame, text=file_line, font=ctk.CTkFont(size=12, weight="bold"), text_color="#F8FAFC"
        ).grid(row=0, column=0, sticky="w")

        val_str = f"Masked Value:  {f.get('masked_value', '')}   •   Confidence: {f.get('confidence', 0)}% ({f.get('detection_method', '')})"
        ctk.CTkLabel(
            info_frame, text=val_str, font=ctk.CTkFont(size=11, weight="bold"), text_color="#38BDF8"
        ).grid(row=1, column=0, sticky="w", pady=(3, 3))

        ctx_str = f"Context:  \"{f.get('context', '')}\""
        ctk.CTkLabel(
            info_frame, text=ctx_str, font=ctk.CTkFont(size=11), text_color="#94A3B8", wraplength=750
        ).grid(row=2, column=0, sticky="w")

        reg_str = f"Legal Scope:  {f.get('regulation', 'DPDP Act 2023')}"
        ctk.CTkLabel(
            info_frame, text=reg_str, font=ctk.CTkFont(size=10), text_color="#64748B"
        ).grid(row=3, column=0, sticky="w", pady=(2, 0))

        self.displayed_finding_cards += 1

    def _render_audit(self):
        self._clear_audit_scroll()

        if not self.all_file_audit:
            lbl = ctk.CTkLabel(
                self.audit_scroll,
                text="No file audit data available yet.",
                text_color="#64748B",
                font=ctk.CTkFont(size=13)
            )
            lbl.pack(pady=40)
            return

        for item in self.all_file_audit:
            self._append_audit_card(item)

    def _append_audit_card(self, item: dict):
        card = ctk.CTkFrame(self.audit_scroll, fg_color="#111827", corner_radius=8, border_width=1, border_color="#1F2937")
        card.pack(fill="x", padx=4, pady=5)
        card.grid_columnconfigure(1, weight=1)

        status = item.get("status", "CLEAN")
        status_color = "#DC2626" if status == "PII_DETECTED" else "#10B981" if status == "CLEAN" else "#64748B"

        lbl_status = ctk.CTkLabel(
            card,
            text=status,
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color=status_color,
            text_color="#FFFFFF",
            corner_radius=4,
            width=115,
            height=28
        )
        lbl_status.grid(row=0, column=0, padx=12, pady=10, sticky="n")

        info = ctk.CTkFrame(card, fg_color="transparent")
        info.grid(row=0, column=1, sticky="ew", padx=6, pady=8)

        ctk.CTkLabel(
            info, text=f"📄 {item.get('relative_path', item.get('file_name', ''))}", font=ctk.CTkFont(size=12, weight="bold"), text_color="#F8FAFC"
        ).pack(anchor="w")

        meta = f"Type: {item.get('file_type', '')}  |  Size: {item.get('file_size', 0)/1024:.1f} KB  |  Findings: {item.get('pii_count', 0)}  |  Risk: {item.get('risk_score', 'N/A')}"
        ctk.CTkLabel(
            info, text=meta, font=ctk.CTkFont(size=11), text_color="#94A3B8"
        ).pack(anchor="w", pady=(3, 0))

        hash_str = f"SHA256: {item.get('sha256', '')[:32]}..."
        ctk.CTkLabel(
            info, text=hash_str, font=ctk.CTkFont(family="Consolas", size=10), text_color="#64748B"
        ).pack(anchor="w", pady=(2, 0))

    # ===================================================================
    # EXCEL & FILE LAUNCHERS
    # ===================================================================
    def _open_excel_report(self):
        if self.latest_report_path and os.path.exists(self.latest_report_path):
            if sys.platform == "win32":
                os.startfile(self.latest_report_path)
            elif sys.platform == "darwin":
                subprocess.run(["open", self.latest_report_path])
            else:
                subprocess.run(["xdg-open", self.latest_report_path])

    def _open_reports_folder(self):
        out_dir = self.output_dir_var.get().strip()
        if not os.path.exists(out_dir):
            os.makedirs(out_dir, exist_ok=True)

        if sys.platform == "win32":
            os.startfile(out_dir)
        elif sys.platform == "darwin":
            subprocess.run(["open", out_dir])
        else:
            subprocess.run(["xdg-open", out_dir])

    def _open_heatmap(self):
        if self.latest_heatmap_path and os.path.exists(self.latest_heatmap_path):
            if sys.platform == "win32":
                os.startfile(self.latest_heatmap_path)
            elif sys.platform == "darwin":
                subprocess.run(["open", self.latest_heatmap_path])
            else:
                subprocess.run(["xdg-open", self.latest_heatmap_path])

    def _open_db_config(self):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Database Connection Config")
        dialog.geometry("500x400")
        dialog.configure(fg_color="#0B0F19")

        ctk.CTkLabel(dialog, text="Database Connector Configuration",
                     font=ctk.CTkFont(size=16, weight="bold"), text_color="#38BDF8").pack(pady=(12, 8))

        frame = ctk.CTkFrame(dialog, fg_color="#111827", corner_radius=8)
        frame.pack(fill="both", expand=True, padx=16, pady=4)

        fields = [("Name", "name"), ("Type (database/mongodb/redis)", "type"),
                  ("Driver (postgresql/mysql/mongodb/redis)", "driver"),
                  ("Host", "host"), ("Port", "port"), ("Database", "database"),
                  ("User", "user"), ("Password", "pass")]
        entries = {}
        for i, (label, key) in enumerate(fields):
            ctk.CTkLabel(frame, text=label, font=ctk.CTkFont(size=11), text_color="#E2E8F0").grid(
                row=i, column=0, sticky="w", padx=12, pady=3)
            e = ctk.CTkEntry(frame, font=ctk.CTkFont(size=11), fg_color="#1F2937",
                             border_color="#374151", text_color="#F8FAFC", width=280)
            e.grid(row=i, column=1, padx=8, pady=3, sticky="ew")
            if key == "type":
                e.insert(0, "database")
            elif key == "driver":
                e.insert(0, "postgresql")
            elif key == "host":
                e.insert(0, "localhost")
            elif key == "port":
                e.insert(0, "5432")
            elif key == "name":
                e.insert(0, "my-db-scan")
            entries[key] = e

        def save_config():
            config = {}
            for key, entry in entries.items():
                val = entry.get().strip()
                if key == "port" and val:
                    val = int(val)
                if val:
                    config[key] = val
            if config.get("driver") in ("mongodb", "redis"):
                config["type"] = config.get("type") or config["driver"]
            self._db_config = config
            self.lbl_status.configure(text=f"✅ DB config saved: {config.get('name', config.get('type', 'unknown'))}")
            dialog.destroy()

        ctk.CTkButton(dialog, text="Save Config & Close", command=save_config,
                      fg_color="#0284C7", hover_color="#0369A1",
                      font=ctk.CTkFont(size=12, weight="bold")).pack(pady=10)

if __name__ == "__main__":
    app = PIIGuardianApp()
    app.mainloop()
