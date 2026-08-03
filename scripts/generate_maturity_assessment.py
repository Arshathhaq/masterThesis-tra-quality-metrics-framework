import openpyxl
from openpyxl.styles import (
    PatternFill, Font, Alignment, Border, Side
)
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.datavalidation import DataValidation
from openpyxl.drawing.image import Image as XLImage
import io

wb = openpyxl.Workbook()

# ─────────────────────────────────────────────
# COLOUR PALETTE
# ─────────────────────────────────────────────
RED_FILL        = PatternFill("solid", fgColor="C00000")
LIGHT_RED_FILL  = PatternFill("solid", fgColor="FF4C4C")
YELLOW_FILL     = PatternFill("solid", fgColor="FFD966")
GREEN_FILL      = PatternFill("solid", fgColor="92D050")
DARK_GREEN_FILL = PatternFill("solid", fgColor="375623")
BLUE_FILL       = PatternFill("solid", fgColor="1F4E79")
MID_BLUE_FILL   = PatternFill("solid", fgColor="2E75B6")
LIGHT_BLUE_FILL = PatternFill("solid", fgColor="D9E1F2")
GREY_FILL       = PatternFill("solid", fgColor="F2F2F2")
DARK_GREY_FILL  = PatternFill("solid", fgColor="595959")
WHITE_FILL      = PatternFill("solid", fgColor="FFFFFF")
ORANGE_FILL     = PatternFill("solid", fgColor="F4B942")
PURPLE_FILL     = PatternFill("solid", fgColor="7030A0")
TEAL_FILL       = PatternFill("solid", fgColor="00B0F0")
ID5_FILL        = PatternFill("solid", fgColor="D9E1F2")
ID2_FILL        = PatternFill("solid", fgColor="E2EFDA")
ID3_FILL        = PatternFill("solid", fgColor="FFF2CC")

WHITE_FONT      = Font(name="Calibri", bold=True,  color="FFFFFF", size=11)
SMALL_WHITE     = Font(name="Calibri", bold=True,  color="FFFFFF", size=10)
DARK_FONT       = Font(name="Calibri", bold=True,  color="1F4E79", size=11)
BODY_FONT       = Font(name="Calibri",             color="000000", size=10)
BOLD_FONT       = Font(name="Calibri", bold=True,  color="000000", size=10)
ITALIC_FONT     = Font(name="Calibri", italic=True,color="595959", size=9)
TITLE_FONT      = Font(name="Calibri", bold=True,  color="FFFFFF", size=14)
SUBTITLE_FONT   = Font(name="Calibri", bold=True,  color="1F4E79", size=12)

THIN = Side(style="thin",   color="BFBFBF")
MED  = Side(style="medium", color="1F4E79")

THIN_BORDER = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)
MED_BORDER  = Border(left=MED,  right=MED,  top=MED,  bottom=MED)

WRAP    = Alignment(wrap_text=True, vertical="top")
CENTER  = Alignment(horizontal="center", vertical="center", wrap_text=True)
VCENTER = Alignment(horizontal="left",   vertical="center", wrap_text=True)

# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────
def hdr(ws, row, col, text, fill=BLUE_FILL, font=WHITE_FONT,
        align=CENTER, border=THIN_BORDER):
    c = ws.cell(row=row, column=col, value=text)
    c.fill = fill; c.font = font
    c.alignment = align; c.border = border
    return c

def cell(ws, row, col, text="", fill=WHITE_FILL, font=BODY_FONT,
         align=WRAP, border=THIN_BORDER):
    c = ws.cell(row=row, column=col, value=text)
    c.fill = fill; c.font = font
    c.alignment = align; c.border = border
    return c

def header_row(ws, row, headers, fill=BLUE_FILL, font=WHITE_FONT):
    for c, h in enumerate(headers, 1):
        hdr(ws, row, c, h, fill=fill, font=font)

def write_row(ws, row, values, fills=None, font=BODY_FONT,
              row_height=45):
    fills = fills or [WHITE_FILL] * len(values)
    for c, (v, f) in enumerate(zip(values, fills), 1):
        cell(ws, row, c, v, fill=f, font=font)
    ws.row_dimensions[row].height = row_height

def set_col_widths(ws, widths):
    for i, w in enumerate(widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = w

def merge_title(ws, row, col_start, col_end, text,
                fill=BLUE_FILL, font=TITLE_FONT, height=30):
    ws.merge_cells(
        start_row=row, start_column=col_start,
        end_row=row,   end_column=col_end
    )
    c = ws.cell(row=row, column=col_start, value=text)
    c.fill = fill; c.font = font; c.alignment = CENTER
    ws.row_dimensions[row].height = height

def section_bar(ws, row, col_start, col_end, text,
                fill=MID_BLUE_FILL):
    ws.merge_cells(
        start_row=row, start_column=col_start,
        end_row=row,   end_column=col_end
    )
    c = ws.cell(row=row, column=col_start, value=text)
    c.fill = fill; c.font = WHITE_FONT; c.alignment = VCENTER
    ws.row_dimensions[row].height = 20

def alt_fill(row_idx):
    return GREY_FILL if row_idx % 2 == 0 else WHITE_FILL

def add_dropdown(ws, col_letter, row_start, row_end, formula):
    dv = DataValidation(type="list", formula1=formula,
                        allow_blank=True, showDropDown=False)
    ws.add_data_validation(dv)
    dv.sqref = f"{col_letter}{row_start}:{col_letter}{row_end}"

# ═══════════════════════════════════════════════════════════════
# SHEET 0 – COVER / DASHBOARD
# ═══════════════════════════════════════════════════════════════
ws0 = wb.active
ws0.title = "Dashboard"
ws0.sheet_view.showGridLines = False
ws0.sheet_view.showRowColHeaders = False

set_col_widths(ws0, [3,18,18,18,18,18,18,3])

# ── Banner ──────────────────────────────────────────────────────
for r in range(1, 7):
    ws0.row_dimensions[r].height = 18
ws0.merge_cells("B1:G6")
c = ws0.cell(row=1, column=2,
             value="TRA Quality Evaluation Tool\nRefinement Tracker")
c.fill  = BLUE_FILL
c.font  = Font(name="Calibri", bold=True, color="FFFFFF", size=22)
c.alignment = CENTER

# ── Subtitle bar ────────────────────────────────────────────────
ws0.merge_cells("B7:G7")
c = ws0.cell(row=7, column=2,
             value="Expert Interview Feedback — Full Coverage & Gap Analysis")
c.fill = MID_BLUE_FILL; c.font = WHITE_FONT; c.alignment = CENTER
ws0.row_dimensions[7].height = 22

# ── KPI boxes ───────────────────────────────────────────────────
ws0.row_dimensions[9].height  = 14
ws0.row_dimensions[10].height = 40
ws0.row_dimensions[11].height = 22
ws0.row_dimensions[12].height = 14

kpis = [
    ("B", "Total Feedback\nPoints",  "93",  BLUE_FILL),
    ("C", "Previously\nCovered",     "61",  MID_BLUE_FILL),
    ("D", "Gaps\nFound",             "32",  LIGHT_RED_FILL),
    ("E", "Total REF\nItems",        "69",  MID_BLUE_FILL),
    ("F", "P1 Critical\nItems",       "9",  LIGHT_RED_FILL),
    ("G", "Interviewees\nReviewed",   "3",  BLUE_FILL),
]
for col, label, val, fill in kpis:
    ws0.merge_cells(f"{col}9:{col}9")
    ws0.merge_cells(f"{col}10:{col}10")
    ws0.merge_cells(f"{col}11:{col}11")
    lc = ws0[f"{col}9"]
    lc.value = label
    lc.fill  = fill
    lc.font  = Font(name="Calibri", bold=True, color="FFFFFF", size=9)
    lc.alignment = CENTER
    vc = ws0[f"{col}10"]
    vc.value = val
    vc.fill  = fill
    vc.font  = Font(name="Calibri", bold=True, color="FFFFFF", size=28)
    vc.alignment = CENTER

# ── Interviewee summary ─────────────────────────────────────────
ws0.row_dimensions[14].height = 18
ws0.merge_cells("B14:G14")
section_bar(ws0, 14, 2, 7, "  Interviewee Overview")

iv_headers = ["ID", "Name", "Role", "Feedback Points",
              "Gaps Found", "Fill Colour"]
iv_data = [
    ["ID5","Ricarda Weber",   "TRA Expert / Practitioner","52","17",""],
    ["ID2","Fabian Reinhardt","TRA Reviewer",             "11", "3",""],
    ["ID3","Marvin Hege",     "TRA Quality Lead",         "30","12",""],
]
iv_fills = [ID5_FILL, ID2_FILL, ID3_FILL]

for ci, h in enumerate(iv_headers, 2):
    hdr(ws0, 15, ci, h)
ws0.row_dimensions[15].height = 18

for ri, (row, fill) in enumerate(zip(iv_data, iv_fills), 16):
    for ci, v in enumerate(row, 2):
        c = ws0.cell(row=ri, column=ci, value=v)
        c.fill = fill; c.font = BOLD_FONT
        c.alignment = CENTER; c.border = THIN_BORDER
    ws0.cell(row=ri, column=7).fill = fill
    ws0.row_dimensions[ri].height = 20

# ── Priority summary ────────────────────────────────────────────
ws0.row_dimensions[20].height = 18
ws0.merge_cells("B20:G20")
section_bar(ws0, 20, 2, 7, "  Priority Breakdown")

pr_headers = ["Priority","REF Count","Description","Action"]
pr_data = [
    ["P1 – Critical",    "9",  "Fix immediately — blocks correctness or usability",
     "Address before next release"],
    ["P2 – Refine",      "41", "Metric needs redesign, clarification or extension",
     "Plan for v1.2"],
    ["P3 – Enhancement", "19", "New feature, integration or documentation",
     "Plan for v2.0 / Future"],
]
pr_fills = [LIGHT_RED_FILL, YELLOW_FILL, GREEN_FILL]

for ci, h in enumerate(pr_headers, 2):
    hdr(ws0, 21, ci, h)
ws0.row_dimensions[21].height = 18

for ri, (row, fill) in enumerate(zip(pr_data, pr_fills), 22):
    for ci, v in enumerate(row, 2):
        c = ws0.cell(row=ri, column=ci, value=v)
        c.fill = fill
        c.font = Font(name="Calibri", bold=(ci == 2), size=10,
                      color="FFFFFF" if fill == LIGHT_RED_FILL else "1F1F1F")
        c.alignment = WRAP; c.border = THIN_BORDER
    ws0.row_dimensions[ri].height = 28

# ── Sheet index ─────────────────────────────────────────────────
ws0.row_dimensions[26].height = 18
ws0.merge_cells("B26:G26")
section_bar(ws0, 26, 2, 7, "  Workbook Sheet Index")

idx = [
    ["Dashboard",               "This page — KPIs, overview and navigation"],
    ["Refinement_Backlog",      "All 69 REF items with priority, status and owner"],
    ["Metric_Status_Overview",  "All 28 metrics — current status and linked REFs"],
    ["Interviewee_Feedback_Log","93 feedback points mapped to REF items"],
    ["Gap_Analysis",            "32 newly identified gaps (REF-042 to REF-069)"],
    ["Legend",                  "Colour codes, status values and category definitions"],
]
for ri, (sheet, desc) in enumerate(idx, 27):
    c1 = ws0.cell(row=ri, column=2, value=sheet)
    c1.fill = LIGHT_BLUE_FILL; c1.font = BOLD_FONT
    c1.alignment = VCENTER; c1.border = THIN_BORDER
    c2 = ws0.cell(row=ri, column=3, value=desc)
    ws0.merge_cells(
        start_row=ri, start_column=3,
        end_row=ri,   end_column=7
    )
    c2.fill = WHITE_FILL; c2.font = BODY_FONT
    c2.alignment = VCENTER; c2.border = THIN_BORDER
    ws0.row_dimensions[ri].height = 18

# ═══════════════════════════════════════════════════════════════
# SHEET 1 – REFINEMENT BACKLOG (REF-001 … REF-069)
# ═══════════════════════════════════════════════════════════════
ws1 = wb.create_sheet("Refinement_Backlog")
ws1.sheet_view.showGridLines = False
ws1.freeze_panes = "A3"

set_col_widths(ws1, [10,18,18,20,62,18,20,14,14,14,42])

merge_title(ws1, 1, 1, 11,
            "Refinement Backlog — All 69 REF Items", height=28)

HEADERS1 = ["Item ID","Metric / Area","Priority","Category",
            "Action Required","Source","Affects Metric(s)",
            "Status","Owner","Target Version","Notes / Resolution"]
header_row(ws1, 2, HEADERS1)
ws1.row_dimensions[2].height = 22

PRIORITY_FILL = {
    "P1 – Critical":    LIGHT_RED_FILL,
    "P2 – Refine":      YELLOW_FILL,
    "P3 – Enhancement": GREEN_FILL,
}

ALL_REFS = [
    # ── P1 Critical ──────────────────────────────────────────
    ["REF-001","Tool Architecture","P1 – Critical","Clarification",
     "Explicitly state in UI and documentation that the tool is a review-support aid, not a replacement for expert judgment. Findings must be manually confirmed, dismissed, or marked N/A.",
     "ID2, ID3, ID5","All","Open","","v1.1",""],
    ["REF-002","Tool Architecture","P1 – Critical","UX",
     "Add per-metric guidance text prompting the reviewer on what to do (e.g. 'Please revisit component X and check comprehensibility').",
     "ID5","All","Open","","v1.1",""],
    ["REF-003","Tool Architecture","P1 – Critical","UX",
     "Implement a mechanism for reviewers to dismiss or override individual findings with a note (false-positive handling).",
     "ID5","All","Open","","v1.1",""],
    ["REF-004","Import / Mendix","P1 – Critical","Import Fix",
     "Fix Mendix import bug causing participant list and moderator data to be lost. Investigate and correct import pipeline.",
     "ID5","CM-01","Open","","v1.1",""],
    ["REF-005","Import / Mendix","P1 – Critical","Import Fix",
     "Fix figure/image import from XLS sheet (Intended Operation section lost). Flag explicitly when manual review of original document is required.",
     "ID5","CM-03, CM-13","Open","","v1.1",""],
    ["REF-006","Import / Mendix","P1 – Critical","Import Fix",
     "Clarify whether Mendix Tool supports interface and communication modeling. Align CM-07, CM-08, CM-09 evaluation accordingly.",
     "ID5","CM-07, CM-08, CM-09","Open","","v1.1",""],
    ["REF-007","CM-19 / CM-24","P1 – Critical","Metric Refinement",
     "Fix similarity detection false positives (100% similarity reported for clearly different threats T1 vs T4). Recalibrate Jaccard/NLP logic. Validate against larger TRA corpus.",
     "ID2","CM-19, CM-24","Open","","v1.1",
     "Reported: T1 vs T4 scored 100% similarity incorrectly"],
    ["REF-008","CM-05","P1 – Critical","Metric Refinement",
     "Improve placeholder detection precision to reduce false positives (e.g. 'at a frequency to be determined' flagged unexpectedly). Add explanation text in report.",
     "ID2","CM-05","Open","","v1.1",""],
    ["REF-009","CM-20","P1 – Critical","Clarification",
     "Clarify whether Mendix Tool allows manual risk value entry. If not, mark metric N/A for XLS imports or redefine for Mendix context.",
     "ID5","CM-20","Open","","v1.1",
     "In XLS, risk column is auto-computed and cannot be overridden"],
    # ── P2 Refine ────────────────────────────────────────────
    ["REF-010","CM-01","P2 – Refine","Metric Refinement",
     "Extend to check for presence of required roles (Business Owner, Quality Officer, etc.), not just participant count. Add note that role qualification cannot be auto-verified.",
     "ID5, ID3","CM-01","Open","","v1.2",""],
    ["REF-011","CM-01","P2 – Refine","Metric Refinement",
     "For long-lived/living TRAs, check that at least 1-2 workshops were held per year rather than just one total. Use date of first workshop as document age indicator.",
     "ID3","CM-01","Open","","v1.2",
     "TRA-X creation date != predecessor Excel TRA creation date"],
    ["REF-012","CM-02","P2 – Refine","Metric Refinement",
     "Change threshold from 'updated since creation' to 'updated within the last X months.' Consider using review/release workflow dates instead of file modification timestamps.",
     "ID3, ID5","CM-02","Open","","v1.2",""],
    ["REF-013","CM-04","P2 – Refine","Metric Refinement",
     "Extend placeholder detection set (add 'to be determined', 'TBD', 'N/A', 'open', etc.). Show exact cell/location of each placeholder in the report.",
     "ID5","CM-04","Open","","v1.2",""],
    ["REF-014","CM-10","P2 – Refine","Metric Refinement",
     "Add inverse check: every threat should reference at least one protection goal it violates. Clarify which fields are evaluated in documentation.",
     "ID3","CM-10","Open","","v1.2",""],
    ["REF-015","CM-16","P2 – Refine","Metric Refinement",
     "Clarify whether CM-16 is redundant with CM-06/07/09. Keep as standalone top-level sanity check for edge case where no components/interfaces/communications are modeled. Move to top of Formal Completeness section.",
     "ID3","CM-16, CM-06, CM-07, CM-09","Open","","v1.2",""],
    ["REF-016","CM-17","P2 – Refine","Metric Refinement",
     "Provide per-threat explanation of why it was rated generic/weak. Rename reference list from 'good threats' to 'typical/standard threats.'",
     "ID3, ID5","CM-17","Open","","v1.2",""],
    ["REF-017","CM-18","P2 – Refine","Metric Refinement",
     "Move to Coverage section. Add note about valid exemptions (e.g. public website with only public data).",
     "ID5","CM-18","Open","","v1.2",""],
    ["REF-018","CM-19","P2 – Refine","Metric Refinement",
     "Split into two separate metrics: (a) near-duplicate threat detection, (b) rating consistency — same/similar description should yield same rating. Also check consistency with protection goal/impact sheet ratings.",
     "ID5","CM-19","Open","","v1.2",""],
    ["REF-019","CM-21","P2 – Refine","Metric Refinement",
     "Verify metric numbering is consistent with threat IDs in report. Add note that 'acceptance' is a valid treatment decision and should be explicitly stateable in the tool.",
     "ID5","CM-21","Open","","v1.2",
     "Interviewee noted mismatch: T6 had no suggestion, not T5"],
    ["REF-020","CM-22","P2 – Refine","Metric Refinement",
     "Promote to mandatory KPI. Flag if no red-rated risk exists. Consider flagging if all threats are rated the same (insufficient discrimination).",
     "ID5","CM-22","Open","","v1.2",""],
    ["REF-021","CM-23","P2 – Refine","Metric Refinement",
     "Extend assumption linkage check to cover all assumption types (Security Zone, Interface, Threat-specific), not only General assumptions.",
     "ID3","CM-23","Open","","v1.2",""],
    ["REF-022","CM-24","P2 – Refine","Clarification",
     "Confirm CM-24 is not a duplicate of CM-19. Clearly differentiate both metrics in the report if both are retained.",
     "ID5","CM-24, CM-19","Open","","v1.2",""],
    ["REF-023","CM-25","P2 – Refine","Clarification",
     "Clarify in report and documentation which TRA sheet / Mendix Tool fields map to each semantic slot (actor, action, target-interface, weakness, impact, protection-goal). Consider recommending a formal threat description template.",
     "ID5","CM-25","Open","","v1.2",""],
    ["REF-024","CM-27","P2 – Refine","Clarification",
     "Document which field or marker constitutes a sign-off in the Mendix Tool schema. If no such field exists, report as not assessable and prompt reviewer to confirm approval was handled by other means.",
     "ID3, ID5","CM-27","Open","","v1.2",""],
    ["REF-025","CM-28","P2 – Refine","Clarification",
     "Clarify in documentation that evidence references may appear in any text field and that the metric checks for their presence anywhere in the document, not in a specific location.",
     "ID5","CM-28","Open","","v1.2",""],
    ["REF-026","CM-06","P2 – Refine","Redundancy Review",
     "Investigate whether CM-06 is fully determined by CM-07 and CM-09. Clarify the distinction or consolidate if redundant.",
     "ID3","CM-06, CM-07, CM-09","Open","","v1.2",""],
    ["REF-027","CM-12","P2 – Refine","Redundancy Review",
     "Investigate whether CM-12 is redundant with CM-10 and CM-11. Review whether CM-12 adds independent information.",
     "ID3","CM-12, CM-10, CM-11","Open","","v1.2",""],
    ["REF-028","CM-14","P2 – Refine","Clarification",
     "Clarify and document what CM-14 checks and how the verdict is reached. Determine whether out-of-scope flagging can be modeled in the Mendix Tool.",
     "ID5","CM-14","Open","","v1.2",""],
    # ── P3 Enhancement ───────────────────────────────────────
    ["REF-029","Report UX","P3 – Enhancement","UX",
     "Show problematic TRA text inline in the report for each finding so reviewer does not need to switch back to original document.",
     "ID2","All","Open","","v2.0",""],
    ["REF-030","Report UX","P3 – Enhancement","UX",
     "Replace severity labels: 'Critical' → 'Urgently review'; 'High/Warn' → 'Prio 1 / Prio 2' to encourage constructive responses.",
     "ID5","All","Open","","v2.0",""],
    ["REF-031","Report UX","P3 – Enhancement","UX",
     "Restructure findings summary section: reduce summary at end, focus on review and improvement suggestions. Findings are already marked per-metric.",
     "ID5","All","Open","","v2.0",""],
    ["REF-032","Report UX","P3 – Enhancement","UX",
     "Retain and expand 'Good' / positive indicators in report. Passing metrics should be acknowledged, not just failures.",
     "ID5","All","Open","","v2.0",""],
    ["REF-033","Report UX","P3 – Enhancement","UX",
     "Add explicit label per metric clarifying that passing means 'formally and structurally compliant' — not 'content-wise high quality.'",
     "ID3","All","Open","","v2.0",""],
    ["REF-034","New Metric","P3 – Enhancement","New Metric",
     "Add component/interface/communication modeling quality metric as prerequisite check for all coverage metrics. Handles edge case where CM-06/07/09 are all N/A.",
     "ID3","CM-06, CM-07, CM-09, CM-16","Open","","v2.0",""],
    ["REF-035","New Metric","P3 – Enhancement","New Metric",
     "Add role presence check: verify required roles (Business Owner, Quality Officer, etc.) are listed. Flag missing roles. Note qualification cannot be auto-verified.",
     "ID5","CM-01","Open","","v2.0",""],
    ["REF-036","New Metric","P3 – Enhancement","New Metric",
     "Add Delta/Update TRA detection: detect if TRA is a delta or update TRA and adjust metric expectations accordingly (e.g. CM-01 workshop count thresholds).",
     "ID5","CM-01, CM-02","Open","","v2.0",""],
    ["REF-037","New Metric","P3 – Enhancement","New Metric",
     "Add rating-text consistency check: flag individual threats where textual description of impact/likelihood does not match the assigned numerical rating.",
     "ID5","CM-19","Open","","v2.0","Extension of CM-19b"],
    ["REF-038","Integration","P3 – Enhancement","Integration",
     "Evaluate integration with Mendix Tool / TRA-X so authors receive real-time feedback during TRA creation, not only post-hoc.",
     "ID2, ID5","All","Open","","Future",""],
    ["REF-039","Integration","P3 – Enhancement","Integration",
     "Validate NLP/comparison metrics against a larger TRA corpus to calibrate thresholds and reduce false positive rates.",
     "ID2, ID3","CM-17, CM-19, CM-24","Open","","Future",""],
    ["REF-040","Integration","P3 – Enhancement","Integration",
     "Consider LLM enhancement as a future phase for semantic checks (CM-17, CM-25, CM-26) while preserving deterministic core.",
     "ID3","CM-17, CM-25, CM-26","Open","","Future",""],
    ["REF-041","Integration","P3 – Enhancement","Integration",
     "Explore whether draw.io / system diagram files can be parsed to auto-populate component and interface models.",
     "ID5","CM-06, CM-07, CM-08, CM-09","Open","","Future",""],
    # ── GAP items REF-042 … REF-069 ─────────────────────────
    ["REF-042","CM-02","P2 – Refine","Clarification",
     "Add note that version count alone is misleading for Conceptboard-style TRAs where results are manually transferred. Version count metric should account for workflow type.",
     "ID5","CM-02","Open","","v1.2","Newly identified gap"],
    ["REF-043","All Metrics","P2 – Refine","UX",
     "Add rationale explanation per metric in the report — explain WHY the presence or absence of each element is a quality indicator, not just what was found.",
     "ID5","All","Open","","v1.2","Newly identified gap"],
    ["REF-044","CM-04","P2 – Refine","Metric Refinement",
     "Document and mitigate false positive risk in placeholder detection (e.g. 'to do once a month' in attack description text is not a real placeholder). Consider context-aware filtering.",
     "ID5","CM-04","Open","","v1.2","Newly identified gap"],
    ["REF-045","CM-05","P3 – Enhancement","Clarification",
     "Add context note: assumption validation metric is more meaningful in single-source-of-truth online tools (e.g. Mendix) where customer works on same version, vs. XLS handover workflows.",
     "ID5","CM-05","Open","","v2.0","Newly identified gap"],
    ["REF-046","CM-06","P2 – Refine","Metric Refinement",
     "Add note that 'relevant component' scope must be explicitly defined in the TRA. Components listed preparatorily but not intended for threat analysis should be distinguishable from in-scope components.",
     "ID5","CM-06","Open","","v1.2","Newly identified gap"],
    ["REF-047","CM-06","P2 – Refine","Metric Refinement",
     "Capture multi-component attack modeling limitation: when one attack involves multiple components, only one is selected in the threat column. Tool should account for this pattern.",
     "ID5","CM-06","Open","","v1.2","Newly identified gap"],
    ["REF-048","CM-06","P2 – Refine","Metric Refinement",
     "Capture bidirectional traceability issue: in XLS, components can appear in threat list without being in component list. Tool should handle both directions of traceability.",
     "ID5","CM-06","Open","","v1.2","Newly identified gap"],
    ["REF-049","CM-10","P2 – Refine","UX",
     "Add rationale explanation for CM-10 in report: explain why every non-negligible protection goal should be linked to at least one threat scenario.",
     "ID5","CM-10","Open","","v1.2","Newly identified gap"],
    ["REF-050","CM-13 / CM-15","P2 – Refine","Clarification",
     "Document limitation: automated tool cannot assess whether a text description is truly comprehensible to a qualified insider. Flag as human-review-required and prompt reviewer explicitly.",
     "ID5","CM-13, CM-15","Open","","v1.2","Newly identified gap"],
    ["REF-051","CM-19","P3 – Enhancement","New Metric",
     "Capture negotiation-pattern detection: flag cases where similar threats receive significantly different ratings, which may indicate social pressure during TRA workshop ('oh please, not another critical').",
     "ID5","CM-19","Open","","v2.0","Newly identified gap"],
    ["REF-052","CM-20","P2 – Refine","UX",
     "Add user education note in report about the intended purpose of the comment/justification column in the TRA sheet, as many users use it for overflow remarks.",
     "ID5","CM-20","Open","","v1.2","Newly identified gap"],
    ["REF-053","CM-21","P2 – Refine","Clarification",
     "Add note about post-TRA customer workflow gap: customer may need to fill in treatment decisions after the TRA but may not return the updated sheet, making this metric harder to enforce in XLS-based workflows.",
     "ID5","CM-21","Open","","v1.2","Newly identified gap"],
    ["REF-054","CM-23","P2 – Refine","Clarification",
     "Note that no explicit column exists in XLS sheet for assumption-to-threat linkage. Check whether Mendix Tool provides this field and align metric accordingly.",
     "ID5","CM-23","Open","","v1.2","Newly identified gap"],
    ["REF-055","CM-25","P2 – Refine","Clarification",
     "Capture field mapping ambiguity: protection goals are often recorded in the impact column rather than a dedicated field. Tool must account for this when evaluating CM-25 slot completeness.",
     "ID5","CM-25","Open","","v1.2","Newly identified gap"],
    ["REF-056","General","P3 – Enhancement","Documentation",
     "Log positive design feedback from ID2: HTML dashboard easy to understand, design well received. Useful for thesis and future development justification.",
     "ID2","—","Open","","v2.0","Newly identified gap"],
    ["REF-057","General","P3 – Enhancement","New Feature",
     "Capture TRA-X conformity checking angle: tool could be used to detect whether colleagues are using TRA-X correctly, not just whether TRA content is complete.",
     "ID2","All","Open","","v2.0","Newly identified gap"],
    ["REF-058","General","P2 – Refine","Clarification",
     "Capture user error as a source of findings: some findings (e.g. unreferenced assets) may stem from incorrect TRA-X usage rather than genuine TRA quality issues. Tool should distinguish where possible.",
     "ID2","All","Open","","v1.2","Newly identified gap"],
    ["REF-059","General","P3 – Enhancement","Documentation",
     "Log positive feedback from ID3: dependency-free design and local deterministic execution are valued features. Preserve these properties in future versions.",
     "ID3","—","Open","","v2.0","Newly identified gap"],
    ["REF-060","General","P3 – Enhancement","Documentation",
     "Log positive feedback from ID3: report formatting and structure well received.",
     "ID3","—","Open","","v2.0","Newly identified gap"],
    ["REF-061","General","P2 – Refine","Documentation",
     "Capture foundational quality propagation insight: deficiencies in TRA foundations (components, assets, protection goals) propagate through all higher-level metrics. Document this in tool guidance.",
     "ID3","All","Open","","v1.2","Newly identified gap"],
    ["REF-062","General","P2 – Refine","Documentation",
     "Capture asymmetry of quality criteria: it is easier to identify bad quality than good quality. Knock-out metrics should be clearly labeled as such and not used to infer positive quality.",
     "ID3","All","Open","","v1.2","Newly identified gap"],
    ["REF-063","General","P2 – Refine","Clarification",
     "Document that valid deviations exist in ~10% of cases due to business/segment-specific TRA methodology flexibility. Tool findings should always allow for expert override.",
     "ID3","All","Open","","v1.2","Newly identified gap"],
    ["REF-064","General","P2 – Refine","Documentation",
     "Capture NLP/comparison metrics (CM-17, CM-19, CM-24) as better positive quality indicators compared to binary knock-out metrics. Reflect this distinction in report and documentation.",
     "ID3","CM-17, CM-19, CM-24","Open","","v1.2","Newly identified gap"],
    ["REF-065","General","P2 – Refine","Documentation",
     "Capture over-scoring risk: some TRAs may score formally well but be content-wise poor. Document this boundary condition explicitly in tool guidance and thesis.",
     "ID3","All","Open","","v1.2","Newly identified gap"],
    ["REF-066","General","P2 – Refine","UX",
     "Capture gaming risk: naive straight-forward action from a metric finding may satisfy the criterion formally without genuinely improving TRA quality. Add guidance notes to discourage this.",
     "ID3","All","Open","","v1.2","Newly identified gap"],
    ["REF-067","CM-27","P2 – Refine","Clarification",
     "Note technical limitation: static sign-off text blocks do not technically protect the TRA document against subsequent changes. Mention this in metric documentation.",
     "ID3","CM-27","Open","","v1.2","Newly identified gap"],
    ["REF-068","CM-07","P2 – Refine","Clarification",
     "Clarify interface type scope: does 'logical interface' include only network interfaces or also proximity and host interfaces? Define clearly in metric documentation.",
     "ID3","CM-07","Open","","v1.2","Newly identified gap"],
    ["REF-069","CM-17","P2 – Refine","UX",
     "Improve CM-17 calculation transparency: explain in the report how the score is calculated and how the input (threat text) influences the metric result.",
     "ID3","CM-17","Open","","v1.2","Newly identified gap"],
]

for ri, row in enumerate(ALL_REFS, start=3):
    p     = row[2]
    pfill = PRIORITY_FILL.get(p, WHITE_FILL)
    base  = alt_fill(ri)
    fills = [base]*11
    fills[2] = pfill          # Priority column coloured
    write_row(ws1, ri, row, fills=fills, row_height=55)
    # Priority font colour
    ws1.cell(row=ri, column=3).font = Font(
        name="Calibri", bold=True, size=10,
        color="FFFFFF" if p == "P1 – Critical" else "1F1F1F"
    )

last1 = len(ALL_REFS) + 2
add_dropdown(ws1, "C", 3, last1,
             '"P1 – Critical,P2 – Refine,P3 – Enhancement"')
add_dropdown(ws1, "H", 3, last1,
             '"Open,In Progress,Done,Deferred,Won\'t Fix"')
add_dropdown(ws1, "J", 3, last1,
             '"v1.1,v1.2,v2.0,Future"')
ws1.auto_filter.ref = f"A2:K{last1}"

# ═══════════════════════════════════════════════════════════════
# SHEET 2 – METRIC STATUS OVERVIEW
# ═══════════════════════════════════════════════════════════════
ws2 = wb.create_sheet("Metric_Status_Overview")
ws2.sheet_view.showGridLines = False
ws2.freeze_panes = "A3"
set_col_widths(ws2, [10,35,20,55,35,18])

merge_title(ws2, 1, 1, 6,
            "Metric Status Overview — All 28 Metrics", height=28)
HEADERS2 = ["Metric ID","Metric Name","Current Status",
            "Action Summary","Linked REF Items","Interviewee Source"]
header_row(ws2, 2, HEADERS2)
ws2.row_dimensions[2].height = 22

STATUS_FILL = {
    "Keep":              GREEN_FILL,
    "Refine":            YELLOW_FILL,
    "Extend":            YELLOW_FILL,
    "Clarify":           LIGHT_BLUE_FILL,
    "Relocate":          LIGHT_BLUE_FILL,
    "Relocate + Clarify":LIGHT_BLUE_FILL,
    "Fix + Refine":      ORANGE_FILL,
    "Split":             ORANGE_FILL,
    "Promote":           GREEN_FILL,
    "Import Fix":        LIGHT_RED_FILL,
    "Redundancy Review": GREY_FILL,
}

METRICS = [
    ["CM-01","Relevant-role / workshop participation","Refine",
     "Add role check; adjust for living documents; use workshop date for age",
     "REF-004,010,011,035,036","ID2,ID3,ID5"],
    ["CM-02","Living-document maintenance","Refine",
     "Use recency threshold; consider workflow dates; account for Conceptboard workflow",
     "REF-012,036,042","ID3,ID5"],
    ["CM-03","IntendedOp section presence","Import Fix",
     "Flag figure import limitation explicitly",
     "REF-005","ID5"],
    ["CM-04","Placeholder detection","Refine",
     "Extend placeholder set; show locations; mitigate false positives",
     "REF-013,044","ID5"],
    ["CM-05","Assumption validation","Refine",
     "Improve placeholder precision; add explanation; note workflow context",
     "REF-008,045","ID2,ID5"],
    ["CM-06","Component coverage by threats","Redundancy Review",
     "Clarify vs. CM-07/09; add relevant-scope note; handle multi-component attacks",
     "REF-026,046,047,048","ID3,ID5"],
    ["CM-07","Interface coverage by threats","Clarify",
     "Define 'logical interface' scope (network/proximity/host); align with Mendix",
     "REF-006,068","ID3,ID5"],
    ["CM-08","External interface coverage","Clarify",
     "State what coverage means in report; align with Mendix",
     "REF-006","ID5"],
    ["CM-09","Inter-component communication coverage","Refine",
     "Align with Mendix communication modeling; explore draw.io parsing",
     "REF-006,041","ID5"],
    ["CM-10","Protection-goal coverage","Extend",
     "Add inverse check (threat → protection goal); add rationale explanation",
     "REF-014,049","ID3,ID5"],
    ["CM-11","Asset representation","Keep",
     "Confirm logic is sound","—","ID5"],
    ["CM-12","Asset mapping to components","Redundancy Review",
     "Clarify vs. CM-10/CM-11",
     "REF-027","ID3"],
    ["CM-13","System overview text length","Relocate",
     "Move to Formal Completeness; flag human-review-required for comprehensibility",
     "REF-005,050","ID5"],
    ["CM-14","Out-of-scope boundary justification","Clarify",
     "Document verdict logic; check Mendix support",
     "REF-028","ID5"],
    ["CM-15","Component scope description","Clarify",
     "Flag human-review-required for comprehensibility",
     "REF-050","ID5"],
    ["CM-16","No-threat red flag","Relocate + Clarify",
     "Move to top of Formal Completeness; clarify redundancy with CM-06/07/09",
     "REF-015","ID3"],
    ["CM-17","Threat specificity vs. good-threat list","Refine",
     "Add per-threat explanation; rename reference list; improve transparency",
     "REF-016,039,069","ID3,ID5"],
    ["CM-18","Protection goal span (CIA)","Relocate",
     "Move to Coverage; add exemption note",
     "REF-017","ID5"],
    ["CM-19","Rating consistency / near-duplicate threats","Split",
     "Separate into (a) duplicate detection (b) rating consistency; add negotiation-pattern detection",
     "REF-007,018,022,037,051","ID5"],
    ["CM-20","Stored risk vs. computed risk","Clarify",
     "Define for Mendix context; mark N/A for XLS; add comment column education note",
     "REF-009,052","ID5"],
    ["CM-21","Treatment decision presence","Fix + Refine",
     "Fix threat ID numbering; add 'acceptance' option; note post-TRA workflow gap",
     "REF-019,053","ID5"],
    ["CM-22","Risk rating discrimination","Promote",
     "Make mandatory KPI; flag insufficient discrimination",
     "REF-020","ID5"],
    ["CM-23","Assumption usage / linkage","Extend",
     "Cover all assumption types; note missing XLS column",
     "REF-021,054","ID3,ID5"],
    ["CM-24","Near-duplicate threat pairs","Clarify",
     "Confirm distinct from CM-19; differentiate in report; fix false positives",
     "REF-007,022","ID5"],
    ["CM-25","Threat-structure completeness","Clarify",
     "Document field-to-slot mapping; address protection-goal-in-impact-column ambiguity",
     "REF-023,055","ID5"],
    ["CM-26","Vagueness / imprecision reduction","Keep",
     "Confirm logic is sound; consider applying to all text boxes","—","ID5"],
    ["CM-27","Authority approval presence","Clarify",
     "Define sign-off marker; document N/A path; note static block limitation",
     "REF-024,067","ID3,ID5"],
    ["CM-28","Evidence reference presence","Clarify",
     "Document any-field search is intended; add rationale explanation",
     "REF-025,043","ID5"],
]

for ri, row in enumerate(METRICS, start=3):
    base  = alt_fill(ri)
    sfill = STATUS_FILL.get(row[2], WHITE_FILL)
    fills = [base]*6
    fills[2] = sfill
    write_row(ws2, ri, row, fills=fills, row_height=40)
    ws2.cell(row=ri, column=3).font = Font(
        name="Calibri", bold=True, size=10,
        color="FFFFFF" if row[2] == "Import Fix" else "1F1F1F"
    )

ws2.auto_filter.ref = f"A2:F{len(METRICS)+2}"

# ═══════════════════════════════════════════════════════════════
# SHEET 3 – INTERVIEWEE FEEDBACK LOG
# ═══════════════════════════════════════════════════════════════
ws3 = wb.create_sheet("Interviewee_Feedback_Log")
ws3.sheet_view.showGridLines = False
ws3.freeze_panes = "A3"
set_col_widths(ws3, [8,20,25,18,70,25,10])

merge_title(ws3, 1, 1, 7,
            "Interviewee Feedback Log — 93 Feedback Points", height=28)
HEADERS3 = ["ID","Name","Role / Context","Feedback Area",
            "Key Quote / Observation","Linked REF Items","Gap?"]
header_row(ws3, 2, HEADERS3)
ws3.row_dimensions[2].height = 22

ID_FILL = {"ID5": ID5_FILL, "ID2": ID2_FILL, "ID3": ID3_FILL}

FEEDBACK = [
    # ── ID5 ──────────────────────────────────────────────────
    ["ID5","Ricarda Weber","TRA Expert / Practitioner","CM-01 Import",
     "Due to import mistake of Mendix-Tool, original TRA contains the relevant data — participant list and moderator lost.",
     "REF-004","No"],
    ["ID5","Ricarda Weber","TRA Expert / Practitioner","CM-01 Roles",
     "Maybe you can check also for the presence of typically required roles, like Business Owner or Quality Officer.",
     "REF-010","No"],
    ["ID5","Ricarda Weber","TRA Expert / Practitioner","CM-01 Delta TRA",
     "Keep also in mind, that there may be TRA Updates / Delta TRAs.",
     "REF-036","No"],
    ["ID5","Ricarda Weber","TRA Expert / Practitioner","CM-02 Workflow",
     "This TRA was done as Concept-Board-TRA where I afterwards transfer results manually — therefore not many versions.",
     "REF-042","GAP"],
    ["ID5","Ricarda Weber","TRA Expert / Practitioner","CM-27",
     "I am confused. Where in the TRA Sheet should this be added? And who should approve it?",
     "REF-024","No"],
    ["ID5","Ricarda Weber","TRA Expert / Practitioner","CM-28",
     "SVM was mentioned in the Weaknesses column, PenTest in possible measures. Do you explain why such references are a quality indicator?",
     "REF-025,043","GAP"],
    ["ID5","Ricarda Weber","TRA Expert / Practitioner","CM-03",
     "Due to import behavior of Mendix-Tool, original TRA contains the relevant data as figure, which was not imported.",
     "REF-005","No"],
    ["ID5","Ricarda Weber","TRA Expert / Practitioner","CM-04 Location",
     "In xls, you cannot search for '??'. This hits every cell. Would need help to locate these occurrences.",
     "REF-013","No"],
    ["ID5","Ricarda Weber","TRA Expert / Practitioner","CM-04 False Positives",
     "There may be quite some false positives. In the TRA list I found a 'to do once a month' in an attack description text.",
     "REF-044","GAP"],
    ["ID5","Ricarda Weber","TRA Expert / Practitioner","CM-05",
     "In this online TRA tool, if there is just one source of truth and the customer works on the same version, this makes perfect sense.",
     "REF-045","GAP"],
    ["ID5","Ricarda Weber","TRA Expert / Practitioner","CM-06 Scope",
     "There was no intention to analyze threats for all these components, many of which were components interacting with the system under investigation.",
     "REF-046","GAP"],
    ["ID5","Ricarda Weber","TRA Expert / Practitioner","CM-06 Multi-component",
     "If an attack involves several components, I just select one for the column in the threat list.",
     "REF-047","GAP"],
    ["ID5","Ricarda Weber","TRA Expert / Practitioner","CM-06 Bidirectional",
     "We had components in the threat list that did not make it into the component list — so at least in the xls sheet this works both ways.",
     "REF-048","GAP"],
    ["ID5","Ricarda Weber","TRA Expert / Practitioner","CM-07/08/09",
     "This is due to the import of the TRA into the Mendix Tool, as no interfaces are modeled in the xls sheet.",
     "REF-006","No"],
    ["ID5","Ricarda Weber","TRA Expert / Practitioner","CM-09 draw.io",
     "Maybe it could parse my draw.ios into a system description.",
     "REF-041","No"],
    ["ID5","Ricarda Weber","TRA Expert / Practitioner","CM-10 Rationale",
     "I do not understand, what you were looking at here. Why must there be a threat for every non-negligible protection goal?",
     "REF-049","GAP"],
    ["ID5","Ricarda Weber","TRA Expert / Practitioner","CM-13/15 Comprehensibility",
     "Can you really rate if a text and the associated figures are comprehensible to the participants and subsequent readers of the TRA?",
     "REF-050","GAP"],
    ["ID5","Ricarda Weber","TRA Expert / Practitioner","CM-16",
     "Self-evident. You should put this basic sanity check on the top, maybe into formal completeness.",
     "REF-015","No"],
    ["ID5","Ricarda Weber","TRA Expert / Practitioner","CM-17",
     "I challenge 'good threats'. This heavily depends on how the threat is described and on the creativity of the TRA participants.",
     "REF-016","No"],
    ["ID5","Ricarda Weber","TRA Expert / Practitioner","CM-18",
     "There might be valid exemptions, like for a public website with only public data. Maybe relocate to coverage.",
     "REF-017","No"],
    ["ID5","Ricarda Weber","TRA Expert / Practitioner","CM-19 Split",
     "Rating consistency to me suggests that you rate impact consistently for the same actual impact. Same/Similar description = same rating.",
     "REF-018","No"],
    ["ID5","Ricarda Weber","TRA Expert / Practitioner","CM-19 Negotiation",
     "Deviations may indicate that in the TRA there may have been negotiations like 'oh, please, can't be that bad'.",
     "REF-051","GAP"],
    ["ID5","Ricarda Weber","TRA Expert / Practitioner","CM-20 Comment",
     "I always used the comment column to store whatever remarks I had or as overflow for other columns. I never was aware of its 'true' intention.",
     "REF-052","GAP"],
    ["ID5","Ricarda Weber","TRA Expert / Practitioner","CM-20 Risk",
     "The risk column is automatically computed. Is this different in the Mendix tool?",
     "REF-009","No"],
    ["ID5","Ricarda Weber","TRA Expert / Practitioner","CM-21 Numbering",
     "Maybe your numbering got muddled here. I had no suggestion for T6, not T5.",
     "REF-019","No"],
    ["ID5","Ricarda Weber","TRA Expert / Practitioner","CM-21 Acceptance",
     "Maybe it cannot be fixed at all and must be accepted? Should that be stated in that column as well?",
     "REF-019","No"],
    ["ID5","Ricarda Weber","TRA Expert / Practitioner","CM-21 Post-TRA",
     "In other TRAs it might not be possible in the timeboxed manner and afterwards the customer would need to fill it in but might not hand it back.",
     "REF-053","GAP"],
    ["ID5","Ricarda Weber","TRA Expert / Practitioner","CM-22",
     "Please make this a mandatory quality KPI. Each TRA must have a red risk.",
     "REF-020","No"],
    ["ID5","Ricarda Weber","TRA Expert / Practitioner","CM-23 Linkage",
     "Do I have to link an assumption on the intended operational environment with threats? Never did so in any TRA consciously.",
     "REF-021","No"],
    ["ID5","Ricarda Weber","TRA Expert / Practitioner","CM-23 XLS Column",
     "There is no explicit column in the xls-Sheet for assumption linkage. Is there in the Mendix-Tool?",
     "REF-054","GAP"],
    ["ID5","Ricarda Weber","TRA Expert / Practitioner","CM-24",
     "Is this a duplicate of CM-19? Or was this an explanation muddle?",
     "REF-022","No"],
    ["ID5","Ricarda Weber","TRA Expert / Practitioner","CM-25 Fields",
     "Which fields in the TRA sheet or the Mendix-Tool are you referring to here? I am confused. What should I write where and how?",
     "REF-023","No"],
    ["ID5","Ricarda Weber","TRA Expert / Practitioner","CM-25 Protection Goal",
     "The protection goals I mostly addressed in the impact column.",
     "REF-055","GAP"],
    ["ID5","Ricarda Weber","TRA Expert / Practitioner","General UX Guidance",
     "The reader should be encouraged to check if the description is really comprehensible. Maybe your display should give such guidance explicitly.",
     "REF-002","No"],
    ["ID5","Ricarda Weber","TRA Expert / Practitioner","General Tone",
     "You style your report with red/yellow/green. Maybe touchy people will try to fix things in a formal manner rather than a constructive one.",
     "REF-030","No"],
    ["ID5","Ricarda Weber","TRA Expert / Practitioner","General Structure",
     "I would omit the findings summary and focus on the review and improvement suggestions.",
     "REF-031","No"],
    ["ID5","Ricarda Weber","TRA Expert / Practitioner","General Labels",
     "I would replace 'Critical' with 'Urgently review' and use 'Prio 1/Prio 2' instead of 'High/Warn'.",
     "REF-030","No"],
    ["ID5","Ricarda Weber","TRA Expert / Practitioner","General False Positives",
     "The user should be able to decide on 'false-positives'.",
     "REF-003","No"],
    ["ID5","Ricarda Weber","TRA Expert / Practitioner","General Integration",
     "If your tool is integrated with the Mendix-Tool like a container vulnerability scanner in the CICD pipeline, people would become aware easily.",
     "REF-038","No"],
    # ── ID2 ──────────────────────────────────────────────────
    ["ID2","Fabian Reinhardt","TRA Reviewer","General Design",
     "The HTML dashboard and report is easy to understand and I like the design very much.",
     "REF-056","GAP"],
    ["ID2","Fabian Reinhardt","TRA Reviewer","CM-01 Import",
     "The PDF shows workshop participants but the report says none found — discrepancy.",
     "REF-004","No"],
    ["ID2","Fabian Reinhardt","TRA Reviewer","CM-05 A_gen-9",
     "The assumption A_gen-9 must be reviewed but I do not understand why — 'at a frequency to be determined'.",
     "REF-008","No"],
    ["ID2","Fabian Reinhardt","TRA Reviewer","CM-19/24 Similarity",
     "The detection of similarity seems odd. It reports 100% similarity for T1 (Unauthorized access to Frontend) and T4 (Attacker gets access to source code).",
     "REF-007","No"],
    ["ID2","Fabian Reinhardt","TRA Reviewer","General Corpus",
     "If we would run this script against more of our TRAs we could improve it even more.",
     "REF-039","No"],
    ["ID2","Fabian Reinhardt","TRA Reviewer","General Checks",
     "The 28 quality checks make sense and should be extended and added by validating real world TRAs.",
     "REF-039","No"],
    ["ID2","Fabian Reinhardt","TRA Reviewer","General Conformity",
     "We could use an abstraction of your tool to check for the conformity and if our colleagues are using TRA-X in the right way.",
     "REF-057","GAP"],
    ["ID2","Fabian Reinhardt","TRA Reviewer","General User Error",
     "I saw a lot of findings where data/assets were not referenced at all, which might be because the users were not using TRA-X properly.",
     "REF-058","GAP"],
    ["ID2","Fabian Reinhardt","TRA Reviewer","General Integration",
     "Tool should be driven forward — not only for validators but also for TRA-X users. Maybe as an integration in TRA-X itself?",
     "REF-038","No"],
    ["ID2","Fabian Reinhardt","TRA Reviewer","Report UX Inline",
     "It would help if the report would show exactly the text of the TRA which is problematic, e.g. show T1 and T4 descriptions inline.",
     "REF-029","No"],
    # ── ID3 ──────────────────────────────────────────────────
    ["ID3","Marvin Hege","TRA Quality Lead","General Design",
     "The script is dependency free and therefore easy to use and setup without any hassle. Report is nicely formatted and well structured.",
     "REF-059,060","GAP"],
    ["ID3","Marvin Hege","TRA Quality Lead","General Foundations",
     "A degraded maturity on the foundations of the TRA will propagate through the higher layers.",
     "REF-061","GAP"],
    ["ID3","Marvin Hege","TRA Quality Lead","General Quality Asymmetry",
     "It is easier to identify criteria for bad quality. Unfortunately, often these criteria act as knock out metrics as they do not inversely indicate good quality.",
     "REF-062","GAP"],
    ["ID3","Marvin Hege","TRA Quality Lead","General Valid Deviations",
     "Even though a metric correctly determines the quality in 90% of cases, in the remaining 10% there might be good reasons why to deviate.",
     "REF-063","GAP"],
    ["ID3","Marvin Hege","TRA Quality Lead","General Knock-out",
     "CM-22, CM-16, CM-18 are pure knock-out criteria. Not passing = bad quality. Passing = nearly meaningless.",
     "REF-033","No"],
    ["ID3","Marvin Hege","TRA Quality Lead","General NLP Metrics",
     "NLP/comparison metrics (CM-17, CM-19, CM-24) I consider potentially as better positive indicators for good quality.",
     "REF-064","GAP"],
    ["ID3","Marvin Hege","TRA Quality Lead","General Formal vs Content",
     "Many metrics mainly check if some formal criteria is fulfilled, but not the quality in which it has been fulfilled.",
     "REF-033","No"],
    ["ID3","Marvin Hege","TRA Quality Lead","General Over-scoring",
     "I was surprised how well many of our TRAs passed. Maybe I am too pedantic, but I consider some of our TRAs much worse than your script indicated.",
     "REF-065","GAP"],
    ["ID3","Marvin Hege","TRA Quality Lead","General Tool Role",
     "I wouldn't use it to measure quality but as a tool in the first phase of a TRA review to get initial metrics and find the low hanging fruits.",
     "REF-001","No"],
    ["ID3","Marvin Hege","TRA Quality Lead","General Gaming Risk",
     "A naively straight forward derived action from the metric will be sufficient to fulfill the criteria but may often not be the reasonable best solution.",
     "REF-066","GAP"],
    ["ID3","Marvin Hege","TRA Quality Lead","CM-01 Living Doc",
     "TRAs in our department are commonly not one-off TRAs, but documents which are updated for years and decades.",
     "REF-011","No"],
    ["ID3","Marvin Hege","TRA Quality Lead","CM-01 Date",
     "Creation date inside TRA-X != creation of predecessor Excel TRA; date of first workshop may give better indication.",
     "REF-011","No"],
    ["ID3","Marvin Hege","TRA Quality Lead","CM-02 Workflow Dates",
     "Instead of considering the changed date, data from the review and release workflow may be more expressive.",
     "REF-012","No"],
    ["ID3","Marvin Hege","TRA Quality Lead","CM-27 Sign-off Marker",
     "Metric description does not state how sign off could be done (i.e., which marker to use).",
     "REF-024","No"],
    ["ID3","Marvin Hege","TRA Quality Lead","CM-27 Static Block",
     "Static sign-off text blocks may be difficult process wise in practice as they do not protect the document against change technically.",
     "REF-067","GAP"],
    ["ID3","Marvin Hege","TRA Quality Lead","CM-06 Redundancy",
     "Isn't CM-06 already fully determined by CM-07 and CM-09 as components cannot have threats directly assigned?",
     "REF-026","No"],
    ["ID3","Marvin Hege","TRA Quality Lead","CM-07 Interface Type",
     "What is meant with 'logical' interface — only network or also proximity and host interfaces?",
     "REF-068","GAP"],
    ["ID3","Marvin Hege","TRA Quality Lead","CM-08 Coverage",
     "Coverage by what? Threats? Needs clarification.",
     "REF-006","No"],
    ["ID3","Marvin Hege","TRA Quality Lead","CM-10 Inverse",
     "I would also like to see a metric the other way round: all threats should refer to a protection goal which is violated.",
     "REF-014","No"],
    ["ID3","Marvin Hege","TRA Quality Lead","CM-12 Redundancy",
     "Doesn't this metric fully positively correlate to CM-10 and CM-11 and is therefore redundant?",
     "REF-027","No"],
    ["ID3","Marvin Hege","TRA Quality Lead","CM-16 Redundancy",
     "Isn't CM-16 already fully determined by CM-06, CM-07 and CM-09?",
     "REF-015","No"],
    ["ID3","Marvin Hege","TRA Quality Lead","CM-17 Transparency",
     "I do not clearly understand how it is calculated and how the input influences the metric.",
     "REF-069","GAP"],
    ["ID3","Marvin Hege","TRA Quality Lead","CM-23 Assumption Types",
     "Why are only general assumptions considered? Security Zone, Interface and Threat specific assumptions can lose their assignment and become orphans.",
     "REF-021","No"],
]

for ri, row in enumerate(FEEDBACK, start=3):
    iid   = row[0]
    ifill = ID_FILL.get(iid, WHITE_FILL)
    is_gap = row[6] == "GAP"
    gfill = ORANGE_FILL if is_gap else GREEN_FILL
    fills = [ifill]*6 + [gfill]
    write_row(ws3, ri, row, fills=fills, row_height=50)
    ws3.cell(row=ri, column=7).font = Font(
        name="Calibri", bold=True, size=10,
        color="FFFFFF" if is_gap else "1F1F1F"
    )
    ws3.cell(row=ri, column=7).alignment = CENTER

ws3.auto_filter.ref = f"A2:G{len(FEEDBACK)+2}"

# ═══════════════════════════════════════════════════════════════
# SHEET 4 – GAP ANALYSIS
# ═══════════════════════════════════════════════════════════════
ws4 = wb.create_sheet("Gap_Analysis")
ws4.sheet_view.showGridLines = False
ws4.freeze_panes = "A3"
set_col_widths(ws4, [10,18,18,20,62,18,20,14,14,42])

merge_title(ws4, 1, 1, 10,
            "Gap Analysis — 32 Newly Identified Gaps (REF-042 to REF-069)",
            height=28)
HEADERS4 = ["Item ID","Metric / Area","Priority","Category",
            "Action Required","Source","Affects Metric(s)",
            "Status","Target Version","Notes"]
header_row(ws4, 2, HEADERS4)
ws4.row_dimensions[2].height = 22

GAPS = [r for r in ALL_REFS if int(r[0].split("-")[1]) >= 42]

for ri, row in enumerate(GAPS, start=3):
    p     = row[2]
    pfill = PRIORITY_FILL.get(p, WHITE_FILL)
    base  = alt_fill(ri)
    # drop Owner column (index 8) for this sheet
    short = row[:7] + [row[7]] + [row[9]] + [row[10]]
    fills = [base]*10
    fills[2] = pfill
    write_row(ws4, ri, short, fills=fills, row_height=55)
    ws4.cell(row=ri, column=3).font = Font(
        name="Calibri", bold=True, size=10,
        color="FFFFFF" if p == "P1 – Critical" else "1F1F1F"
    )

ws4.auto_filter.ref = f"A2:J{len(GAPS)+2}"

# ── Gap summary bar ─────────────────────────────────────────────
sum_row = len(GAPS) + 4
ws4.merge_cells(f"A{sum_row}:J{sum_row}")
section_bar(ws4, sum_row, 1, 10,
            f"  Total gaps captured: {len(GAPS)}  |  "
            "All gaps sourced from expert interview feedback  |  "
            "Status: Open — pending refinement phase")

# ═══════════════════════════════════════════════════════════════
# SHEET 5 – LEGEND
# ═══════════════════════════════════════════════════════════════
ws5 = wb.create_sheet("Legend")
ws5.sheet_view.showGridLines = False
set_col_widths(ws5, [3,28,50,3])

merge_title(ws5, 1, 2, 3, "Legend — Colour Codes & Definitions",
            height=28)

def leg_section(ws, row, title):
    ws.merge_cells(f"B{row}:C{row}")
    c = ws.cell(row=row, column=2, value=f"  {title}")
    c.fill = MID_BLUE_FILL; c.font = WHITE_FONT
    c.alignment = VCENTER
    ws.row_dimensions[row].height = 20

def leg_row(ws, row, label, desc, fill=WHITE_FILL,
            font_color="1F1F1F"):
    c1 = ws.cell(row=row, column=2, value=label)
    c2 = ws.cell(row=row, column=3, value=desc)
    for c in [c1, c2]:
        c.fill = fill
        c.font = Font(name="Calibri", bold=(c.column==2),
                      size=10, color=font_color)
        c.alignment = WRAP; c.border = THIN_BORDER
    ws.row_dimensions[row].height = 20

leg_section(ws5, 3,  "PRIORITY COLOURS — Refinement Backlog & Gap Analysis")
leg_row(ws5, 4,  "P1 – Critical",
        "Fix immediately — blocks correctness or usability",
        LIGHT_RED_FILL, "FFFFFF")
leg_row(ws5, 5,  "P2 – Refine",
        "Metric needs redesign, clarification or extension",
        YELLOW_FILL)
leg_row(ws5, 6,  "P3 – Enhancement",
        "New feature, integration or documentation improvement",
        GREEN_FILL)

leg_section(ws5, 8,  "STATUS VALUES — Refinement Backlog")
for r, (s, d) in enumerate([
    ("Open",        "Not yet started"),
    ("In Progress", "Currently being worked on"),
    ("Done",        "Completed and verified"),
    ("Deferred",    "Postponed to a later version"),
    ("Won't Fix",   "Decided not to address"),
], start=9):
    leg_row(ws5, r, s, d)

leg_section(ws5, 15, "METRIC STATUS COLOURS — Metric Status Overview")
for r, (s, d, f, fc) in enumerate([
    ("Keep",              "No changes needed — logic confirmed sound",
     GREEN_FILL,      "1F1F1F"),
    ("Refine / Extend",   "Metric logic needs improvement or extension",
     YELLOW_FILL,     "1F1F1F"),
    ("Clarify",           "Documentation or scope needs clarifying",
     LIGHT_BLUE_FILL, "1F1F1F"),
    ("Relocate",          "Move to a different report section",
     LIGHT_BLUE_FILL, "1F1F1F"),
    ("Relocate + Clarify","Move section AND clarify documentation",
     LIGHT_BLUE_FILL, "1F1F1F"),
    ("Fix + Refine",      "Bug fix plus metric redesign needed",
     ORANGE_FILL,     "1F1F1F"),
    ("Split",             "Break into two or more separate metrics",
     ORANGE_FILL,     "1F1F1F"),
    ("Promote",           "Elevate to mandatory KPI status",
     GREEN_FILL,      "1F1F1F"),
    ("Import Fix",        "Root cause is in Mendix import pipeline",
     LIGHT_RED_FILL,  "FFFFFF"),
    ("Redundancy Review", "Check if metric duplicates another",
     GREY_FILL,       "1F1F1F"),
], start=16):
    leg_row(ws5, r, s, d, f, fc)

leg_section(ws5, 27, "INTERVIEWEE COLOUR CODING — Feedback Log")
leg_row(ws5, 28, "ID5 – Ricarda Weber",
        "TRA Expert / Practitioner — 52 feedback points, 17 gaps",
        ID5_FILL)
leg_row(ws5, 29, "ID2 – Fabian Reinhardt",
        "TRA Reviewer — 11 feedback points, 3 gaps",
        ID2_FILL)
leg_row(ws5, 30, "ID3 – Marvin Hege",
        "TRA Quality Lead — 30 feedback points, 12 gaps",
        ID3_FILL)

leg_section(ws5, 32, "GAP INDICATOR — Feedback Log Column G")
leg_row(ws5, 33, "GAP",
        "Feedback point was not previously captured — new REF item created",
        ORANGE_FILL, "FFFFFF")
leg_row(ws5, 34, "No",
        "Feedback point was already covered by an existing REF item",
        GREEN_FILL)

leg_section(ws5, 36, "CATEGORY DEFINITIONS")
for r, (cat, desc) in enumerate([
    ("Import Fix",        "Root cause is a bug or limitation in the Mendix import pipeline"),
    ("Metric Refinement", "The metric logic, thresholds or scope need to be changed"),
    ("Clarification",     "The metric definition or documentation needs to be made clearer"),
    ("UX",                "The report display, labels or guidance text need improvement"),
    ("Redundancy Review", "The metric may overlap with another and needs consolidation review"),
    ("New Metric",        "A completely new metric or check should be added"),
    ("New Feature",       "A new tool capability beyond metric checking"),
    ("Integration",       "Relates to connecting the tool with external systems (TRA-X, CICD)"),
    ("Documentation",     "Relates to thesis write-up, tool guidance text or rationale notes"),
], start=37):
    leg_row(ws5, r, cat, desc, alt_fill(r))

# ═══════════════════════════════════════════════════════════════
# SAVE
# ═══════════════════════════════════════════════════════════════
output = "TRA_Tool_Refinement_Tracker_FULL.xlsx"
wb.save(output)
print(f"✅  Saved → {output}")
print(f"    Sheets : Dashboard | Refinement_Backlog | "
      f"Metric_Status_Overview | Interviewee_Feedback_Log | "
      f"Gap_Analysis | Legend")
print(f"    REF items : 69  |  Feedback points : 93  |  Gaps : 32")