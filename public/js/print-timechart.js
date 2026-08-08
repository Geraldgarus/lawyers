// "Time Chart and Court Records" document — the same markup is used both
// for the print button (case-detail.html, wrapped in its own popup
// document) and the View button (rendered inline in the View Court Date
// modal), so what you see on screen always matches what prints.

// Returns just the document's inner HTML (letterhead through the
// signature row) — no <html>/<head>/<style> wrapper — so it can be
// dropped straight into a modal body. Callers that render this outside
// print-timechart.css's own popup document (i.e. the View modal) need
// that stylesheet loaded separately; see case-detail.html's tc-doc styles.
function buildTimeChartHtml(c, h) {
  h = h || {};

  // A filled-in blank shows the value (underlined, like ink on the printed
  // line); an empty one stays a dotted line, exactly like the blank paper
  // form when a field hasn't been recorded yet.
  const blank = (value, minCh) => {
    minCh = minCh || 14;
    if (value !== null && value !== undefined && value !== '') {
      return `<span class="fill">${escapeHtml(String(value))}</span>`;
    }
    return `<span class="dots" style="min-width:${minCh}ch;"></span>`;
  };
  const proceedingDateTime = h.proceeding_type || '';
  // From/To are fixed black labels — each time value is blanked
  // independently so a filled start time doesn't turn an unfilled end
  // time blue too (and vice versa).
  const timeRange = (startVal, endVal) =>
    `From ${blank(startVal ? fmtTimeStr(startVal) : null, 10)} To ${blank(endVal ? fmtTimeStr(endVal) : null, 10)}`;

  return `
    <div class="letterhead">
      <div class="swash">~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~</div>
      <h1>Tanscar Attorneys</h1>
      <div class="tagline">Commissioners for Oaths and Notaries Public</div>
      <div class="addr">
        Tanscar House, Plot no. 502, Block 42.<br>
        Bwawani/Mkandu Street,<br>
        Kinondoni District.<br>
        P.O.Box 72144,<br>
        Dar-Es-Salaam, Tanzania<br>
        Telephone: +255-222-922207 &nbsp; Fax: +255-222-922207<br>
        Email: info@tanscarattorneys.co.tz &nbsp; Website: http://www.tanscarattorneys.co.tz/
      </div>
    </div>

    <h2 class="doc-title">TIME CHART AND COURT RECORDS</h2>

    <div class="section">
      <p>In the ${blank(h.court, 22)} of Tanzania at ${blank(h.region, 18)}</p>
      <p>Civil Case/Civil Appeal/Misc. Civil Cause/Civil Revision/Civil Misc. Land Application/Land/Commercial
      Case/Matrimonial Cause/Criminal Case No. ${blank(c.case_number, 14)} of ${blank(c.case_year, 8)}</p>
      <p>Parties: ${blank(c.parties, 40)}</p>
      <p class="versus">Versus</p>
      <p>${blank(c.opposing_party, 60)}</p>
    </div>

    <div class="section">
      <p><span class="field-label">Presiding Judge/Magistrate:</span> ${blank(h.presiding_judge, 40)}</p>
      <p><span class="field-label">Date of Mention/1<sup>st</sup> PTC/Mediation/Hearing/Final PTC/Judgment/Ruling:</span> ${blank(proceedingDateTime, 30)}</p>
    </div>

    <div class="section">
      <p><span class="field-label">Counsel for the Plaintiff(s)/Applicant(s)/Petitioner(s)/Objector(s):</span> ${blank(h.counsel_plaintiff, 30)}</p>
      <p><span class="field-label">Counsel for the Defendant(s)/Respondent(s):</span> ${blank(h.counsel_defendant, 34)}</p>
      <p><span class="field-label">Court Clerk:</span> ${blank(h.court_clerk, 40)}</p>
    </div>

    <div class="section">
      <p><span class="field-label">Last Order of the Court:</span> ${blank(h.last_court_order, 40)}</p>
      <p><span class="field-label">Current Prayer/Order/Direction being sought:</span> ${blank(h.prayer_sought, 30)}</p>
      <p style="margin-top:10px;"><span class="field-label">Court Order/Direction:</span> ${blank(h.court_order_direction, 40)}</p>
    </div>

    <div class="section">
      <p><span class="field-label">Time spent: In Court:</span> &nbsp; ${timeRange(h.court_start_time, h.court_end_time)}</p>
      <p style="margin-left:70px;"><span class="field-label">For Office Consultation:</span> ${timeRange(h.consultation_start_time, h.consultation_end_time)}</p>
    </div>

    <div class="sig-row">
      <div class="sig-box">
        <div class="line">${h.record_date ? fmtDate(h.record_date) : ''}</div>
        Date
      </div>
      <div class="sig-box">
        <div class="line">${h.recorded_by ? escapeHtml(h.recorded_by) : ''}</div>
        Name &amp; Signature
      </div>
    </div>
  `;
}

// The print-only CSS for buildTimeChartHtml()'s markup — shared so the
// popup document below and case-detail.html's inline View modal (which
// injects the same class names into the app's own page) can both use it
// without the rules drifting apart. `scope` lets the view modal namespace
// it (e.g. ".tc-doc") since these are otherwise fairly generic class names
// that could clash with the rest of the app's CSS.
function timeChartStyles(scope) {
  scope = scope || '';
  const s = scope ? scope + ' ' : '';
  return `
    ${s}.letterhead { text-align: center; border-bottom: 2px solid #1a1a1a; padding-bottom: 10px; margin-bottom: 18px; }
    ${s}.letterhead .swash { font-size: 11px; letter-spacing: 3px; color: #444; }
    ${s}.letterhead h1 { font-family: 'Playfair Display', Georgia, serif; font-size: 34px; font-weight: 700; margin: 4px 0 2px; letter-spacing: 0.5px; }
    ${s}.letterhead .tagline { font-size: 13px; font-style: italic; margin-bottom: 10px; }
    ${s}.letterhead .addr { font-size: 11.5px; line-height: 1.5; }
    ${s}h2.doc-title { font-size: 16px; text-decoration: underline; text-align: center; margin: 18px 0 16px; }
    ${s}.dots { display: inline-block; border-bottom: 1px dotted #1a1a1a; height: 1px; vertical-align: -3px; }
    ${s}.fill { font-weight: 700; color: #1D4ED8; border-bottom: 1px solid #1a1a1a; padding: 0 2px; }
    ${s}.field-label { font-weight: 700; }
    ${s} p { margin: 6px 0; }
    ${s}.versus { text-align: center; font-weight: 700; margin: 4px 0; }
    ${s}.section { border-top: 1px solid #ddd; padding-top: 12px; margin-top: 16px; }
    ${s}.section:first-of-type { border-top: none; padding-top: 0; margin-top: 0; }
    ${s}.sig-row { display: flex; justify-content: space-between; margin-top: 46px; }
    ${s}.sig-box { width: 45%; text-align: center; }
    ${s}.sig-box .line { border-bottom: 1px dotted #1a1a1a; height: 26px; margin-bottom: 4px; text-align: center; font-weight: 700; color: #1D4ED8; }
  `;
}

// `win` is optional — pass an already-open window when the caller had to
// await data first (e.g. an API fetch), since opening the window only
// after an await breaks the direct-user-gesture chain most browsers
// require to avoid popup-blocking it. Callers with the data already in
// hand (no await needed) can omit it and let this open the window itself.
function printTimeChart(c, h, win) {
  if (!win) {
    win = window.open('', '_blank', 'width=850,height=1000');
    if (!win) { showToast('Please allow popups to print', 'error'); return; }
  }

  win.document.write(`
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Time Chart and Court Records — ${escapeHtml(c.case_number)}</title>
      <style>
        @page { size: A4; margin: 16mm 18mm; }
        * { box-sizing: border-box; }
        body { font-family: Georgia, 'Times New Roman', serif; color: #1a1a1a; padding: 0; font-size: 13px; line-height: 1.9; }
        ${timeChartStyles('')}
        @media print { body { -webkit-print-color-adjust: exact; } .fill { color: #1D4ED8 !important; } }
      </style>
    </head>
    <body>
      ${buildTimeChartHtml(c, h)}
      <script>window.onload = function() { setTimeout(function(){ window.print(); }, 300); };<\/script>
    </body>
    </html>
  `);
  win.document.close();
}
