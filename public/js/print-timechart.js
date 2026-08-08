// "Time Chart and Court Records" print template, used by the per-Court-Date
// print button on case-detail.html. (Case Status Report used to reuse this
// too, before it became a fully manual report unlinked from real cases —
// it now prints its own table via window.print() instead.)
// `win` is optional — pass an already-open window when the caller had to
// await data first (e.g. an API fetch), since opening the window only
// after an await breaks the direct-user-gesture chain most browsers
// require to avoid popup-blocking it. Callers with the data already in
// hand (no await needed) can omit it and let this open the window itself.
function printTimeChart(c, h, win) {
  h = h || {};
  if (!win) {
    win = window.open('', '_blank', 'width=850,height=1000');
    if (!win) { showToast('Please allow popups to print', 'error'); return; }
  }

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
        .letterhead { text-align: center; border-bottom: 2px solid #1a1a1a; padding-bottom: 10px; margin-bottom: 18px; }
        .letterhead .swash { font-size: 11px; letter-spacing: 3px; color: #444; }
        .letterhead h1 { font-family: 'Playfair Display', Georgia, serif; font-size: 34px; font-weight: 700; margin: 4px 0 2px; letter-spacing: 0.5px; }
        .letterhead .tagline { font-size: 13px; font-style: italic; margin-bottom: 10px; }
        .letterhead .addr { font-size: 11.5px; line-height: 1.5; }
        h2.doc-title { font-size: 16px; text-decoration: underline; text-align: center; margin: 18px 0 16px; }
        .dots { display: inline-block; border-bottom: 1px dotted #1a1a1a; height: 1px; vertical-align: -3px; }
        .fill { font-weight: 700; color: #1D4ED8; border-bottom: 1px solid #1a1a1a; padding: 0 2px; }
        .field-label { font-weight: 700; }
        p { margin: 6px 0; }
        .versus { text-align: center; font-weight: 700; margin: 4px 0; }
        .section { border-top: 1px solid #ddd; padding-top: 12px; margin-top: 16px; }
        .section:first-of-type { border-top: none; padding-top: 0; margin-top: 0; }
        .sig-row { display: flex; justify-content: space-between; margin-top: 46px; }
        .sig-box { width: 45%; text-align: center; }
        .sig-box .line { border-bottom: 1px dotted #1a1a1a; height: 26px; margin-bottom: 4px; text-align: center; font-weight: 700; color: #1D4ED8; }
        @media print { body { -webkit-print-color-adjust: exact; } .fill { color: #1D4ED8 !important; } }
      </style>
    </head>
    <body>
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

      <script>window.onload = function() { setTimeout(function(){ window.print(); }, 300); };<\/script>
    </body>
    </html>
  `);
  win.document.close();
}
