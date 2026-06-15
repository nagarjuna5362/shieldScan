const PDFDocument = require('pdfkit');

function generatePdfReport(reportData, res) {
  const doc = new PDFDocument({ margin: 50, size: 'A4', bufferPages: true });

  doc.pipe(res);

  // Header / Title
  doc.fillColor('#e02929').fontSize(24).text('🛡️ ShieldScan', { continued: true });
  doc.fillColor('#333333').fontSize(14).text('  Website Security Report', { align: 'right' });
  doc.moveDown(0.5);
  
  doc.strokeColor('#e02929').lineWidth(2).moveTo(50, doc.y).lineTo(545, doc.y).stroke();
  doc.moveDown(1);

  // Metadata Section
  const metaY = doc.y;
  doc.fontSize(10).fillColor('#666666');
  doc.text(`Target URL: ${reportData.url}`, 50, metaY);
  doc.text(`Hostname: ${reportData.hostname}`);
  doc.text(`Scan Date: ${new Date(reportData.timestamp).toLocaleString()}`);
  doc.text(`Scan Duration: ${reportData.scanDuration || 'N/A'}`);
  
  // Score Box on Right
  doc.rect(345, metaY, 200, 70).fill('#1a1a1a');
  doc.fillColor('#ffffff').fontSize(16).text(`Score: ${reportData.score}/100`, 365, metaY + 15);
  doc.fontSize(11).text(`Grade: ${reportData.grade} (${reportData.label || ''})`, 365, metaY + 40);

  // Restore cursor y coordinate below metadata
  doc.y = metaY + 90;

  // Vulnerability Count Summary
  doc.fillColor('#333333').fontSize(12).text('Vulnerability Summary', 50, doc.y);
  doc.strokeColor('#dddddd').lineWidth(1).moveTo(50, doc.y).lineTo(545, doc.y).stroke();
  doc.moveDown(0.5);

  const sum = reportData.summary || { critical: 0, high: 0, medium: 0, low: 0, pass: 0 };
  doc.fontSize(10).fillColor('#666666');
  doc.text(`Critical Vulnerabilities: ${sum.critical}`);
  doc.text(`High Severity Risks: ${sum.high}`);
  doc.text(`Medium Severity: ${sum.medium}`);
  doc.text(`Low Severity: ${sum.low}`);
  doc.text(`Passed Checks: ${sum.pass}`);
  doc.moveDown(1.5);

  // Top Fix Priorities
  if (reportData.fixPriorities && reportData.fixPriorities.length > 0) {
    doc.fillColor('#333333').fontSize(12).text('Top Fix Recommendations', 50, doc.y);
    doc.strokeColor('#dddddd').lineWidth(1).moveTo(50, doc.y).lineTo(545, doc.y).stroke();
    doc.moveDown(0.5);

    reportData.fixPriorities.forEach((fix, index) => {
      doc.fontSize(10).fillColor('#e02929').text(`${index + 1}. ${fix.name} (CVSS: ${fix.cvss}, Exploitability: ${fix.exploitability})`);
      doc.fillColor('#555555').fontSize(9).text(`   Remediation: ${fix.recommendation}`);
      doc.moveDown(0.5);
    });
    doc.moveDown(1.5);
  }

  // Findings list
  doc.fillColor('#333333').fontSize(12).text('Detailed Findings', 50, doc.y);
  doc.strokeColor('#dddddd').lineWidth(1).moveTo(50, doc.y).lineTo(545, doc.y).stroke();
  doc.moveDown(0.5);

  const passed = [];
  const failed = [];

  reportData.results.forEach((r) => {
    if (r.status === 'PASS') {
      passed.push(r);
    } else {
      failed.push(r);
    }
  });

  // Print failures first
  if (failed.length > 0) {
    doc.fillColor('#d32f2f').fontSize(11).text('Failed & Warning Audits', 50, doc.y);
    doc.moveDown(0.5);

    failed.forEach((r) => {
      // Ensure we don't overflow the page abruptly
      if (doc.y > 700) {
        doc.addPage();
      }

      doc.fontSize(10).fillColor('#d32f2f').text(`✘ [${r.status}] ${r.name}`);
      doc.fontSize(9).fillColor('#666666');
      doc.text(`Category: ${r.category}  |  Severity: ${r.severity}  |  CVSS: ${r.cvss || 'N/A'}  |  Exploitability: ${r.exploitability || 'N/A'}`);
      doc.fillColor('#333333').text(`Finding: ${r.description}`);
      if (r.fix) {
        doc.fillColor('#555555').text(`Remediation: ${r.fix.description}`);
      }
      doc.moveDown(0.5);
    });
    doc.moveDown(1);
  }

  // Print passes
  if (passed.length > 0) {
    if (doc.y > 700) {
      doc.addPage();
    }
    doc.fillColor('#2e7d32').fontSize(11).text('Passed Audits', 50, doc.y);
    doc.moveDown(0.5);

    passed.forEach((r) => {
      if (doc.y > 730) {
        doc.addPage();
      }
      doc.fontSize(9).fillColor('#2e7d32').text(`✔ [PASS] ${r.name}`);
      doc.fillColor('#666666').fontSize(8.5).text(`   ${r.description}`);
      doc.moveDown(0.3);
    });
  }

  // Add Page Numbers and Footer
  const pages = doc.bufferedPageRange();
  for (let i = 0; i < pages.count; i++) {
    doc.switchToPage(i);
    doc.fontSize(8).fillColor('#999999').text(
      `Page ${i + 1} of ${pages.count}  |  ShieldScan Security Report  |  Made by nagarjuna's team`,
      50,
      780,
      { align: 'center' }
    );
  }

  doc.end();
}

module.exports = { generatePdfReport };
