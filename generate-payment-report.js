const ExcelJS = require('exceljs');
const path = require('path');

async function generatePaymentReport(data, outputPath = 'payment-report.xlsx', reportType = 'default') {
  const workbook = new ExcelJS.Workbook();

  if (reportType === 'delinquent_owners') {
    const delinquentSheet = workbook.addWorksheet('Delinquent Homeowners');
    const almostDueSheet = workbook.addWorksheet('Almost Due Homeowners');

    // Add headers to both
    const headers = ['Name', 'Amount', 'Date', 'Payment Method', 'Status'];
    delinquentSheet.addRow(headers);
    almostDueSheet.addRow(headers);

    // Sort into respective sheets
    data.forEach(item => {
      const row = [
        item.name || `${item.firstName || ''} ${item.lastName || ''}`,
        item.amount || item.MDAmount || '',
        item.date || item.lastPaymentDate || '',
        item.paymentMethod || '',
        item.status || item.PStatus || ''
      ];

      if ((item.PStatus || item.status)?.toLowerCase() === 'delinquent') {
        delinquentSheet.addRow(row);
      } else if ((item.PStatus || item.status)?.toLowerCase() === 'almost due') {
        almostDueSheet.addRow(row);
      }
    });
  } else {
    const worksheet = workbook.addWorksheet('Payments');
    worksheet.addRow(['Name', 'Amount', 'Date', 'Payment Method', 'Status']);

    data.forEach(item => {
      worksheet.addRow([
        item.name || `${item.firstName || ''} ${item.lastName || ''}`,
        item.amount || item.MDAmount || '',
        item.date || item.lastPaymentDate || '',
        item.paymentMethod || '',
        item.status || item.PStatus || ''
      ]);
    });
  }

  const fullPath = path.join(__dirname, outputPath);
  await workbook.xlsx.writeFile(fullPath);
  console.log(`✅ Report generated at ${fullPath}`);
  return fullPath;
}

module.exports = generatePaymentReport;
