import fs from "node:fs";
import path from "node:path";
import ExcelJS from "exceljs";

const outputDir = path.resolve("C:/Codex/FusionWeb/docs/report-template-styles/excel");
fs.mkdirSync(outputDir, { recursive: true });

for (const file of fs.readdirSync(outputDir)) {
  if (file.toLowerCase().endsWith(".xlsx")) {
    fs.unlinkSync(path.join(outputDir, file));
  }
}

const data = {
  counts: [
    ["端口", 10],
    ["URL", 569],
    ["指纹", 1265],
    ["漏洞", 5],
    ["严重", 2],
    ["高危", 2],
  ],
  ports: [
    ["192.168.102.129", 25, "tcp", "smtp", "open", "Postfix smtpd"],
    ["192.168.102.129", 110, "tcp", "pop3", "open", "Dovecot ready"],
    ["192.168.102.129", 3389, "tcp", "rdp", "open", "Microsoft Terminal Services"],
    ["192.168.102.129", 5357, "tcp", "http", "open", "Microsoft HTTPAPI httpd"],
  ],
  recon: [
    ["https://pifa.rclsdzp.cn/index/user/login.html", 200, "登录 - 鲁盛豆制品批发", 9592],
    ["http://www.fengfansuliao.cn", 301, "301 Moved Permanently", 257],
    ["http://111.35.72.184:66/Web_sc/login.gn", 200, "异速联E-Soonlink 2020标准版", 4801],
  ],
  fingerprints: [
    ["rdp://192.168.102.129:3389", "Microsoft-Windows远程连接", "Windows"],
    ["http://192.168.102.129:5357/", "Microsoft-HTTPAPI", "web"],
    ["http://192.168.102.129:62486/", "Next.js", "web"],
  ],
  vulns: [
    ["Thinkphp Lang - Local File Inclusion", "critical", "http://cisstf.com/?lang=../../thinkphp/base", "优先修复"],
    ["DaHua ICC GetClassValue.jsp RCE", "critical", "https://60.8.70.142:8443/evo-apigw/admin/API/Developer/GetClassValue.jsp", "立即隔离"],
    ["Weak TLS Configuration", "high", "https://example.internal", "计划修复"],
  ],
  request: `POST /evo-apigw/admin/API/Developer/GetClassValue.jsp HTTP/1.1
Host: 60.8.70.142:8443
User-Agent: Mozilla/5.0
Content-Type: application/json

{
  "data": {
    "clazzName": "com.dahua.admin.util.RuntimeUtil",
    "methodName": "syncexecReturnInputStream",
    "fieldName": ["id"]
  }
}`,
  response: `HTTP/1.1 200
Server: nginx
Content-Type: application/json;charset=UTF-8

{"code":1000,"desc":"Success","data":"uid=0(root) gid=0(root) groups=0(root)"}`,
};

const palettes = {
  blue: { dark: "1E3A8A", main: "2563EB", soft: "DBEAFE", pale: "EFF6FF", text: "111827", danger: "DC2626" },
  slate: { dark: "0F172A", main: "334155", soft: "E2E8F0", pale: "F8FAFC", text: "111827", danger: "B91C1C" },
  red: { dark: "7F1D1D", main: "DC2626", soft: "FEE2E2", pale: "FFF1F2", text: "111827", danger: "991B1B" },
  green: { dark: "14532D", main: "16A34A", soft: "DCFCE7", pale: "F0FDF4", text: "052E16", danger: "BE123C" },
  amber: { dark: "78350F", main: "D97706", soft: "FEF3C7", pale: "FFFBEB", text: "1F2937", danger: "B91C1C" },
};

const border = { style: "thin", color: { argb: "FFD5DCE8" } };
const allBorder = { top: border, left: border, bottom: border, right: border };

function styleSheet(ws, widths = []) {
  ws.properties.defaultRowHeight = 24;
  widths.forEach((width, index) => {
    ws.getColumn(index + 1).width = width;
  });
  ws.eachRow((row) => {
    row.eachCell((cell) => {
      cell.font = { name: "Microsoft YaHei UI", size: 10, color: { argb: "FF111827" } };
      cell.alignment = { vertical: "middle", wrapText: true };
      cell.border = allBorder;
    });
  });
}

function title(ws, text, lastCol, palette) {
  ws.mergeCells(1, 1, 2, lastCol);
  const cell = ws.getCell("A1");
  cell.value = text;
  cell.font = { name: "Microsoft YaHei UI", size: 20, bold: true, color: { argb: "FFFFFFFF" } };
  cell.alignment = { vertical: "middle", horizontal: "center" };
  cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: `FF${palette.dark}` } };
  cell.border = allBorder;
}

function headerRow(row, palette) {
  row.eachCell((cell) => {
    cell.font = { name: "Microsoft YaHei UI", size: 10, bold: true, color: { argb: "FFFFFFFF" } };
    cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: `FF${palette.main}` } };
    cell.alignment = { vertical: "middle", horizontal: "center", wrapText: true };
    cell.border = allBorder;
  });
}

function addTable(ws, startRow, startCol, headers, rows, palette) {
  const header = ws.getRow(startRow);
  headers.forEach((h, i) => {
    header.getCell(startCol + i).value = h;
  });
  headerRow(header, palette);
  rows.forEach((row, r) => {
    row.forEach((value, c) => {
      const cell = ws.getCell(startRow + 1 + r, startCol + c);
      cell.value = value;
      cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: r % 2 === 0 ? "FFFFFFFF" : `FF${palette.pale}` } };
    });
  });
  ws.autoFilter = {
    from: { row: startRow, column: startCol },
    to: { row: startRow, column: startCol + headers.length - 1 },
  };
}

function addKpis(ws, startRow, palette, perRow = 6) {
  data.counts.forEach(([label, value], i) => {
    const rowOffset = Math.floor(i / perRow) * 3;
    const col = 1 + (i % perRow) * 2;
    ws.mergeCells(startRow + rowOffset, col, startRow + rowOffset, col + 1);
    ws.mergeCells(startRow + rowOffset + 1, col, startRow + rowOffset + 2, col + 1);
    const labelCell = ws.getCell(startRow + rowOffset, col);
    const valueCell = ws.getCell(startRow + rowOffset + 1, col);
    labelCell.value = label;
    valueCell.value = value;
    labelCell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: `FF${palette.soft}` } };
    valueCell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FFFFFFFF" } };
    labelCell.font = { name: "Microsoft YaHei UI", size: 10, bold: true, color: { argb: `FF${palette.dark}` } };
    valueCell.font = { name: "Microsoft YaHei UI", size: 22, bold: true, color: { argb: `FF${palette.main}` } };
    labelCell.alignment = { horizontal: "center", vertical: "middle" };
    valueCell.alignment = { horizontal: "center", vertical: "middle" };
    labelCell.border = allBorder;
    valueCell.border = allBorder;
  });
}

async function save(workbook, fileName) {
  workbook.creator = "FusionWeb";
  workbook.created = new Date("2026-07-23T00:00:00+08:00");
  await workbook.xlsx.writeFile(path.join(outputDir, fileName));
}

async function dashboard() {
  const wb = new ExcelJS.Workbook();
  const p = palettes.blue;
  const ws = wb.addWorksheet("总览看板", { views: [{ showGridLines: false }] });
  title(ws, "FusionWeb 扫描报告 - 管理层摘要看板", 12, p);
  addKpis(ws, 4, p);
  ws.mergeCells("A8:F8");
  ws.getCell("A8").value = "优先修复风险";
  headerRow(ws.getRow(8), p);
  addTable(ws, 9, 1, ["漏洞名称", "等级", "目标", "处置建议"], data.vulns, p);
  addTable(ws, 9, 7, ["风险类型", "数量"], [["严重漏洞", 2], ["高危漏洞", 2], ["公网入口", 569], ["开放端口", 10]], p);
  styleSheet(ws, [22, 14, 56, 18, 16, 16, 18, 12, 12, 12, 12, 12]);
  await save(wb, "01-executive-dashboard.xlsx");
}

async function multiSheetAudit() {
  const wb = new ExcelJS.Workbook();
  const p = palettes.slate;
  const overview = wb.addWorksheet("00 报告总览", { views: [{ showGridLines: false }] });
  title(overview, "FusionWeb 扫描报告 - 多 Sheet 审计工作簿", 10, p);
  addKpis(overview, 4, p, 5);
  addTable(overview, 9, 1, ["模块", "Sheet", "说明"], [["端口信息", "01 端口信息", "开放端口与服务"], ["信息收集", "02 信息收集", "URL、状态码、标题"], ["指纹识别", "03 指纹识别", "技术栈识别"], ["漏洞详情", "04 漏洞详情", "漏洞与整改建议"], ["数据包证据", "05 数据包证据", "请求包与响应包"]], p);
  styleSheet(overview, [18, 22, 56, 16, 16, 16, 16, 16, 16, 16]);
  const specs = [
    ["01 端口信息", ["主机", "端口", "协议", "服务", "状态", "Banner"], data.ports, [20, 10, 10, 18, 12, 34]],
    ["02 信息收集", ["URL", "状态码", "标题", "长度"], data.recon, [58, 12, 32, 12]],
    ["03 指纹识别", ["目标", "指纹", "分类"], data.fingerprints, [50, 34, 16]],
    ["04 漏洞详情", ["漏洞名称", "等级", "目标", "处置建议"], data.vulns, [42, 14, 66, 18]],
  ];
  specs.forEach(([name, headers, rows, widths]) => {
    const ws = wb.addWorksheet(name, { views: [{ state: "frozen", ySplit: 1, showGridLines: false }] });
    addTable(ws, 1, 1, headers, rows, p);
    styleSheet(ws, widths);
  });
  const evidence = wb.addWorksheet("05 数据包证据", { views: [{ showGridLines: false }] });
  title(evidence, "请求包 / 响应包", 4, p);
  addTable(evidence, 4, 1, ["类型", "内容"], [["请求包", data.request], ["响应包", data.response]], p);
  styleSheet(evidence, [16, 110, 16, 16]);
  evidence.getColumn(2).font = { name: "Cascadia Mono", size: 9 };
  await save(wb, "02-multi-sheet-audit.xlsx");
}

async function riskRegister() {
  const wb = new ExcelJS.Workbook();
  const p = palettes.red;
  const ws = wb.addWorksheet("风险登记表", { views: [{ state: "frozen", ySplit: 4, showGridLines: false }] });
  title(ws, "FusionWeb 扫描报告 - 风险登记表", 9, p);
  addTable(ws, 4, 1, ["编号", "风险项", "等级", "影响资产", "状态", "负责人", "计划完成", "复测结果", "备注"], data.vulns.map((v, i) => [`R-${i + 1}`, ...v.slice(0, 3), "待处理", "安全团队", "2026-07-30", "未复测", v[3]]), p);
  styleSheet(ws, [12, 40, 14, 58, 14, 16, 18, 16, 26]);
  await save(wb, "03-risk-register.xlsx");
}

async function assetInventory() {
  const wb = new ExcelJS.Workbook();
  const p = palettes.green;
  const ws = wb.addWorksheet("资产画像", { views: [{ showGridLines: false }] });
  title(ws, "FusionWeb 扫描报告 - 资产画像清单", 8, p);
  addKpis(ws, 4, p, 4);
  addTable(ws, 10, 1, ["资产", "开放端口", "服务画像", "指纹", "关联 URL", "风险数量"], [
    ["192.168.102.129", "25, 110, 3389, 5357", "smtp / pop3 / rdp / http", "Microsoft HTTPAPI, Windows RDP", "http://192.168.102.129:5357/", 2],
    ["60.8.70.142", "8443", "https", "DaHua ICC", "https://60.8.70.142:8443/evo-apigw/admin/API/Developer/GetClassValue.jsp", 1],
    ["cisstf.com", "80", "http", "ThinkPHP", "http://cisstf.com/?lang=../../thinkphp/base", 1],
  ], p);
  styleSheet(ws, [24, 24, 34, 36, 70, 14, 14, 14]);
  await save(wb, "04-asset-inventory.xlsx");
}

async function remediationTracker() {
  const wb = new ExcelJS.Workbook();
  const p = palettes.amber;
  const ws = wb.addWorksheet("整改跟踪", { views: [{ state: "frozen", ySplit: 4, showGridLines: false }] });
  title(ws, "FusionWeb 扫描报告 - 整改跟踪模板", 10, p);
  addTable(ws, 4, 1, ["阶段", "任务", "漏洞", "等级", "处理人", "开始时间", "截止时间", "当前状态", "验证方式", "说明"], [
    ["确认", "确认漏洞可复现", data.vulns[0][0], "critical", "安全团队", "2026-07-23", "2026-07-24", "进行中", "复测请求包", "先确认影响面"],
    ["修复", "升级或临时阻断", data.vulns[1][0], "critical", "业务团队", "2026-07-24", "2026-07-26", "待开始", "版本核验", "公网入口优先"],
    ["复测", "复测并关闭风险", data.vulns[2][0], "high", "安全团队", "2026-07-26", "2026-07-30", "待开始", "扫描复测", "保留复测记录"],
  ], p);
  styleSheet(ws, [14, 24, 42, 14, 16, 16, 16, 16, 20, 32]);
  await save(wb, "05-remediation-tracker.xlsx");
}

async function evidenceWorkbook() {
  const wb = new ExcelJS.Workbook();
  const p = palettes.slate;
  const index = wb.addWorksheet("证据索引", { views: [{ showGridLines: false }] });
  title(index, "FusionWeb 扫描报告 - 数据包证据工作簿", 6, p);
  addTable(index, 4, 1, ["编号", "漏洞", "等级", "请求包 Sheet", "响应包 Sheet", "目标"], data.vulns.map((v, i) => [`E-${i + 1}`, v[0], v[1], `请求包-${i + 1}`, `响应包-${i + 1}`, v[2]]), p);
  styleSheet(index, [12, 42, 14, 18, 18, 70]);
  data.vulns.forEach((v, i) => {
    const req = wb.addWorksheet(`请求包-${i + 1}`, { views: [{ showGridLines: false }] });
    title(req, `请求包 - ${v[0]}`, 3, p);
    addTable(req, 4, 1, ["字段", "内容"], [["目标", v[2]], ["HTTP 请求", data.request]], p);
    styleSheet(req, [18, 110, 16]);
    req.getColumn(2).font = { name: "Cascadia Mono", size: 9 };
    const res = wb.addWorksheet(`响应包-${i + 1}`, { views: [{ showGridLines: false }] });
    title(res, `响应包 - ${v[0]}`, 3, p);
    addTable(res, 4, 1, ["字段", "内容"], [["目标", v[2]], ["HTTP 响应", data.response]], p);
    styleSheet(res, [18, 110, 16]);
    res.getColumn(2).font = { name: "Cascadia Mono", size: 9 };
  });
  await save(wb, "06-evidence-workbook.xlsx");
}

async function managementBrief() {
  const wb = new ExcelJS.Workbook();
  const p = palettes.blue;
  const ws = wb.addWorksheet("一页简报", { views: [{ showGridLines: false }] });
  title(ws, "FusionWeb 扫描报告 - 一页简报", 8, p);
  ws.mergeCells("A4:D8");
  ws.getCell("A4").value = "当前核心风险集中在严重漏洞和公网暴露资产，建议优先处理 RCE 与文件包含类问题。";
  ws.getCell("A4").font = { name: "Microsoft YaHei UI", size: 18, bold: true, color: { argb: `FF${p.dark}` } };
  ws.getCell("A4").alignment = { vertical: "middle", horizontal: "center", wrapText: true };
  ws.getCell("A4").fill = { type: "pattern", pattern: "solid", fgColor: { argb: `FF${p.soft}` } };
  addKpis(ws, 10, p, 4);
  addTable(ws, 17, 1, ["优先级", "事项", "原因", "建议"], [["P0", "处理严重漏洞", "可直接造成高影响风险", "立即修复"], ["P1", "复核公网入口", "攻击面较大", "限制访问"], ["P2", "整理资产指纹", "降低误报和遗漏", "补全资产台账"]], p);
  styleSheet(ws, [14, 28, 42, 30, 16, 16, 16, 16]);
  await save(wb, "07-management-brief.xlsx");
}

async function technicalRawData() {
  const wb = new ExcelJS.Workbook();
  const p = palettes.slate;
  const ws = wb.addWorksheet("技术明细", { views: [{ state: "frozen", ySplit: 1, showGridLines: false }] });
  addTable(ws, 1, 1, ["数据类型", "目标", "字段一", "字段二", "字段三", "风险等级", "备注"], [
    ...data.ports.map((p) => ["端口", p[0], p[1], p[3], p[5], "", "open"]),
    ...data.recon.map((r) => ["URL", r[0], r[1], r[2], r[3], "", "已收集"]),
    ...data.fingerprints.map((f) => ["指纹", f[0], f[1], f[2], "", "", "已识别"]),
    ...data.vulns.map((v) => ["漏洞", v[2], v[0], v[3], "", v[1], "待验证"]),
  ], p);
  styleSheet(ws, [14, 70, 38, 36, 24, 14, 18]);
  await save(wb, "08-technical-raw-data.xlsx");
}

async function complianceChecklist() {
  const wb = new ExcelJS.Workbook();
  const p = palettes.green;
  const ws = wb.addWorksheet("合规检查", { views: [{ showGridLines: false }] });
  title(ws, "FusionWeb 扫描报告 - 合规检查清单", 8, p);
  addTable(ws, 4, 1, ["检查项", "检查内容", "当前结果", "风险等级", "证据来源", "建议"], [
    ["资产暴露", "是否存在非必要公网服务", "发现 10 个开放端口", "medium", "端口信息", "复核必要性"],
    ["漏洞修复", "是否存在严重漏洞", "发现 2 个严重漏洞", "critical", "漏洞详情", "立即修复"],
    ["传输安全", "是否存在弱 TLS 配置", "发现弱 TLS 配置", "high", "漏洞详情", "升级配置"],
    ["证据留存", "是否保留请求响应证据", "已保留", "info", "数据包证据", "归档保存"],
  ], p);
  styleSheet(ws, [18, 36, 34, 14, 18, 32, 14, 14]);
  await save(wb, "09-compliance-checklist.xlsx");
}

async function incidentResponse() {
  const wb = new ExcelJS.Workbook();
  const p = palettes.red;
  const ws = wb.addWorksheet("应急处置", { views: [{ showGridLines: false }] });
  title(ws, "FusionWeb 扫描报告 - 应急处置记录", 9, p);
  addTable(ws, 4, 1, ["时间线", "事件", "发现内容", "影响", "动作", "负责人", "状态", "证据", "备注"], [
    ["T+0", "发现漏洞", data.vulns[1][0], "critical", "记录证据", "安全团队", "完成", "请求包/响应包", "保留原始数据"],
    ["T+1", "临时阻断", "限制公网访问", "降低风险", "加访问控制", "运维团队", "待确认", "访问策略", "先控面"],
    ["T+2", "正式修复", "升级或补丁", "消除风险", "发布修复", "研发团队", "待开始", "版本记录", "安排窗口"],
    ["T+3", "复测关闭", "重新扫描", "确认闭环", "生成复测报告", "安全团队", "待开始", "复测证据", "关闭风险"],
  ], p);
  styleSheet(ws, [14, 18, 38, 14, 24, 16, 14, 28, 26]);
  await save(wb, "10-incident-response.xlsx");
}

await dashboard();
await multiSheetAudit();
await riskRegister();
await assetInventory();
await remediationTracker();
await evidenceWorkbook();
await managementBrief();
await technicalRawData();
await complianceChecklist();
await incidentResponse();

const indexPath = path.resolve("C:/Codex/FusionWeb/docs/report-template-styles/index.html");
let indexHtml = fs.readFileSync(indexPath, "utf8");
const excelList = `<h2>Excel 10 款</h2>
        <ol>
          <li><a href="excel/01-executive-dashboard.xlsx">01 管理层摘要看板</a></li>
          <li><a href="excel/02-multi-sheet-audit.xlsx">02 多 Sheet 审计工作簿</a></li>
          <li><a href="excel/03-risk-register.xlsx">03 风险登记表</a></li>
          <li><a href="excel/04-asset-inventory.xlsx">04 资产画像清单</a></li>
          <li><a href="excel/05-remediation-tracker.xlsx">05 整改跟踪模板</a></li>
          <li><a href="excel/06-evidence-workbook.xlsx">06 数据包证据工作簿</a></li>
          <li><a href="excel/07-management-brief.xlsx">07 一页管理简报</a></li>
          <li><a href="excel/08-technical-raw-data.xlsx">08 技术明细数据表</a></li>
          <li><a href="excel/09-compliance-checklist.xlsx">09 合规检查清单</a></li>
          <li><a href="excel/10-incident-response.xlsx">10 应急处置记录</a></li>
        </ol>`;

indexHtml = indexHtml.replace(/<h2>Excel 10 款<\/h2>\s*<ol>[\s\S]*?<\/ol>/, excelList);
indexHtml = indexHtml.replace(/<p class="hint">[\s\S]*?<\/p>/, '<p class="hint">HTML 和 Excel 都已重做为不同布局，不再只是换颜色。Markdown 仍保留原来的 10 款样式预览。</p>');
fs.writeFileSync(indexPath, indexHtml, "utf8");
