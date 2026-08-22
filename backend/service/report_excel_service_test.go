package service

import (
	"testing"

	"github.com/xuri/excelize/v2"
)

func TestExcelReconSheetsAreSplitByType(t *testing.T) {
	data := &ReportData{
		ReconResults: []ReconSummary{
			{
				Type:     "port",
				Target:   "192.168.102.129:62486",
				Host:     "192.168.102.129",
				Port:     "62486",
				Protocol: "http",
				Service:  "HTTP",
				Status:   "open",
				Banner:   "HTTP/1.1 200 OK",
			},
			{
				Type:       "url",
				Target:     "http://192.168.102.129:62486",
				Source:     "httpx",
				StatusCode: "200",
				Title:      "FusionWeb",
				Length:     "1024",
			},
		},
	}

	f := excelize.NewFile()
	defer f.Close()
	headerStyle, _ := f.NewStyle(&excelize.Style{})
	cellStyle, _ := f.NewStyle(&excelize.Style{})

	s := &ReportService{}
	portResults, webResults := splitReportReconResults(data.ReconResults)
	s.createPortServiceSheet(f, portResults, headerStyle, cellStyle)
	s.createWebServiceSheet(f, webResults, headerStyle, cellStyle)

	sheets := map[string]bool{}
	for _, name := range f.GetSheetList() {
		sheets[name] = true
	}
	if !sheets["端口服务"] {
		t.Fatalf("expected 端口服务 sheet, got %v", f.GetSheetList())
	}
	if !sheets["Web服务"] {
		t.Fatalf("expected Web服务 sheet, got %v", f.GetSheetList())
	}
	if sheets["信息收集"] {
		t.Fatalf("did not expect legacy 信息收集 sheet")
	}

	if got, _ := f.GetCellValue("端口服务", "D2"); got != "HTTP" {
		t.Fatalf("expected port protocol http, got %q", got)
	}
	if got, _ := f.GetCellValue("Web服务", "B2"); got != "http://192.168.102.129:62486" {
		t.Fatalf("expected target URL, got %q", got)
	}
}
