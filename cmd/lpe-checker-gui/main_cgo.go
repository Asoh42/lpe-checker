//go:build cgo

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"

	"lpe-checker/internal/batch"
	"lpe-checker/internal/display"
	"lpe-checker/internal/model"
	htmlreport "lpe-checker/internal/report"
	"lpe-checker/internal/rules"
)

type hostInputRow struct {
	host           *widget.Entry
	port           *widget.Entry
	user           *widget.Entry
	password       *widget.Entry
	passwordSource *widget.Select
	row            *fyne.Container
}

func batchReportHosts(results []batch.Result) []model.BatchReportHost {
	hosts := make([]model.BatchReportHost, 0, len(results))
	for _, result := range results {
		item := model.BatchReportHost{Target: result.Target, Status: htmlreport.BatchStatusFailed}
		if result.Status == batch.StatusSuccess {
			item.Status = htmlreport.BatchStatusSuccess
		}
		if result.Err != nil {
			item.ScanError = result.Err
		} else if item.Status == htmlreport.BatchStatusFailed {
			item.ScanError = errors.New(result.Status)
		}
		if result.Status == batch.StatusSuccess || result.Status == batch.StatusCommandError {
			reportCopy := result.Report
			item.Report = &reportCopy
		}
		hosts = append(hosts, item)
	}
	return hosts
}

// fixedHeightLayout keeps scrollable input sections responsive in width while
// reserving only a compact vertical area.
type fixedHeightLayout struct{ height float32 }

func (l *fixedHeightLayout) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	for _, object := range objects {
		object.Move(fyne.NewPos(0, 0))
		object.Resize(size)
	}
}

func (l *fixedHeightLayout) MinSize([]fyne.CanvasObject) fyne.Size {
	return fyne.NewSize(0, l.height)
}

type compactVBoxLayout struct{ gap float32 }

func (l *compactVBoxLayout) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	y := float32(0)
	for _, object := range objects {
		height := object.MinSize().Height
		object.Move(fyne.NewPos(0, y))
		object.Resize(fyne.NewSize(size.Width, height))
		y += height + l.gap
	}
}

func (l *compactVBoxLayout) MinSize(objects []fyne.CanvasObject) fyne.Size {
	minimum := fyne.NewSize(0, 0)
	for index, object := range objects {
		size := object.MinSize()
		if size.Width > minimum.Width {
			minimum.Width = size.Width
		}
		minimum.Height += size.Height
		if index > 0 {
			minimum.Height += l.gap
		}
	}
	return minimum
}

func truncatedSingleLine(text string, maxRunes int) string {
	text = strings.Join(strings.Fields(text), " ")
	runes := []rune(text)
	if len(runes) <= maxRunes {
		return text
	}
	return string(runes[:maxRunes-1]) + "…"
}

func newTruncatedLabel() *widget.Label {
	label := widget.NewLabel("")
	label.Wrapping = fyne.TextWrapOff
	label.Truncation = fyne.TextTruncateEllipsis
	return label
}

func main() {
	a := app.NewWithID("local.lpe-checker")
	w := a.NewWindow(display.GUIText("window_title"))
	// Fyne v2.5 does not expose a stable public API for querying the usable
	// monitor work area before showing a window. Use a conservative resizable
	// default that fits typical 1366x768 laptop displays.
	w.Resize(fyne.NewSize(1000, 680))

	var currentReport model.Report
	hasReport := false
	var currentFailedReport model.FailedScanReport
	hasFailedReport := false
	findings := []model.Finding{}
	status := widget.NewLabel(display.GUIText("ready"))

	detailText := widget.NewLabel(display.GUIText("no_host_selected"))
	detailText.Wrapping = fyne.TextWrapWord
	detailTextScroll := container.NewVScroll(detailText)
	setSystemInfo := func(text string) {
		detailText.SetText("")
		detailText.SetText(text)
		detailText.Refresh()
	}

	findingsTable := widget.NewTable(
		func() (int, int) { return len(findings) + 1, 5 },
		func() fyne.CanvasObject { return newTruncatedLabel() },
		func(id widget.TableCellID, obj fyne.CanvasObject) {
			label := obj.(*widget.Label)
			if id.Row == 0 {
				headers := []string{display.GUIText("finding_id"), display.GUIText("finding_name"), display.GUIText("severity"), display.GUIText("reason"), display.GUIText("remediation")}
				label.SetText(headers[id.Col])
				label.TextStyle = fyne.TextStyle{Bold: true}
				return
			}
			label.TextStyle = fyne.TextStyle{}
			finding := findings[id.Row-1]
			cols := []string{finding.ID, finding.Name, display.SeverityZH(strings.ToLower(finding.Severity)), finding.Reason, display.FindingRemediationZH(finding)}
			label.SetText(cols[id.Col])
		},
	)
	for column, width := range []float32{150, 220, 100, 280, 330} {
		findingsTable.SetColumnWidth(column, width)
	}
	clearDetails := func(message string) {
		currentReport = model.Report{}
		hasReport = false
		currentFailedReport = model.FailedScanReport{}
		hasFailedReport = false
		findings = []model.Finding{}
		setSystemInfo(message)
		findingsTable.Refresh()
	}

	var resultsMu sync.Mutex
	overviewResults := []batch.Result{}
	overviewList := widget.NewList(
		func() int { resultsMu.Lock(); defer resultsMu.Unlock(); return len(overviewResults) },
		func() fyne.CanvasObject { return newTruncatedLabel() },
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			resultsMu.Lock()
			if id < 0 || id >= len(overviewResults) {
				resultsMu.Unlock()
				return
			}
			result := overviewResults[id]
			resultsMu.Unlock()
			text := result.Target + " | " + display.BatchStatusZH(result.Status)
			if result.Status == batch.StatusSuccess || result.Status == batch.StatusCommandError {
				text += " | " + display.RiskSummaryZH(result.Report)
			} else if result.Err != nil {
				text += " | " + truncatedSingleLine(htmlreport.ClassifyScanError(result.Err), 80)
			}
			obj.(*widget.Label).SetText(text)
		},
	)
	overviewList.OnSelected = func(id widget.ListItemID) {
		resultsMu.Lock()
		if id < 0 || id >= len(overviewResults) {
			resultsMu.Unlock()
			return
		}
		result := overviewResults[id]
		resultsMu.Unlock()
		if result.Status == batch.StatusSuccess || result.Status == batch.StatusCommandError {
			currentReport = result.Report
			hasReport = true
			currentFailedReport = model.FailedScanReport{}
			hasFailedReport = false
			findings = result.Report.Findings
			setSystemInfo(display.SystemInfoText(result.Report.SystemInfo))
			findingsTable.Refresh()
			return
		}
		if result.Err != nil {
			currentReport = model.Report{}
			hasReport = false
			currentFailedReport = htmlreport.NewFailedScanReport(result.Target, result.Report.Meta.ScanTime, result.Err)
			hasFailedReport = true
			findings = []model.Finding{}
			setSystemInfo(currentFailedReport.Error)
			findingsTable.Refresh()
		} else {
			clearDetails(display.BatchStatusZH(result.Status))
		}
	}

	hostRowsBox := container.NewVBox()
	hostRows := []*hostInputRow{}
	credentialGroups := make(map[string]*widget.Entry)
	credentialRowsBox := container.NewVBox()
	credentialOptions := func() []string {
		names := make([]string, 0, len(credentialGroups))
		for name := range credentialGroups {
			names = append(names, name)
		}
		sort.Strings(names)
		return append([]string{display.GUIText("own_password")}, names...)
	}
	refreshCredentialSources := func() {
		options := credentialOptions()
		for _, hostRow := range hostRows {
			selected := hostRow.passwordSource.Selected
			hostRow.passwordSource.SetOptions(options)
			if selected == "" || selected == display.GUIText("own_password") {
				hostRow.passwordSource.SetSelected(display.GUIText("own_password"))
				hostRow.password.Enable()
			} else if _, exists := credentialGroups[selected]; exists {
				hostRow.passwordSource.SetSelected(selected)
				hostRow.password.Disable()
			} else {
				// Preserve a deleted group name so scan validation can report it.
				hostRow.passwordSource.Selected = selected
				hostRow.passwordSource.Refresh()
				hostRow.password.Disable()
			}
		}
	}
	var rebuildCredentialRows func()
	rebuildCredentialRows = func() {
		credentialRowsBox.RemoveAll()
		names := make([]string, 0, len(credentialGroups))
		for name := range credentialGroups {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			groupName := name
			deleteButton := widget.NewButton(display.GUIText("delete_host"), func() {
				delete(credentialGroups, groupName)
				rebuildCredentialRows()
				refreshCredentialSources()
			})
			credentialRowsBox.Add(container.NewGridWithColumns(3, widget.NewLabel(groupName), credentialGroups[groupName], deleteButton))
		}
		credentialRowsBox.Refresh()
	}
	var rebuildHostRows func()
	rebuildHostRows = func() {
		hostRowsBox.RemoveAll()
		for _, hostRow := range hostRows {
			hostRowsBox.Add(hostRow.row)
		}
		hostRowsBox.Refresh()
	}
	addHostRow := func(initial batch.Host) {
		entryHost := widget.NewEntry()
		entryHost.SetPlaceHolder("192.0.2.10")
		entryHost.SetText(initial.Host)
		entryPort := widget.NewEntry()
		if initial.Port <= 0 {
			initial.Port = 22
		}
		entryPort.SetText(strconv.Itoa(initial.Port))
		entryUser := widget.NewEntry()
		entryUser.SetPlaceHolder("root")
		entryUser.SetText(initial.User)
		entryPassword := widget.NewPasswordEntry()
		entryPassword.SetText(initial.Password)
		passwordSource := widget.NewSelect(credentialOptions(), nil)
		hostRow := &hostInputRow{host: entryHost, port: entryPort, user: entryUser, password: entryPassword, passwordSource: passwordSource}
		passwordSource.OnChanged = func(selected string) {
			if selected == display.GUIText("own_password") {
				entryPassword.Enable()
			} else {
				entryPassword.Disable()
			}
		}
		passwordSource.SetSelected(display.GUIText("own_password"))
		deleteButton := widget.NewButton(display.GUIText("delete_host"), func() {
			for index, candidate := range hostRows {
				if candidate == hostRow {
					hostRows = append(hostRows[:index], hostRows[index+1:]...)
					break
				}
			}
			rebuildHostRows()
		})
		hostRow.row = container.NewGridWithColumns(6, entryHost, entryPort, entryUser, passwordSource, entryPassword, deleteButton)
		hostRows = append(hostRows, hostRow)
		rebuildHostRows()
	}
	addHostRow(batch.Host{})
	importCSV := func() {
		open := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				status.SetText(display.GUIText("csv_open_failed") + ": " + err.Error())
				return
			}
			if reader == nil {
				return
			}
			defer reader.Close()
			imported, skipped, parseErr := parseCSVHosts(reader)
			if parseErr != nil {
				status.SetText(display.GUIText("csv_open_failed") + ": " + parseErr.Error())
				return
			}
			// The initial untouched row is only a placeholder, not user-entered data.
			if len(imported) > 0 && len(hostRows) == 1 && strings.TrimSpace(hostRows[0].host.Text) == "" &&
				strings.TrimSpace(hostRows[0].user.Text) == "" && hostRows[0].password.Text == "" && strings.TrimSpace(hostRows[0].port.Text) == "22" {
				hostRows = nil
				rebuildHostRows()
			}
			for _, host := range imported {
				addHostRow(host)
			}
			status.SetText(display.GUICSVImportResult(len(imported), skipped))
		}, w)
		open.SetFilter(storage.NewExtensionFileFilter([]string{".csv"}))
		open.Show()
	}
	addCredentialGroup := func() {
		nameEntry := widget.NewEntry()
		passwordEntry := widget.NewPasswordEntry()
		form := dialog.NewForm(
			display.GUIText("add_credential"), display.GUIText("confirm"), display.GUIText("cancel"),
			[]*widget.FormItem{
				widget.NewFormItem(display.GUIText("credential_name"), nameEntry),
				widget.NewFormItem(display.GUIText("password"), passwordEntry),
			},
			func(confirmed bool) {
				if !confirmed {
					return
				}
				name := strings.TrimSpace(nameEntry.Text)
				if name == "" || passwordEntry.Text == "" {
					status.SetText(display.GUIText("credential_required"))
					return
				}
				if strings.EqualFold(name, display.GUIText("own_password")) {
					status.SetText(display.GUIText("credential_duplicate"))
					return
				}
				for existing := range credentialGroups {
					if strings.EqualFold(existing, name) {
						status.SetText(display.GUIText("credential_duplicate"))
						return
					}
				}
				groupPassword := widget.NewPasswordEntry()
				groupPassword.SetText(passwordEntry.Text)
				credentialGroups[name] = groupPassword
				rebuildCredentialRows()
				refreshCredentialSources()
			}, w,
		)
		form.Show()
	}
	credentialHeader := container.NewHBox(
		widget.NewLabel(display.GUIText("credential_groups")),
		widget.NewButton(display.GUIText("add_credential"), addCredentialGroup),
	)
	credentialScroll := container.NewVScroll(credentialRowsBox)
	credentialArea := container.New(&fixedHeightLayout{height: 64}, credentialScroll)
	hostHeader := container.NewGridWithColumns(6,
		widget.NewLabel(display.GUIText("host")), widget.NewLabel(display.GUIText("port")),
		widget.NewLabel(display.GUIText("user")), widget.NewLabel(display.GUIText("password_source")),
		widget.NewLabel(display.GUIText("password")),
		container.NewHBox(
			widget.NewButton(display.GUIText("add_host"), func() { addHostRow(batch.Host{}) }),
			widget.NewButton(display.GUIText("import_csv"), importCSV),
		),
	)
	securityNotice := widget.NewLabel(display.GUIText("csv_security"))
	securityNotice.Wrapping = fyne.TextWrapWord
	hostScroll := container.NewVScroll(hostRowsBox)
	hostArea := container.New(&fixedHeightLayout{height: 84}, hostScroll)

	ruleChecks := make(map[string]*widget.Check)
	ruleRows := container.NewVBox()
	loadedRules, ruleLoadErr := rules.LoadDefaultWithSources("")
	if ruleLoadErr != nil {
		status.SetText(display.GUIText("scan_init_failed") + ": " + ruleLoadErr.Error())
	} else {
		for _, rule := range loadedRules.Rules {
			check := widget.NewCheck(rule.ID+" — "+rule.Name, nil)
			check.SetChecked(true)
			ruleChecks[rule.ID] = check
			ruleRows.Add(check)
		}
	}
	ruleScroll := container.NewVScroll(ruleRows)
	ruleArea := container.New(&fixedHeightLayout{height: 76}, ruleScroll)
	ruleHeader := container.NewHBox(
		widget.NewLabel(display.GUIText("detection_rules")),
		widget.NewButton(display.GUIText("select_all"), func() {
			for _, check := range ruleChecks {
				check.SetChecked(true)
			}
		}),
		widget.NewButton(display.GUIText("select_none"), func() {
			for _, check := range ruleChecks {
				check.SetChecked(false)
			}
		}),
	)

	var scanCancel context.CancelFunc
	var scanButton, stopButton *widget.Button
	var batchExportButtons []*widget.Button
	startBatch := func() {
		if len(hostRows) == 0 {
			status.SetText(display.GUIText("no_hosts"))
			return
		}
		groupPasswords := make(map[string]string, len(credentialGroups))
		for name, passwordEntry := range credentialGroups {
			groupPasswords[name] = passwordEntry.Text
		}
		hosts := make([]batch.Host, 0, len(hostRows))
		for _, row := range hostRows {
			port, err := strconv.Atoi(strings.TrimSpace(row.port.Text))
			hostName := strings.TrimSpace(row.host.Text)
			if hostName == "" || strings.TrimSpace(row.user.Text) == "" || err != nil || port < 1 || port > 65535 {
				status.SetText(display.GUIText("invalid_host_row"))
				return
			}
			source := row.passwordSource.Selected
			if source == display.GUIText("own_password") {
				source = credentialSourceOwn
			}
			password, passwordErr := resolveHostPassword(source, row.password.Text, groupPasswords)
			if passwordErr != nil {
				var resolutionErr *credentialResolutionError
				if errors.As(passwordErr, &resolutionErr) {
					status.SetText(display.GUICredentialValidation(hostName, resolutionErr.Kind, resolutionErr.Group))
				} else {
					status.SetText(display.GUICredentialValidation(hostName, "", ""))
				}
				return
			}
			hosts = append(hosts, batch.Host{Host: hostName, Port: port, User: strings.TrimSpace(row.user.Text), Password: password})
		}
		selectedIDs := []string{}
		for _, rule := range loadedRules.Rules {
			if check := ruleChecks[rule.ID]; check != nil && check.Checked {
				selectedIDs = append(selectedIDs, rule.ID)
			}
		}
		if len(selectedIDs) == 0 {
			status.SetText(display.GUIText("select_one_rule"))
			return
		}

		resultsMu.Lock()
		overviewResults = make([]batch.Result, len(hosts))
		for index, host := range hosts {
			overviewResults[index] = batch.Result{Index: index, Target: host.ID(), Status: batch.StatusWaiting}
		}
		resultsMu.Unlock()
		overviewList.Refresh()
		clearDetails(display.GUIText("no_host_selected"))
		ctx, cancel := context.WithCancel(context.Background())
		scanCancel = cancel
		scanButton.Disable()
		stopButton.Enable()
		for _, button := range batchExportButtons {
			button.Disable()
		}
		status.SetText(display.GUIBatchProgress(0, len(hosts)))
		go func() {
			done := 0
			finalResults, _ := batch.ScanAll(ctx, hosts, selectedIDs, batch.DefaultConcurrency, nil, func(result batch.Result) {
				if result.Err != nil && result.Status != batch.StatusScanning {
					fmt.Fprintf(os.Stderr, "scan %s failed: %v\n", result.Target, result.Err)
				}
				resultsMu.Lock()
				overviewResults[result.Index] = result
				if result.Status != batch.StatusScanning {
					done++
				}
				currentDone := done
				resultsMu.Unlock()
				overviewList.Refresh()
				status.SetText(display.GUIBatchProgress(currentDone, len(hosts)))
			})
			resultsMu.Lock()
			overviewResults = finalResults
			resultsMu.Unlock()
			overviewList.Refresh()
			status.SetText(display.GUIBatchFinished(len(finalResults)))
			scanButton.Enable()
			stopButton.Disable()
			if len(finalResults) > 0 {
				for _, button := range batchExportButtons {
					button.Enable()
				}
			}
			scanCancel = nil
		}()
	}
	scanButton = widget.NewButton(display.GUIText("batch_scan"), startBatch)
	stopButton = widget.NewButton(display.GUIText("stop_scan"), func() {
		if scanCancel != nil {
			scanCancel()
		}
	})
	stopButton.Disable()

	saveGenerated := func(fileName string, generate func(io.Writer) error) {
		save := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
			if err != nil {
				status.SetText(display.GUIText("save_failed") + ": " + err.Error())
				return
			}
			if writer == nil {
				return
			}
			defer writer.Close()
			if generateErr := generate(writer); generateErr != nil {
				status.SetText(display.GUIText("save_failed") + ": " + generateErr.Error())
				return
			}
			status.SetText(display.GUIText("saved") + ": " + writer.URI().String())
		}, w)
		save.SetFileName(fileName)
		save.Show()
	}

	exportJSON := func() {
		if !hasReport && !hasFailedReport {
			status.SetText(display.GUIText("no_report"))
			return
		}
		saveGenerated("lpe-checker-report.json", func(writer io.Writer) error {
			if hasFailedReport {
				return htmlreport.GenerateFailedScanJSON(writer, currentFailedReport)
			}
			data, marshalErr := json.MarshalIndent(currentReport, "", "  ")
			if marshalErr == nil {
				_, marshalErr = writer.Write(data)
			}
			return marshalErr
		})
	}
	exportHTML := func() {
		if !hasReport && !hasFailedReport {
			status.SetText(display.GUIText("no_report"))
			return
		}
		saveGenerated("lpe-checker-report.html", func(writer io.Writer) error {
			if hasFailedReport {
				return htmlreport.GenerateFailedScanHTML(writer, currentFailedReport)
			}
			return htmlreport.GenerateHTML(writer, currentReport)
		})
	}

	snapshotBatchResults := func() ([]batch.Result, bool) {
		resultsMu.Lock()
		defer resultsMu.Unlock()
		if len(overviewResults) == 0 {
			status.SetText(display.GUIText("no_batch_report"))
			return nil, false
		}
		return append([]batch.Result{}, overviewResults...), true
	}
	showBatchHostSelection := func(results []batch.Result, onSelected func([]batch.Result)) {
		checks := make([]*widget.Check, 0, len(results))
		options := make([]fyne.CanvasObject, 0, len(results))
		for _, result := range results {
			label := display.GUIExportHostOption(result.Target, result.Status, result.Report.Summary.TotalFindings)
			check := widget.NewCheck(label, nil)
			checks = append(checks, check)
			options = append(options, check)
		}
		optionScroll := container.NewVScroll(container.NewVBox(options...))
		optionScroll.SetMinSize(fyne.NewSize(620, 360))
		selectionControls := container.NewHBox(
			widget.NewButton(display.GUIText("select_all"), func() {
				for _, check := range checks {
					check.SetChecked(true)
				}
			}),
			widget.NewButton(display.GUIText("select_none"), func() {
				for _, check := range checks {
					check.SetChecked(false)
				}
			}),
		)
		dialogContent := container.NewVBox(selectionControls, optionScroll)
		selectionDialog := dialog.NewCustomConfirm(
			display.GUIText("export_host_selection_title"),
			display.GUIText("confirm"),
			display.GUIText("cancel"),
			dialogContent,
			func(confirmed bool) {
				if !confirmed {
					return
				}
				indices := make([]int, 0, len(checks))
				for index, check := range checks {
					if check.Checked {
						indices = append(indices, index)
					}
				}
				subset, ok := selectBatchResultSubset(results, indices)
				if !ok {
					status.SetText(display.GUIText("select_one_export_host"))
					return
				}
				onSelected(subset)
			},
			w,
		)
		selectionDialog.Show()
	}
	exportAllBatch := func(onSelected func([]batch.Result)) {
		results, ok := snapshotBatchResults()
		if !ok {
			return
		}
		onSelected(results)
	}
	exportSelectedBatch := func(onSelected func([]batch.Result)) {
		results, ok := snapshotBatchResults()
		if !ok {
			return
		}
		showBatchHostSelection(results, onSelected)
	}
	exportBatchHTMLResults := func(results []batch.Result) {
		batchReport := htmlreport.NewBatchReport(batchReportHosts(results), time.Now())
		saveGenerated("lpe-checker-batch-report.html", func(writer io.Writer) error {
			return htmlreport.GenerateBatchHTML(writer, batchReport)
		})
	}
	exportBatchJSONResults := func(results []batch.Result) {
		batchReport := htmlreport.NewBatchReport(batchReportHosts(results), time.Now())
		saveGenerated("lpe-checker-batch-report.json", func(writer io.Writer) error {
			return htmlreport.GenerateBatchJSON(writer, batchReport)
		})
	}
	exportAllHTMLButton := widget.NewButton(display.GUIText("export_all_html"), func() {
		exportAllBatch(func(results []batch.Result) {
			exportBatchHTMLResults(results)
		})
	})
	exportAllJSONButton := widget.NewButton(display.GUIText("export_all_json"), func() {
		exportAllBatch(func(results []batch.Result) {
			exportBatchJSONResults(results)
		})
	})
	exportSelectedHTMLButton := widget.NewButton(display.GUIText("export_selected_html"), func() {
		exportSelectedBatch(func(results []batch.Result) {
			exportBatchHTMLResults(results)
		})
	})
	exportSelectedJSONButton := widget.NewButton(display.GUIText("export_selected_json"), func() {
		exportSelectedBatch(func(results []batch.Result) {
			exportBatchJSONResults(results)
		})
	})
	batchExportButtons = []*widget.Button{exportAllHTMLButton, exportAllJSONButton, exportSelectedHTMLButton, exportSelectedJSONButton}
	for _, button := range batchExportButtons {
		button.Disable()
	}
	singleExportGroup := container.NewHBox(
		widget.NewLabel(display.GUIText("single_report_group")),
		widget.NewButton(display.GUIText("export_html"), exportHTML),
		widget.NewButton(display.GUIText("export_json"), exportJSON),
	)
	batchExportGroup := container.NewHBox(
		widget.NewLabel(display.GUIText("batch_report_group")),
		exportAllHTMLButton, exportAllJSONButton, exportSelectedHTMLButton, exportSelectedJSONButton,
	)
	actions := container.NewVBox(
		container.NewHBox(scanButton, stopButton, status),
		singleExportGroup,
		batchExportGroup,
	)
	inputArea := container.New(&compactVBoxLayout{gap: 2}, credentialHeader, credentialArea, hostHeader, securityNotice, hostArea, ruleHeader, ruleArea, actions)
	detail := container.NewBorder(widget.NewLabel(display.GUIText("host_details")), nil, nil, nil, container.NewVSplit(detailTextScroll, findingsTable))
	overview := container.NewBorder(widget.NewLabel(display.GUIText("host_overview")), nil, nil, nil, overviewList)
	split := container.NewHSplit(overview, detail)
	split.Offset = 0.38
	w.SetContent(container.NewBorder(inputArea, nil, nil, nil, split))
	w.SetOnClosed(func() {
		if scanCancel != nil {
			scanCancel()
		}
	})
	w.ShowAndRun()
}
