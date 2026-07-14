package main

import (
	"errors"
	"testing"
	"time"

	"lpe-checker/internal/batch"
	htmlreport "lpe-checker/internal/report"
)

func TestSelectBatchResultSubset(t *testing.T) {
	results := []batch.Result{
		{Index: 0, Target: "host-a:22", Status: batch.StatusSuccess},
		{Index: 1, Target: "host-b:22", Status: batch.StatusConnectionError, Err: errors.New("connection refused")},
		{Index: 2, Target: "host-c:2222", Status: batch.StatusSuccess},
		{Index: 3, Target: "host-d:22", Status: batch.StatusSuccess},
	}

	subset, ok := selectBatchResultSubset(results, []int{3, 1, 1, 99, -1})
	if !ok {
		t.Fatal("expected a non-empty subset")
	}
	if len(subset) != 2 || subset[0].Target != "host-b:22" || subset[1].Target != "host-d:22" {
		t.Fatalf("subset did not preserve original order or failure host: %+v", subset)
	}
	if subset[0].Status != batch.StatusConnectionError || subset[0].Err == nil {
		t.Fatalf("failed selected host was not preserved: %+v", subset[0])
	}
	exported := htmlreport.NewBatchReport(batchReportHosts(subset), time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC))
	if exported.Meta.HostCount != 2 || len(exported.Hosts) != 2 || exported.Hosts[0].Target != "host-b:22" || exported.Hosts[1].Target != "host-d:22" {
		t.Fatalf("selected subset produced the wrong BatchReport: %+v", exported)
	}
	if exported.Hosts[0].Status != htmlreport.BatchStatusFailed || exported.Hosts[0].Error != "主机不可达或连接被拒绝" {
		t.Fatalf("selected failed host was not exported through normal cleaning: %+v", exported.Hosts[0])
	}
}

func TestSelectBatchResultSubsetRejectsEmptySelection(t *testing.T) {
	results := []batch.Result{{Target: "host-a:22", Status: batch.StatusSuccess}}
	for _, selected := range [][]int{nil, {}, {-1, 4}} {
		if subset, ok := selectBatchResultSubset(results, selected); ok || subset != nil {
			t.Fatalf("empty/invalid selection unexpectedly produced a subset: %+v", subset)
		}
	}
}

func TestAllBatchResultsRemainAvailableWithoutFiltering(t *testing.T) {
	results := []batch.Result{
		{Target: "host-a:22", Status: batch.StatusSuccess},
		{Target: "host-b:22", Status: batch.StatusConnectionError},
	}
	all := append([]batch.Result{}, results...)
	if len(all) != len(results) || all[0].Target != results[0].Target || all[1].Target != results[1].Target {
		t.Fatalf("full export copy changed results: %+v", all)
	}
	selectedAll, ok := selectBatchResultSubset(results, []int{0, 1})
	if !ok || len(selectedAll) != len(results) || selectedAll[0].Target != results[0].Target || selectedAll[1].Target != results[1].Target {
		t.Fatalf("select-all did not produce the complete ordered subset: %+v", selectedAll)
	}
}
