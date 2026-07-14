package main

import (
	"bytes"
	"encoding/csv"
	"errors"
	"io"
	"strconv"
	"strings"

	"lpe-checker/internal/batch"
)

func parseCSVHosts(input io.Reader) ([]batch.Host, int, error) {
	data, err := io.ReadAll(input)
	if err != nil {
		return nil, 0, err
	}
	skipped := countBlankCSVLines(data)
	reader := csv.NewReader(bytes.NewReader(data))
	reader.FieldsPerRecord = -1
	reader.TrimLeadingSpace = true
	hosts := []batch.Host{}
	firstRecord := true
	for {
		record, readErr := reader.Read()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			skipped++
			continue
		}
		if firstRecord {
			firstRecord = false
			if isCSVHeader(record) {
				continue
			}
		}
		if len(record) < 4 {
			skipped++
			continue
		}
		host := strings.TrimSpace(record[0])
		portText := strings.TrimSpace(record[1])
		user := strings.TrimSpace(record[2])
		if host == "" || user == "" {
			skipped++
			continue
		}
		port := 22
		if portText != "" {
			port, err = strconv.Atoi(portText)
			if err != nil || port < 1 || port > 65535 {
				skipped++
				continue
			}
		}
		hosts = append(hosts, batch.Host{Host: host, Port: port, User: user, Password: record[3]})
	}
	return hosts, skipped, nil
}

func isCSVHeader(record []string) bool {
	if len(record) < 2 {
		return false
	}
	first := strings.ToLower(strings.TrimSpace(record[0]))
	second := strings.ToLower(strings.TrimSpace(record[1]))
	if first == "host" || first == "hostname" || first == "ip" || first == "主机" ||
		second == "port" || second == "端口" {
		return true
	}
	port := second
	if port == "" {
		return false
	}
	_, err := strconv.Atoi(port)
	return err != nil
}

func countBlankCSVLines(data []byte) int {
	lines := bytes.Split(data, []byte{'\n'})
	count := 0
	for index, line := range lines {
		if index == len(lines)-1 && len(line) == 0 {
			continue
		}
		if len(bytes.TrimSpace(line)) == 0 {
			count++
		}
	}
	return count
}
