package main

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"strconv"
	"strings"

	"bytes"
	"io/ioutil"
	"os"

	"github.com/motaz/codeutils"
	"github.com/motaz/redisaccess"
)

var exceptionVisits []string

type CountryInfo struct {
	Success     bool   `json:"success"`
	Countryname string `json:"countryname"`
	CountryCode string `json:"countrycode2"`
}

func readExceptionVisits() {

	dir := codeutils.GetCurrentAppDir()

	content, err := ioutil.ReadFile(dir + "/exvisits.ini")
	if err != nil {
		codeutils.WriteToLog("Error readExceptionVisits: "+err.Error(), "IPBlocker")
	} else {
		exceptionVisits = strings.Split(string(content), "\n")

	}
}

func existInVisits(line string) (exist bool) {

	exist = false
	for _, visit := range exceptionVisits {
		if strings.TrimSpace(visit) != "" {
			if strings.Contains(line, visit) {
				exist = true
				break
			}
		}
	}
	return
}

func retreiveCountryName(ip string) (countryName, CountryCode string) {

	iplocationURL := codeutils.GetConfigValue("config.ini", "iplocationurl")
	if iplocationURL == "" {
		iplocationURL = "http://host.code.sd/iplocation"
	}
	res, err := callHTTP(iplocationURL + "?ip=" + ip)
	if err == nil {
		var info CountryInfo
		err := json.Unmarshal(res, &info)
		if err == nil {
			countryName = info.Countryname
			CountryCode = info.CountryCode
		}
	}
	return
}

func addIP(ip string, ips *[]string) {

	found := false
	for _, anip := range *ips {
		if ip == anip {
			found = true
			break
		}
	}
	if !found {
		*ips = append(*ips, ip)
	}
}

func checkIP(path string, result string, limitNum int, text string, getCountryName, asteriskLog, blockAny bool) {

	collection := ""
	content, _ := os.ReadFile(path)
	alllines := strings.Split(string(content), "\n")
	exceptIPs, _ := readLines("visitips.txt")
	for _, line := range alllines {
		if strings.Contains(line, "-") {

			visitException := existInVisits(line)
			ip := line[0:strings.Index(line, "-")]
			ip = strings.Trim(ip, " ")
			if visitException {
				addIP(ip, &exceptIPs)
			}
		}
	}
	saveLines("visitips.txt", exceptIPs)

	list := strings.Split(result, "\n")

	for _, line := range list {
		var ip string = ""

		if asteriskLog {
			if strings.Contains(line, "Registration from") && strings.Contains(line, "failed for") {

				ip = line[strings.Index(line, "failed for"):]
				ip = ip[strings.Index(ip, "'")+1 : strings.Index(ip, ":")]

			} else if strings.Contains(line, "Call from") && strings.Contains(line, "rejected") &&

				strings.Contains(line, "(") {
				ip = line[strings.Index(line, "Call from"):]
				ip = ip[strings.Index(ip, "(")+1 : strings.Index(ip, ":")]

			}
		} else if strings.Contains(line, "-") && !strings.Contains(line, "\" 200 ") {

			ip = line[0:strings.Index(line, "-")]
			ip = strings.Trim(ip, " ")
		}
		if ip != "" && !strings.Contains(collection, ip+",") {

			collection = collection + ip + ", "
			process(path, ip, limitNum, text, getCountryName, asteriskLog, blockAny, exceptIPs)
		}

	}
}

func searchSlice(slice []string, text string) (found bool) {

	found = false
	for _, item := range slice {
		if item == text {
			found = true
			break
		}
	}
	return
}

func checkExceptionCountry(countryCode string) (Block bool) {

	Block = true
	lines, err := readLines("countries.ini")

	if err == nil {
		if len(lines) > 0 {
			line := lines[0]
			codes := strings.Split(line, ",")
			for _, cc := range codes {
				if cc == countryCode {
					Block = false
					break
				}
			}
		}
	} else {
		fmt.Println(err.Error())
	}
	return
}

func process(path string, ip string, limitNum int, text string, getCountryName, asterisk, blockAny bool, exceptIPs []string) {

	count := getCount(path, ip, text, asterisk)
	data := " " + ip + " count (" + strconv.Itoa(count) + ") "
	var countryName, countryCode string
	if getCountryName {
		countryName, countryCode = retreiveCountryName(ip)

	}

	found := searchSlice(exceptIPs, ip)
	if (strings.HasPrefix(ip, "127.0")) || (ip == "::1") || (found) {
		data = data + "Skipping"
	} else {
		var blockAnyRequest bool = false
		if blockAny {
			blockAnyRequest = checkExceptionCountry(countryCode)
		}
		if count >= limitNum || blockAnyRequest {
			if blockAnyRequest {
				data = data + " Block any request from " + ip + " "
			} else {
				data = data + "Exceeding limit "
			}
			exception := isExceptionIP(ip)
			if exception {
				data = data + " Exception"

			} else {
				result := block(ip, count)
				data += result
			}
		}
	}
	line := data + " " + text + " " + countryName + " (" + countryCode + ")"

	ourPrint(line)

}

func block(ip string, count int) (result string) {

	if checkBlocked(ip, count) {
		result = "Already blocked"
	} else {
		_, er := shell("/sbin/iptables -I INPUT -s " + ip + " -j DROP")
		if er != "" {
			result = "Error while blocking: " + er
		} else {
			result = "------ Blocked -----"
			writeBlockedIP(ip, count)
		}
	}
	return
}

func getCount(path string, ip string, text string, asterisk bool) int {

	command := "cat " + path + " | grep '" + ip + "' "
	if text != "" {
		command += " | grep '" + text + "' "
	}
	if asterisk {
		command += " | grep 'failed\\|rejected' "
	} else {

		command += " | grep '\" 400 \\|\" 401 \\|\" 404 ' "
	}
	command += " | wc -l"
	result, er := shell(command)

	count := 0
	result = strings.Trim(result, "\r\n")
	if er != "" {
		ourPrint("Error in getCount: " + command + " " + er)
	} else {
		count, _ = strconv.Atoi(result)
	}
	return count
}

func shell(command string) (result string, err string) {

	var out bytes.Buffer
	var errBuf bytes.Buffer

	cmd := exec.Command("/bin/bash", "-c", command)
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	cmd.Run()
	result = out.String()
	err = errBuf.String()
	return
}

func ourPrint(atext string) {

	fmt.Println(atext)
	codeutils.WriteToLog(atext, "blocker")
}

func isExceptionIP(ip string) bool {

	dir := codeutils.GetCurrentAppDir()

	content, err := ioutil.ReadFile(dir + "/exceptions.ini")
	found := false
	if err != nil {
		fmt.Println("Error in isExpectionIP: " + err.Error())
	} else {
		lines := strings.Split(string(content), "\n")
		for _, exceptip := range lines {
			if exceptip != "" {
				if strings.HasPrefix(ip, exceptip) {
					fmt.Println("Skipped: " + ip + ", " + exceptip)
					found = true
					break
				}
			}
		}
	}
	return found
}

func readHack(path string, result string, limitNum int, filename string) bool {

	if !strings.Contains(filename, "/") {
		dir := codeutils.GetCurrentAppDir()

		filename = dir + "/" + filename
	}
	content, err := ioutil.ReadFile(filename)

	found := false
	if err != nil {
		ourPrint("Error in readHack: " + err.Error())
	} else {
		hack := strings.Split(string(content), "\n")
		for _, text := range hack {
			if text != "" {
				checkIP(path, result, 1, text, true, false, false)
			}
		}
	}

	return found
}

func writeBlockedIP(ip string, count int) {

	redisaccess.SetValue("blocked-"+ip, count, time.Hour*24)

}

func saveLines(filePath string, lines []string) error {

	f, err := os.Create(codeutils.GetCurrentAppDir() + "/" + filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, value := range lines {
		if strings.TrimSpace(value) != "" {
			fmt.Fprintln(f, value)
		}
	}
	return nil
}

func readLines(filename string) (lines []string, err error) {

	content, err := ioutil.ReadFile(codeutils.GetCurrentAppDir() + "/" + filename)
	if err == nil {

		lines = strings.Split(string(content), "\n")
	}

	return
}

func checkBlocked(ip string, count int) (found bool) {

	value, found, err := redisaccess.GetValue("blocked-" + ip)
	if err != nil {
		found = false
	}
	if found {
		if value != "" {
			lastCount, err := strconv.Atoi(value)
			if err == nil && lastCount < count {
				fmt.Println("Previous count: ", lastCount, "  is less than current: ", count)
				found = false
			}
		}
	}
	return
}
