// IPBlocker project
// Sept 2017
// 13-Nov-2024 Updated
// Motaz Abdel Azeem
// Code for Computer Software www.code.sd

package main

import (
	"flag"
	"fmt"

	"github.com/motaz/redisaccess"
)

func main() {
	redisaccess.InitRedisLocalhost()
	readExceptionVisits()
	path := flag.String("f", "", "log file full path")
	limit := flag.Int("l", 1000, "Max limit")
	hack := flag.String("h", "", "Hacking text file source")
	country := flag.Bool("c", false, "Get country name")
	asterisk := flag.Bool("a", false, "Asterisk log")

	flag.Parse()

	fmt.Println(*limit)
	limitNum := *limit
	hackFile := *hack
	asteriskLog := *asterisk
	getCountryName := *country
	if *path == "" {
		fmt.Println("IPBlocker, usage: ")
		fmt.Println("./IPBlocker -f <web server access log file path> -l <visit count>")
		fmt.Println("   -a: optional for Asterisk messages log file")
		fmt.Println("Example:\n./IPBlocker -f /var/log/nginx/access.log -l 12000")
		fmt.Println("Note: it requires root privilege to execute")

	} else {

		result, errMsg := shell("tail -n 100 " + *path)
		if errMsg != "" {
			fmt.Println("Error in shell: " + errMsg)
		} else if hackFile != "" {
			readHack(*path, result, limitNum, hackFile)
		} else {
			checkIP(*path, result, limitNum, "", getCountryName, asteriskLog)

		}
	}

}
