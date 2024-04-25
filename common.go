package main

import (
	"io/ioutil"
	"net/http"
)

func callHTTP(url string) (result []byte, err error) {

	var resp *http.Response
	resp, err = http.Get(url)
	if err == nil {
		result, err = ioutil.ReadAll(resp.Body)

	}
	return
}
