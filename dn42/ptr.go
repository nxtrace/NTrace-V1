package dn42

import (
	"encoding/csv"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/spf13/viper"
)

type PtrRow struct {
	IATACode string
	LtdCode  string
	Region   string
	City     string
}

func matchesPattern(prefix string, s string) bool {
	pattern := fmt.Sprintf(`^(.*[-.\d]|^)%s[-.\d].*$`, prefix)

	r, err := regexp.Compile(pattern)
	if err != nil {
		fmt.Println("Invalid regular expression:", err)
		return false
	}

	return r.MatchString(s)
}

var getPtr = sync.OnceValues(func() ([][]string, error) {
	path := viper.Get("ptrPath").(string)
	var r *csv.Reader
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		client := &http.Client{
			// 10 秒超时
			Timeout: time.Duration(10) * time.Second,
		}
		req, _ := http.NewRequest("GET", path, nil)
		content, err := client.Do(req)
		if err != nil {
			log.Println("DN42数据请求超时，请更换其他数据源或使用本地数据")
			return nil, err
		}
		defer content.Body.Close()
		r = csv.NewReader(content.Body)
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = csv.NewReader(f)
	}
	return r.ReadAll()
})

func FindPtrRecord(ptr string) (PtrRow, error) {
	rows, err := getPtr()
	if err != nil {
		return PtrRow{}, err
	}

	// 转小写
	ptr = strings.ToLower(ptr)
	// 先查城市名
	for _, row := range rows {
		city := row[3]
		if city == "" {
			continue
		}
		city = strings.ReplaceAll(city, " ", "")
		city = strings.ToLower(city)

		if matchesPattern(city, ptr) {
			return PtrRow{
				LtdCode: row[1],
				Region:  row[2],
				City:    row[3],
			}, nil
		}
	}
	// 查 IATA Code
	for _, row := range rows {
		iata := row[0]
		if iata == "" {
			continue
		}
		iata = strings.ToLower(iata)
		if matchesPattern(iata, ptr) {
			return PtrRow{
				IATACode: iata,
				LtdCode:  row[1],
				Region:   row[2],
				City:     row[3],
			}, nil
		}
	}

	return PtrRow{}, errors.New("ptr not found")
}
