package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/opensearch-project/opensearch-go"
	"github.com/opensearch-project/opensearch-go/opensearchapi"
	log "github.com/sirupsen/logrus"
	"github.com/xuri/excelize/v2"
)

const (
	endpoint = "https://os.gcaaide.org/"
)

func main() {
	ctx := context.Background()

	client, err := opensearch.NewClient(opensearch.Config{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		},
		Addresses: []string{endpoint},
		Username:  os.Getenv("OPENSEARCH_USR"),
		Password:  os.Getenv("OPENSEARCH_PWD"),
	})
	if err != nil {
		log.Fatalf("failed to search document: %v", err)
	}

	// query for top 25 counts of attacks by ASN
	asnContent := strings.NewReader(`{"aggs":{"2":{"terms":{"field":"geoip.as_org.keyword","order":{"_count":"desc"},"size":5000}}},"size":0,"stored_fields":["*"],"script_fields":{},"docvalue_fields":[{"field":"@timestamp","format":"date_time"},{"field":"endTime","format":"date_time"},{"field":"startTime","format":"date_time"}],"_source":{"excludes":[]},"query":{"bool":{"must":[{"query_string":{"query":"_exists_:loggedin OR _exists_:credentials OR _exists_:commands OR _exists_:unknownCommands OR _exists_:urls OR _exists_:hashes","analyze_wildcard":true,"time_zone":"Europe/London"}},{"range":{"@timestamp":{"gte":"now-12h","lte":"now","format":"strict_date_optional_time"}}}],"filter":[],"should":[],"must_not":[]}}}`)
	// query for top 25 counts of attacks by Country
	countryContent := strings.NewReader(`{"aggs":{"2":{"terms":{"field":"geoip.country_name.keyword","order":{"_count":"desc"},"size":2000}}},"size":0,"stored_fields":["*"],"script_fields":{},"docvalue_fields":[{"field":"@timestamp","format":"date_time"},{"field":"endTime","format":"date_time"},{"field":"startTime","format":"date_time"}],"_source":{"excludes":[]},"query":{"bool":{"must":[{"query_string":{"query":"_exists_:loggedin OR _exists_:credentials OR _exists_:commands OR _exists_:unknownCommands OR _exists_:urls OR _exists_:hashes","analyze_wildcard":true,"time_zone":"Europe/London"}}],"filter":[{"range":{"@timestamp":{"gte":"now-12h","lte":"now","format":"strict_date_optional_time"}}}],"should":[],"must_not":[]}}}`)
	// query for unique peer ASN count
	uniqueASNsContent := strings.NewReader(`{"aggs":{"1":{"cardinality":{"field":"geoip.as_org.keyword"}}},"size":0,"stored_fields":["*"],"script_fields":{},"docvalue_fields":[{"field":"@timestamp","format":"date_time"},{"field":"endTime","format":"date_time"},{"field":"startTime","format":"date_time"}],"_source":{"excludes":[]},"query":{"bool":{"must":[],"filter":[{"match_all":{}},{"range":{"@timestamp":{"gte":"now-12h","lte":"now","format":"strict_date_optional_time"}}}],"should":[],"must_not":[]}}}`)
	// query for unique peer country count
	uniqueCountriesContent := strings.NewReader(`{"aggs":{"1":{"cardinality":{"field":"geoip.country_name.keyword"}}},"size":0,"stored_fields":["*"],"script_fields":{},"docvalue_fields":[{"field":"@timestamp","format":"date_time"},{"field":"endTime","format":"date_time"},{"field":"startTime","format":"date_time"}],"_source":{"excludes":[]},"query":{"bool":{"must":[],"filter":[{"match_all":{}},{"range":{"@timestamp":{"gte":"now-12h","lte":"now","format":"strict_date_optional_time"}}}],"should":[],"must_not":[]}}}`)

	// Make the structs to contain the desired data from the search
	type queryResponse struct {
		Took         int  `json:"took"`
		TimedOut     bool `json:"timed_out"`
		Aggregations struct {
			Filter struct {
				Buckets []struct {
					Key      string `json:"key"`
					DocCount int    `json:"doc_count"`
				} `json:"buckets"`
			} `json:"2"`
		} `json:"aggregations"`
	}

	type CountResponse struct {
		Took         int  `json:"took"`
		TimedOut     bool `json:"timed_out"`
		Aggregations struct {
			Field1 struct {
				Value int `json:"value"`
			} `json:"1"`
		} `json:"aggregations"`
	}

	// search the database using the queries and unmarshal JSON results
	asnBody, err := searchDatabase(ctx, client, asnContent)
	if err != nil {
		log.Fatalf("failed to search database: %v", err)
	}

	var asnResult queryResponse
	if err = json.Unmarshal(asnBody, &asnResult); err != nil {
		log.Fatalf("cannot unmarshal JSON: %v", err)
	}

	countryBody, err := searchDatabase(ctx, client, countryContent)
	if err != nil {
		log.Fatalf("failed to search database: %v", err)
	}

	var countryResult queryResponse
	if err = json.Unmarshal(countryBody, &countryResult); err != nil {
		log.Fatalf("cannot unmarshal JSON: %v", err)
	}

	uniqueASNsBody, err := searchDatabase(ctx, client, uniqueASNsContent)
	if err != nil {
		log.Fatalf("failed to search database: %v", err)
	}

	var asnCountResult CountResponse
	if err = json.Unmarshal(uniqueASNsBody, &asnCountResult); err != nil {
		log.Fatalf("cannot unmarshal JSON: %v", err)
	}

	uniqueCountriesBody, err := searchDatabase(ctx, client, uniqueCountriesContent)
	if err != nil {
		log.Fatalf("failed to search database: %v", err)
	}

	var countryCountResult CountResponse
	if err = json.Unmarshal(uniqueCountriesBody, &countryCountResult); err != nil {
		log.Fatalf("cannot unmarshal JSON: %v", err)
	}

	// extract and format relevant data to be added to the report
	var asNames []string
	var asCounts []int
	for _, bucket := range asnResult.Aggregations.Filter.Buckets {
		asNames = append(asNames, bucket.Key)
		asCounts = append(asCounts, bucket.DocCount)
	}

	var countryNames []string
	var countryCounts []int
	for _, bucket := range countryResult.Aggregations.Filter.Buckets {
		countryNames = append(countryNames, bucket.Key)
		countryCounts = append(countryCounts, bucket.DocCount)
	}

	uniqueASNsCount := asnCountResult.Aggregations.Field1.Value
	uniqueCountriesCount := countryCountResult.Aggregations.Field1.Value

	// count elements in arrays & use this to calculate table ranges
	asnLength := len(asCounts)
	countryLength := len(countryCounts)
	asnTableRange := fmt.Sprintf("A3:B%d", asnLength+3)
	countryTableRange := fmt.Sprintf("A3:B%d", countryLength+3)

	// create report and populate with search results
	fmt.Println("")
	filename, err := createReport(os.Getenv("OPENSEARCH_USR"), asnTableRange, countryTableRange)
	if err != nil {
		log.Fatalf("failed to create report: %v", err)
	}

	if err = populateColumn(asNames, "A", 4, "By ASN", filename); err != nil {
		log.Printf("failed to populate ASN column: %v", err)
	}

	if err = populateColumn(asCounts, "B", 4, "By ASN", filename); err != nil {
		log.Printf("failed to populate ASN count column: %v", err)
	}

	if err = populateColumn(countryNames, "A", 4, "By Country of Origin", filename); err != nil {
		log.Printf("failed to populate country name column: %v", err)
	}

	if err = populateColumn(countryCounts, "B", 4, "By Country of Origin", filename); err != nil {
		log.Printf("failed to populate country count column: %v", err)
	}

	// format strings to show data on unique ASN and country counts
	uniqueASNsString := fmt.Sprintf("In the past 12 hours, AIDE observed %d unique peer ASNs.", uniqueASNsCount)
	uniqueCountriesString := fmt.Sprintf("In the past 12 hours, AIDE observed %d unique peer countries.", uniqueCountriesCount)
	asnAttacksString := fmt.Sprintf("Of those, %d were present in attacker data.", asnLength)
	countryAttacksString := fmt.Sprintf("Of those, %d were the country of origin for attacks.", countryLength)

	// Edit report to include data on unique ASN and country counts using the formatted strings
	f, err := excelize.OpenFile(filename)
	if err != nil {
		log.Fatalf("failed to read excel file: %v", err)
	}

	_ = f.SetCellValue("By ASN", "D3", uniqueASNsString)
	_ = f.SetCellValue("By ASN", "D4", asnAttacksString)
	_ = f.SetCellValue("By Country of Origin", "D3", uniqueCountriesString)
	_ = f.SetCellValue("By Country of Origin", "D4", countryAttacksString)

	if err = f.Save(); err != nil {
		log.Fatalf("failed to save excel file: %v", err)
	}

	fmt.Println("File saved.")
}

func searchDatabase(context context.Context, client *opensearch.Client, content io.Reader) ([]byte, error) {
	search := opensearchapi.SearchRequest{
		Index: []string{"gca-honeyfarm-1-*", "gca-honeyfarm-2-*"},
		Body:  content,
	}

	fmt.Println("Querying database...")
	searchResponse, err := search.Do(context, client)
	if err != nil {
		log.Fatalf("failed to search document: %v", err)
	}
	defer searchResponse.Body.Close()

	// read the response as []byte
	body, err := io.ReadAll(searchResponse.Body)
	if err != nil {
		log.Fatalf("failed to read response body: %v", err)
	} else {
		fmt.Println("Response received.")
	}

	return body, nil
}
