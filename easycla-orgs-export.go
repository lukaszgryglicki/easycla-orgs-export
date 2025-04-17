package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/csv"
	"encoding/pem"
	"fmt"
	"html"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"text/template"
	"time"

	// Snowflake support
	"github.com/antchfx/xmlquery"
	"github.com/joho/godotenv"
	"github.com/snowflakedb/gosnowflake"

	// AWS S3 support
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func fixBrokenAmpersands(xml string) string {
	var builder strings.Builder
	tokens := strings.Split(xml, "&")

	builder.WriteString(tokens[0])
	for _, token := range tokens[1:] {
		if strings.HasPrefix(token, "amp;") ||
			strings.HasPrefix(token, "lt;") ||
			strings.HasPrefix(token, "gt;") ||
			strings.HasPrefix(token, "apos;") ||
			strings.HasPrefix(token, "quot;") ||
			strings.HasPrefix(token, "#") {
			builder.WriteString("&" + token)
		} else {
			builder.WriteString("&amp;" + token)
		}
	}

	return builder.String()
}

func normalizeSnowflakeXML(doc string, clearNewLines bool) string {
	doc = strings.Trim(doc, `"`)
	doc = strings.ReplaceAll(doc, `\"`, `"`)
	if clearNewLines {
		doc = strings.ReplaceAll(doc, `\n`, "")
	}
	doc = html.UnescapeString(doc)
	doc = fixBrokenAmpersands(doc)
	return doc
}

func getTextFromXMLNode(n *xmlquery.Node) string {
	if n != nil {
		return strings.TrimSpace(n.InnerText())
	}
	return ""
}

func mergeAddr(addr1, addr2, sep string) string {
	if addr1 == "" {
		return addr2
	}
	if addr2 == "" {
		return addr1
	}
	return addr1 + sep + addr2
}

// address can be in address1, address2, address3 fields or corporation_address1, corporation_address2, corporation_address3 fields
// also support looking inside base64 encoded content '//RecipientAttachment/Attachment/Data - using the same fields
func parseXML(xmlStr string, parseEmbedded, dbg bool) (string, string, string, string, error) {
	doc, err := xmlquery.Parse(strings.NewReader(normalizeSnowflakeXML(xmlStr, true)))
	if err != nil {
		return "", "", "", "", err
	}

	corpName := xmlquery.FindOne(doc, "//field[@name='corporation_name']/value")
	cName := strings.TrimSpace(getTextFromXMLNode(corpName))

	addr1 := xmlquery.FindOne(doc, "//field[@name='address1']/value")
	addr2 := xmlquery.FindOne(doc, "//field[@name='address2']/value")
	addr3 := xmlquery.FindOne(doc, "//field[@name='address3']/value")

	caddr1 := xmlquery.FindOne(doc, "//field[@name='corporation_address1']/value")
	caddr2 := xmlquery.FindOne(doc, "//field[@name='corporation_address2']/value")
	caddr3 := xmlquery.FindOne(doc, "//field[@name='corporation_address3']/value")

	a1 := strings.TrimSpace(getTextFromXMLNode(addr1))
	a2 := strings.TrimSpace(getTextFromXMLNode(addr2))
	a3 := strings.TrimSpace(getTextFromXMLNode(addr3))

	ca1 := strings.TrimSpace(getTextFromXMLNode(caddr1))
	ca2 := strings.TrimSpace(getTextFromXMLNode(caddr2))
	ca3 := strings.TrimSpace(getTextFromXMLNode(caddr3))

	ad1 := mergeAddr(ca1, a1, ";;;")
	ad2 := mergeAddr(ca2, a2, ";;;")
	ad3 := mergeAddr(ca3, a3, ";;;")

	if parseEmbedded {
		dataNode := xmlquery.FindOne(doc, "//RecipientAttachment/Attachment/Data")
		dataB64 := strings.TrimSpace(getTextFromXMLNode(dataNode))
		if dataB64 != "" {
			data, err := base64.StdEncoding.DecodeString(dataB64)
			if err == nil {
				sData := string(data)
				eCompany, eAddr1, eAddr2, eAddr3, errEbd := parseXML(sData, false, dbg)
				if errEbd != nil {
					fmt.Printf("warning: error parsing embedded XML: '%s'\n", sData)
				} else {
					if dbg {
						fmt.Printf("found embedded data: '%s', '%s', '%s', '%s' --> '%s', '%s', '%s', '%s'\n", cName, ad1, ad2, ad3, eCompany, eAddr1, eAddr2, eAddr2)
					}
					if cName == "" && eCompany != "" {
						cName = eCompany
						if dbg {
							fmt.Printf("embedded company update '%s'", cName)
						}
					}
					if ad1 == "" && eAddr1 != "" {
						ad1 = eAddr1
						if dbg {
							fmt.Printf("embedded address1 update '%s'", ad1)
						}
					}
					if ad2 == "" && eAddr2 != "" {
						ad2 = eAddr2
						if dbg {
							fmt.Printf("embedded address2 update '%s'", ad2)
						}
					}
					if ad3 == "" && eAddr3 != "" {
						ad3 = eAddr3
						if dbg {
							fmt.Printf("embedded address3 update '%s'", ad3)
						}
					}
				}
			} else {
				fmt.Printf("warning: error parsing embedded XML data '%s'\n", dataB64)
			}
		}
	}

	return cName, ad1, ad2, ad3, nil
}

type TemplateData struct {
	Signatures string
	Companies  string
}

func loadQuery(path string, data TemplateData) (string, error) {
	tmplBytes, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	tmpl, err := template.New("sql").Delims("{{", "}}").Parse(string(tmplBytes))
	if err != nil {
		return "", err
	}

	var sb strings.Builder
	if err := tmpl.Execute(&sb, data); err != nil {
		return "", err
	}

	return sb.String(), nil
}

func downloadS3PDF(s3Client *s3.Client, bucket, key string) ([]byte, error) {
	resp, err := s3Client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to download from S3: %w", err)
	}
	defer resp.Body.Close()

	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, resp.Body); err != nil {
		return nil, fmt.Errorf("failed to read S3 object into buffer: %w", err)
	}

	return buf.Bytes(), nil
}

// NOTE: required 'pdftotext' tool installed, tried various PDF parsing libraries but after hours of testing this one works best
func extractTextLinesFromPDF(pdfBytes []byte) ([]string, error) {
	cmd := exec.Command("pdftotext", "-layout", "-", "-")
	cmd.Stdin = bytes.NewReader(pdfBytes)

	var out bytes.Buffer
	cmd.Stdout = &out
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("pdftotext failed: %v: %s", err, stderr.String())
	}

	var lines []string
	scanner := bufio.NewScanner(&out)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading output lines failed: %v", err)
	}

	return lines, nil
}

// If we hit text line matching this - assume this is address
var addressRegexp = regexp.MustCompile(`(?i)\d{1,5}\s+[\w\s.,'-]+(?:\n|,)?\s*\w{2,}\s+\d{4,6}`)

// If we hit text line matching this after any line that contains "address" (no case sensitive) - assume this is address
var addressHinted = regexp.MustCompile(`(?i)(?:address[:\s]*)?\s*(\d{1,5}\s+[\w\s.,'-]+(?:\n|,)?\s*\w{2,}\s+\d{4,6})`)

func extractAddressFromPDF(data []byte) (string, error) {
	lines, err := extractTextLinesFromPDF(data)
	if err != nil {
		return "", err
	}
	for i, line := range lines {
		if addressRegexp.MatchString(line) {
			return line, nil
		}
		if i > 0 && strings.Contains(strings.ToLower(lines[i-1]), "address") {
			if m := addressHinted.FindStringSubmatch(line); len(m) > 1 {
				return m[1], nil
			}
		}
	}
	return fmt.Sprintf("address %d", len(data)), nil
}

func main() {
	_ = godotenv.Load()

	var startDate string
	if len(os.Args) > 1 {
		startDate = os.Args[1]
	} else {
		startDate = "2000-01-01"
	}
	fmt.Printf("Start date: %s\n", startDate)
	dbg := os.Getenv("DEBUG") != ""
	stage := os.Getenv("STAGE")
	if stage == "" {
		stage = "dev"
	}
	fmt.Printf("Stage: %s\n", stage)

	schema := "fivetran_ingest.dynamodb_product"
	var signatures, companies string
	if stage == "prod" {
		signatures = fmt.Sprintf("%s_us_east_1.cla_%s_signatures", schema, stage)
		companies = fmt.Sprintf("%s_us_east_1.cla_%s_companies", schema, stage)
	} else {
		signatures = fmt.Sprintf("%s_us_east1_dev.cla_%s_signatures", schema, stage)
		companies = fmt.Sprintf("%s_us_east1_dev.cla_%s_companies", schema, stage)
	}
	if dbg {
		fmt.Printf("Tables: %s, %s\n", signatures, companies)
	}

	privateKeyPEM := strings.ReplaceAll(os.Getenv("SNOWFLAKE_PRIVATE_KEY"), `\n`, "\n")

	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		panic("failed to decode PEM block containing private key")
	}

	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		panic(fmt.Errorf("failed to parse PKCS#8 private key: %w", err))
	}

	rsaKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		panic("not an RSA private key")
	}

	scfg := &gosnowflake.Config{
		Account:       os.Getenv("SNOWFLAKE_ACCOUNT"),
		User:          os.Getenv("SNOWFLAKE_USERNAME"),
		Role:          os.Getenv("SNOWFLAKE_ROLE"),
		Database:      os.Getenv("SNOWFLAKE_DATABASE"),
		Warehouse:     os.Getenv("SNOWFLAKE_WAREHOUSE"),
		Authenticator: gosnowflake.AuthTypeJwt,
		PrivateKey:    rsaKey,
	}

	dsn, err := gosnowflake.DSN(scfg)
	if err != nil {
		panic(err)
	}

	db, err := sql.Open("snowflake", dsn)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Connect to AWS
	acfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		panic(err)
	}
	s3c := s3.NewFromConfig(acfg)

	// Get normal cases from saved XMLs
	query, err := loadQuery("query-automatic.sql", TemplateData{
		Signatures: signatures,
		Companies:  companies,
	})
	if err != nil {
		panic(fmt.Errorf("failed to load query-automatic.sql: %w", err))
	}
	if dbg {
		fmt.Printf("Query:\n---\n%s\n---\n", query)
	}

	rows, err := db.QueryContext(ctx, query, startDate)
	if err != nil {
		panic(err)
	}
	defer rows.Close()

	fn := fmt.Sprintf("export_%s_%s_from_%s.csv", stage, time.Now().Format("2006-01-02"), startDate)
	f, _ := os.Create(fn)
	w := csv.NewWriter(f)
	defer f.Close()

	_ = w.Write([]string{"Company", "Address"})

	companiesMap := make(map[string]string)
	dataMap := make(map[string]string)
	for rows.Next() {
		var company, signatureID string
		var doc string

		if err := rows.Scan(&company, &signatureID, &doc); err != nil {
			panic(err)
		}

		xmlCompany, addr1, addr2, addr3, xmlErr := parseXML(doc, true, dbg)
		if xmlErr != nil {
			fmt.Printf("warning: error %+v parsing XML: '%s'\n", xmlErr, doc)
		}
		// fmt.Printf("row: company%s, xmlCompany=%s, addr1=%s, addr2=%s, addr3=%s\n", company, xmlCompany, addr1, addr2, addr3)
		finalCompany := strings.TrimSpace(company)
		if finalCompany == "" {
			finalCompany = strings.TrimSpace(xmlCompany)
		}
		if finalCompany == "" {
			fmt.Printf("warning: cannot get company for row: company=%s, xmlCompany=%s, addr1=%s, addr2=%s, addr3=%s, xml: '%s'\n", company, xmlCompany, addr1, addr2, addr3, doc)
			continue
		}
		addr := mergeAddr(addr1, addr2, ", ")
		addr = mergeAddr(addr, addr3, ", ")
		if addr == "" {
			addr = signatureID
		}
		existingAddr, exists := companiesMap[finalCompany]
		if exists {
			if addr == existingAddr {
				if dbg {
					fmt.Printf("warning: company '%s' already exists and has the same address\n", finalCompany)
				}
				continue
			}
			if dbg {
				fmt.Printf("warning: company '%s' already exists and the new address is different '%s' than previous '%s', merging both\n", finalCompany, addr, existingAddr)
			}
			companiesMap[finalCompany] = mergeAddr(existingAddr, addr, ";;;")
			dataMap[finalCompany] = doc
			continue
		}
		companiesMap[finalCompany] = addr
		dataMap[finalCompany] = doc
	}

	// Get special (manual) cases from S3: s3://cla-signature-files-<stage>/contract-group/<projectid>/ccla/<companyid>/<signatureid>.pdf
	query, err = loadQuery("query-manual.sql", TemplateData{
		Signatures: signatures,
		Companies:  companies,
	})
	if err != nil {
		panic(fmt.Errorf("failed to load query-manual.sql: %w", err))
	}
	if dbg {
		fmt.Printf("Query:\n---\n%s\n---\n", query)
	}

	rows, err = db.QueryContext(ctx, query, startDate)
	if err != nil {
		panic(err)
	}
	defer rows.Close()

	s3Bucket := "cla-signature-files-" + stage
	for rows.Next() {
		var company string
		var signatureID, projectID, companyID string

		if err := rows.Scan(&company, &signatureID, &projectID, &companyID); err != nil {
			panic(err)
		}

		// fmt.Printf("row: company%s, signature_id=%s, project_id=%s, company_id=%s\n", company, signatureID, projectID, companyID)
		projectID = strings.ReplaceAll(projectID, `"`, "")
		companyID = strings.ReplaceAll(companyID, `"`, "")
		finalCompany := strings.TrimSpace(company)
		if finalCompany == "" {
			fmt.Printf("warning: cannot get company for row: company=%s, signature_id=%s, project_id=%s, company_id=%s\n", company, signatureID, projectID, companyID)
			continue
		}
		s3Path := fmt.Sprintf("contract-group/%s/ccla/%s/%s.pdf", projectID, companyID, signatureID)
		s3FullPath := fmt.Sprintf("s3://%s/%s", s3Bucket, s3Path)
		// s3://cla-signature-files-prod/contract-group/6c6a70a6-6a54-49eb-8550-6d47e3f902b9/ccla/f0f7536a-f220-451d-a15a-b6bc90e3cdc6/74936cb6-721e-4d01-bf89-347407a9f15c.pdf
		data, err := downloadS3PDF(s3c, s3Bucket, s3Path)
		if err != nil {
			fmt.Printf("warning: failed to download PDF from S3 path: '%s': %+v\n", s3FullPath, err)
			continue
		}
		if dbg {
			os.WriteFile(signatureID+".pdf", data, 0644)
		}
		addr, err := extractAddressFromPDF(data)
		if err != nil {
			if dbg {
				fmt.Printf("warning: cannot extract address from PDF '%s': %+v\n", s3FullPath, err)
			}
			addr = s3FullPath
		} else {
			addr += ";;;" + s3FullPath
		}
		existingAddr, exists := companiesMap[finalCompany]
		if exists {
			if addr == existingAddr {
				if dbg {
					fmt.Printf("warning: company '%s' already exists and has the same address\n", finalCompany)
				}
				continue
			}
			if dbg {
				fmt.Printf("warning: company '%s' already exists and the new address is different '%s' than previous '%s', merging both\n", finalCompany, addr, existingAddr)
			}
			companiesMap[finalCompany] = mergeAddr(existingAddr, addr, ";;;")
			dataMap[finalCompany] = s3FullPath
			continue
		}
		companiesMap[finalCompany] = addr
		dataMap[finalCompany] = s3FullPath
	}

	// Get remaining companies (without filtering for XML or S# PDF) - only names will be generated.
	// Put signature IDS as their address, so they can be checked manually later
	query, err = loadQuery("query-others.sql", TemplateData{
		Signatures: signatures,
		Companies:  companies,
	})
	if err != nil {
		panic(fmt.Errorf("failed to load query-others.sql: %w", err))
	}
	if dbg {
		fmt.Printf("Query:\n---\n%s\n---\n", query)
	}

	rows, err = db.QueryContext(ctx, query, startDate)
	if err != nil {
		panic(err)
	}
	defer rows.Close()

	otherCompaniesMap := make(map[string]string)
	for rows.Next() {
		var company string
		var signatureID string

		if err := rows.Scan(&company, &signatureID); err != nil {
			panic(err)
		}

		finalCompany := strings.TrimSpace(company)
		if finalCompany == "" {
			continue
		}
		addr := signatureID
		existingAddr, exists := otherCompaniesMap[finalCompany]
		if exists {
			if addr == existingAddr {
				if dbg {
					fmt.Printf("warning: company '%s' already exists and has the same address\n", finalCompany)
				}
				continue
			}
			if dbg {
				fmt.Printf("warning: company '%s' already exists and the new address is different '%s' than previous '%s', merging both\n", finalCompany, addr, existingAddr)
			}
			otherCompaniesMap[finalCompany] = mergeAddr(existingAddr, addr, ";;;")
			continue
		}
		otherCompaniesMap[finalCompany] = addr
	}

	for company, signatures := range otherCompaniesMap {
		_, exists := companiesMap[company]
		if !exists {
			companiesMap[company] = signatures
		}
	}

	// Generate the final results
	companiesList := make([]string, 0, len(companiesMap))
	for company := range companiesMap {
		companiesList = append(companiesList, company)
	}
	sort.Strings(companiesList)
	for _, company := range companiesList {
		addresses := strings.Split(companiesMap[company], ";;;")
		if len(addresses) == 1 {
			if addresses[0] == "" {
				if dbg {
					fmt.Printf("No address found for '%s' in XML: '%s'\n", company, dataMap[company])
				} else {
					fmt.Printf("No address found for '%s'\n", company)
				}
			}
			_ = w.Write([]string{company, addresses[0]})
			continue
		}
		mp := make(map[string]struct{})
		for _, addr := range addresses {
			mp[addr] = struct{}{}
		}
		lst := make([]string, 0, len(mp))
		for ad := range mp {
			lst = append(lst, ad)
		}
		sort.Strings(lst)
		addrs := strings.Join(lst, "; ")
		if addrs == "" {
			fmt.Printf("No address found for '%s'\n", company)
		}
		_ = w.Write([]string{company, addrs})
	}
	w.Flush()
	fmt.Printf("Saved %s\n", fn)
}
