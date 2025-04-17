package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/csv"
	"encoding/pem"
	"fmt"
	"html"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/antchfx/xmlquery"
	"github.com/joho/godotenv"
	"github.com/snowflakedb/gosnowflake"
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

func parseXML(xmlStr string) (string, string, string, error) {
	doc, err := xmlquery.Parse(strings.NewReader(normalizeSnowflakeXML(xmlStr, true)))
	// if strings.Contains(xmlStr, "&") {
	// 	fmt.Printf("NORMALIZED:\n%s\nINTO:\n%s\n", xmlStr, normalizeSnowflakeXML(xmlStr, true))
	// }
	if err != nil {
		return "", "", "", err
	}

	corpName := xmlquery.FindOne(doc, "//field[@name='corporation_name']/value")
	addr1 := xmlquery.FindOne(doc, "//field[@name='corporation_address1']/value")
	addr2 := xmlquery.FindOne(doc, "//field[@name='corporation_address2']/value")

	return strings.TrimSpace(getTextFromXMLNode(corpName)), strings.TrimSpace(getTextFromXMLNode(addr1)), strings.TrimSpace(getTextFromXMLNode(addr2)), nil
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

func main() {
	_ = godotenv.Load()

	var startDate string
	if len(os.Args) > 1 {
		startDate = os.Args[1]
	} else {
		startDate = "2000-01-01"
	}
	fmt.Printf("Start date: %s\n", startDate)
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
	fmt.Printf("Tables: %s, %s\n", signatures, companies)

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

	cfg := &gosnowflake.Config{
		Account:       os.Getenv("SNOWFLAKE_ACCOUNT"),
		User:          os.Getenv("SNOWFLAKE_USERNAME"),
		Role:          os.Getenv("SNOWFLAKE_ROLE"),
		Database:      os.Getenv("SNOWFLAKE_DATABASE"),
		Warehouse:     os.Getenv("SNOWFLAKE_WAREHOUSE"),
		Authenticator: gosnowflake.AuthTypeJwt,
		PrivateKey:    rsaKey,
	}

	dsn, err := gosnowflake.DSN(cfg)
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

	query, err := loadQuery("query.sql", TemplateData{
		Signatures: signatures,
		Companies:  companies,
	})
	if err != nil {
		panic(fmt.Errorf("failed to load query.sql: %w", err))
	}
	fmt.Printf("Query:\n---\n%s\n---\n", query)

	rows, err := db.QueryContext(ctx, query, startDate)
	if err != nil {
		panic(err)
	}
	defer rows.Close()

	// fn := fmt.Sprintf("export_%s_from_%s.csv", time.Now().Format("20060102150405"), startDate)
	fn := fmt.Sprintf("export_%s_from_%s.csv", time.Now().Format("2006-01-02"), startDate)
	f, _ := os.Create(fn)
	w := csv.NewWriter(f)
	defer f.Close()

	_ = w.Write([]string{"Company", "Address"})

	for rows.Next() {
		var company string
		var doc string

		if err := rows.Scan(&company, &doc); err != nil {
			panic(err)
		}

		xmlCompany, addr1, addr2, xmlErr := parseXML(doc)
		if xmlErr != nil {
			fmt.Printf("warning: error %+v parsing XML: '%s'\n", xmlErr, doc)
		}
		// fmt.Printf("row: company%s, xmlCompany=%s, addr1=%s, addr2=%s\n", company, xmlCompany, addr1, addr2)
		finalCompany := strings.TrimSpace(company)
		if finalCompany == "" {
			finalCompany = strings.TrimSpace(xmlCompany)
		}
		addr := addr1
		if addr == "" {
			addr = addr2
		} else {
			if addr2 != "" {
				addr += ", " + addr2
			}
		}

		_ = w.Write([]string{finalCompany, addr})
	}
	w.Flush()
	fmt.Printf("Saved %s\n", fn)
}
