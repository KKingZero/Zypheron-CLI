package browser

import (
	"fmt"
	"strings"
)

// DorkCategory represents a category of OSINT dork queries
type DorkCategory struct {
	Name        string   // Category identifier
	Description string   // Human-readable description
	Queries     []string // List of dork query templates
}

// DorkCategories contains all available OSINT dork categories
var DorkCategories = map[string]DorkCategory{
	"sensitive_files": {
		Name:        "sensitive_files",
		Description: "Exposed configuration files, credentials, and sensitive data",
		Queries: []string{
			`filetype:sql "password"`,
			`filetype:sql "INSERT INTO" "users"`,
			`filetype:env DB_PASSWORD`,
			`filetype:env "API_KEY"`,
			`filetype:env "SECRET"`,
			`filetype:log "password"`,
			`filetype:log "authentication"`,
			`filetype:cfg password`,
			`filetype:ini password`,
			`filetype:conf password`,
			`filetype:yaml password`,
			`filetype:yml api_key`,
			`filetype:json "password"`,
			`filetype:xml "password"`,
			`filetype:properties password`,
			`filetype:htpasswd`,
			`filetype:pgpass`,
			`filetype:netrc`,
		},
	},
	"login_pages": {
		Name:        "login_pages",
		Description: "Login portals and authentication endpoints",
		Queries: []string{
			`inurl:login`,
			`inurl:signin`,
			`inurl:auth`,
			`inurl:admin`,
			`inurl:administrator`,
			`inurl:wp-admin`,
			`inurl:wp-login`,
			`inurl:user/login`,
			`inurl:account/login`,
			`intitle:"login" inurl:admin`,
			`intitle:"sign in"`,
			`intitle:"admin login"`,
			`intitle:"control panel"`,
			`inurl:phpmyadmin`,
			`inurl:cpanel`,
			`inurl:webmail`,
		},
	},
	"exposed_documents": {
		Name:        "exposed_documents",
		Description: "Sensitive documents with confidential markers",
		Queries: []string{
			`filetype:pdf "confidential"`,
			`filetype:pdf "internal use only"`,
			`filetype:pdf "not for distribution"`,
			`filetype:pdf "proprietary"`,
			`filetype:doc "confidential"`,
			`filetype:docx "internal only"`,
			`filetype:xls "password"`,
			`filetype:xlsx "employee"`,
			`filetype:ppt "confidential"`,
			`filetype:pptx "internal"`,
			`filetype:odt "confidential"`,
			`filetype:rtf "confidential"`,
		},
	},
	"cloud_storage": {
		Name:        "cloud_storage",
		Description: "Exposed cloud storage buckets and containers",
		Queries: []string{
			`site:s3.amazonaws.com`,
			`site:s3-*.amazonaws.com`,
			`inurl:".s3.amazonaws.com"`,
			`site:blob.core.windows.net`,
			`site:storage.googleapis.com`,
			`site:storage.cloud.google.com`,
			`site:digitaloceanspaces.com`,
			`site:firebasestorage.googleapis.com`,
			`inurl:"storage.googleapis.com"`,
			`inurl:".blob.core.windows.net"`,
			`filetype:json inurl:storage`,
		},
	},
	"cameras_iot": {
		Name:        "cameras_iot",
		Description: "Exposed webcams, IP cameras, and IoT devices",
		Queries: []string{
			`intitle:"webcam" inurl:view`,
			`inurl:"/view/index.shtml"`,
			`intitle:"Network Camera"`,
			`intitle:"IP Camera"`,
			`inurl:"ViewerFrame?Mode="`,
			`inurl:"/live.htm" intext:"M-JPEG"`,
			`intitle:"Live View / - AXIS"`,
			`inurl:"lvappl.htm"`,
			`intitle:"MOBOTIX"`,
			`inurl:"/snapshot.cgi"`,
			`inurl:"/videostream.cgi"`,
			`intitle:"RouterOS" inurl:"webfig"`,
			`intitle:"NETGEAR"`,
		},
	},
	"errors_debug": {
		Name:        "errors_debug",
		Description: "Error messages, debug output, and stack traces",
		Queries: []string{
			`"PHP Parse error"`,
			`"PHP Warning"`,
			`"PHP Fatal error"`,
			`"Warning: mysql_"`,
			`"Warning: mysqli_"`,
			`"Warning: pg_"`,
			`intitle:"500 Internal Server Error"`,
			`"Stack Trace" filetype:txt`,
			`"Fatal error: Uncaught exception"`,
			`"Error in query"`,
			`"SQL syntax" "mysql"`,
			`"ORA-"`,
			`"PostgreSQL query failed"`,
			`intext:"Debug" intext:"error"`,
			`"Traceback (most recent call last)"`,
			`"Exception in thread"`,
		},
	},
	"backups": {
		Name:        "backups",
		Description: "Backup files and archives",
		Queries: []string{
			`filetype:bak`,
			`filetype:old`,
			`filetype:backup`,
			`filetype:bkp`,
			`filetype:bkf`,
			`inurl:backup`,
			`inurl:".bak"`,
			`inurl:".old"`,
			`inurl:"backup.zip"`,
			`inurl:"backup.sql"`,
			`inurl:"dump.sql"`,
			`filetype:tar.gz`,
			`filetype:sql.gz`,
			`intitle:"index of" "backup"`,
			`intitle:"index of" ".sql"`,
		},
	},
	"git_exposed": {
		Name:        "git_exposed",
		Description: "Exposed Git repositories and version control data",
		Queries: []string{
			`inurl:".git"`,
			`intitle:"Index of /.git"`,
			`inurl:".git/config"`,
			`inurl:".git/HEAD"`,
			`inurl:".git/objects"`,
			`inurl:".gitignore"`,
			`inurl:".svn"`,
			`intitle:"Index of /.svn"`,
			`inurl:".hg"`,
			`intitle:"Index of /.hg"`,
			`inurl:"COMMIT_EDITMSG"`,
		},
	},
	"api_keys": {
		Name:        "api_keys",
		Description: "Exposed API keys and tokens",
		Queries: []string{
			`"api_key" filetype:json`,
			`"apikey" filetype:yaml`,
			`"access_token" filetype:json`,
			`"client_secret" filetype:json`,
			`"aws_access_key_id"`,
			`"aws_secret_access_key"`,
			`"AKIA" filetype:txt`,
			`"sk_live_" filetype:txt`,
			`"ghp_" filetype:txt`,
			`"glpat-" filetype:txt`,
			`"xox" filetype:txt`,
			`"Authorization: Bearer"`,
		},
	},
	"directory_listings": {
		Name:        "directory_listings",
		Description: "Open directory listings",
		Queries: []string{
			`intitle:"Index of /"`,
			`intitle:"Index of /admin"`,
			`intitle:"Index of /backup"`,
			`intitle:"Index of /config"`,
			`intitle:"Index of /private"`,
			`intitle:"Index of /uploads"`,
			`intitle:"Index of /data"`,
			`intitle:"Index of /logs"`,
			`intitle:"Parent Directory" -xxx`,
			`"Directory listing for"`,
		},
	},
	"wordpress": {
		Name:        "wordpress",
		Description: "WordPress-specific vulnerabilities and exposures",
		Queries: []string{
			`inurl:wp-content/uploads`,
			`inurl:wp-content/plugins`,
			`inurl:wp-includes`,
			`inurl:wp-config.php`,
			`inurl:xmlrpc.php`,
			`"Index of /wp-content/uploads"`,
			`filetype:sql inurl:wp-content`,
			`inurl:wp-json/wp/v2/users`,
			`inurl:readme.html intext:"wordpress"`,
		},
	},
	"database": {
		Name:        "database",
		Description: "Database files and dumps",
		Queries: []string{
			`filetype:sql`,
			`filetype:mdb`,
			`filetype:accdb`,
			`filetype:sqlite`,
			`filetype:db`,
			`filetype:dbf`,
			`inurl:db.sql`,
			`inurl:dump.sql`,
			`inurl:database.sql`,
			`inurl:backup.sql`,
			`"phpMyAdmin" "Create new database"`,
		},
	},
}

// GetCategory returns a dork category by name
func GetCategory(name string) (DorkCategory, bool) {
	cat, ok := DorkCategories[strings.ToLower(name)]
	return cat, ok
}

// ListCategories returns all available category names with descriptions
func ListCategories() []DorkCategory {
	categories := make([]DorkCategory, 0, len(DorkCategories))
	for _, cat := range DorkCategories {
		categories = append(categories, cat)
	}
	return categories
}

// GetCategoryNames returns just the category names
func GetCategoryNames() []string {
	names := make([]string, 0, len(DorkCategories))
	for name := range DorkCategories {
		names = append(names, name)
	}
	return names
}

// GenerateCategoryDorks generates dork queries for a category with a target site
func GenerateCategoryDorks(categoryName, target string) ([]string, error) {
	cat, ok := GetCategory(categoryName)
	if !ok {
		return nil, fmt.Errorf("unknown category: %s", categoryName)
	}

	var dorks []string
	siteOp := ""
	if target != "" {
		siteOp = fmt.Sprintf("site:%s ", target)
	}

	for _, query := range cat.Queries {
		// Prepend site operator if target is specified
		dork := siteOp + query
		dorks = append(dorks, dork)
	}

	return dorks, nil
}

// GetAllCategoryDorks returns all dork queries across all categories
func GetAllCategoryDorks() []string {
	var allDorks []string
	for _, cat := range DorkCategories {
		allDorks = append(allDorks, cat.Queries...)
	}
	return allDorks
}

// SearchCategoriesByKeyword finds categories that match a keyword
func SearchCategoriesByKeyword(keyword string) []DorkCategory {
	keyword = strings.ToLower(keyword)
	var matches []DorkCategory

	for _, cat := range DorkCategories {
		if strings.Contains(strings.ToLower(cat.Name), keyword) ||
			strings.Contains(strings.ToLower(cat.Description), keyword) {
			matches = append(matches, cat)
		}
	}

	return matches
}
