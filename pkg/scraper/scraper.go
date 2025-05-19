package scraper

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-shiori/go-readability"
	"github.com/gocolly/colly/v2"
)

// ScrapeResult represents the result of a scraping operation
type ScrapeResult struct {
	Title   string
	Content string
	URL     string
	Error   error
}

// ScrapeReadable scrapes a URL for main readable content using go-readability
func ScrapeReadable(rawurl string) (*ScrapeResult, error) {
	resp, err := http.Get(rawurl)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	parsedURL, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}
	article, err := readability.FromReader(strings.NewReader(string(body)), parsedURL)
	if err != nil {
		return nil, err
	}
	return &ScrapeResult{
		Title:   article.Title,
		Content: article.TextContent,
		URL:     rawurl,
	}, nil
}

// CrawlWebsite crawls a website starting from a URL up to a certain depth
func CrawlWebsite(startURL string, depth int, keywords []string) ([]*ScrapeResult, error) {
	var results []*ScrapeResult
	c := colly.NewCollector(
		colly.AllowedDomains(getDomain(startURL)),
		colly.MaxDepth(depth),
	)

	c.OnHTML("a[href]", func(e *colly.HTMLElement) {
		link := e.Request.AbsoluteURL(e.Attr("href"))
		if link != "" {
			c.Visit(link)
		}
	})

	c.OnResponse(func(r *colly.Response) {
		if r.StatusCode == 200 {
			parsedURL, err := url.Parse(r.Request.URL.String())
			if err != nil {
				return
			}
			article, err := readability.FromReader(strings.NewReader(string(r.Body)), parsedURL)
			if err != nil {
				return
			}
			if article.Title != "" && article.TextContent != "" {
				// Filter by keywords if provided
				if len(keywords) > 0 {
					content := strings.ToLower(article.Title + " " + article.TextContent)
					hasKeyword := false
					for _, keyword := range keywords {
						if strings.Contains(content, strings.ToLower(keyword)) {
							hasKeyword = true
							break
						}
					}
					if !hasKeyword {
						return
					}
				}
				results = append(results, &ScrapeResult{
					Title:   article.Title,
					Content: article.TextContent,
					URL:     r.Request.URL.String(),
				})
			}
		}
	})

	err := c.Visit(startURL)
	return results, err
}

// FetchWikipediaArticle fetches a Wikipedia article by title
func FetchWikipediaArticle(title string) (*ScrapeResult, error) {
	apiURL := "https://en.wikipedia.org/w/api.php?action=query&prop=extracts&explaintext&format=json&titles=" + url.QueryEscape(title)
	resp, err := http.Get(apiURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var result struct {
		Query struct {
			Pages map[string]struct {
				Title   string `json:"title"`
				Extract string `json:"extract"`
			} `json:"pages"`
		} `json:"query"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	for _, page := range result.Query.Pages {
		return &ScrapeResult{
			Title:   page.Title,
			Content: page.Extract,
			URL:     "https://en.wikipedia.org/wiki/" + url.QueryEscape(page.Title),
		}, nil
	}
	return nil, nil
}

// Helper to get domain from URL
func getDomain(rawurl string) string {
	u, err := url.Parse(rawurl)
	if err != nil {
		return ""
	}
	return u.Host
}

// ContainsKeywords checks if content contains any of the given keywords
func ContainsKeywords(content string, keywords []string) bool {
	content = strings.ToLower(content)
	for _, keyword := range keywords {
		if strings.Contains(content, strings.ToLower(keyword)) {
			return true
		}
	}
	return false
}
