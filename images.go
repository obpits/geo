package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const wikiSummaryURL = "https://en.wikipedia.org/api/rest_v1/page/summary/"

var imageHTTPClient = &http.Client{Timeout: 5 * time.Second}

type wikiSummaryResponse struct {
	Thumbnail struct {
		Source string `json:"source"`
	} `json:"thumbnail"`
}

// FetchCityImage looks up a thumbnail image for the given city from
// Wikipedia's public summary API. It returns an empty string (no error)
// if no image could be found, so callers can render the question without one.
func FetchCityImage(city string) (string, error) {
	title := strings.ReplaceAll(city, " ", "_")
	req, err := http.NewRequest(http.MethodGet, wikiSummaryURL+url.PathEscape(title), nil)
	if err != nil {
		return "", fmt.Errorf("building city image request: %w", err)
	}
	req.Header.Set("User-Agent", "geo-guessing-game/1.0 (personal project; using Wikipedia REST API per robot policy)")

	resp, err := imageHTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetching city image: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", nil
	}

	var parsed wikiSummaryResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return "", fmt.Errorf("decoding city image response: %w", err)
	}

	return parsed.Thumbnail.Source, nil
}

// ImageCache memoizes city image lookups so repeated questions about the
// same city don't hit the Wikipedia API every time.
type ImageCache struct {
	mu     sync.Mutex
	byCity map[string]string
}

func NewImageCache() *ImageCache {
	return &ImageCache{byCity: make(map[string]string)}
}

// Get returns the image URL for a city, fetching and caching it on first use.
func (c *ImageCache) Get(city string) string {
	c.mu.Lock()
	if imageURL, ok := c.byCity[city]; ok {
		c.mu.Unlock()
		return imageURL
	}
	c.mu.Unlock()

	imageURL, err := FetchCityImage(city)
	if err != nil {
		imageURL = ""
	}

	c.mu.Lock()
	c.byCity[city] = imageURL
	c.mu.Unlock()

	return imageURL
}
