package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

const capitalsURL = "https://countriesnow.space/api/v0.1/countries/capital"

// Capital pairs a country with its capital city.
type Capital struct {
	Country string
	City    string
}

type capitalsResponse struct {
	Error bool `json:"error"`
	Data  []struct {
		Name    string `json:"name"`
		Capital string `json:"capital"`
	} `json:"data"`
}

// FetchCapitals retrieves the full country/capital list from countriesnow.space,
// dropping entries with no capital and de-duplicating by capital name.
func FetchCapitals() ([]Capital, error) {
	resp, err := http.Get(capitalsURL)
	if err != nil {
		return nil, fmt.Errorf("fetching capitals: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching capitals: unexpected status %s", resp.Status)
	}

	var parsed capitalsResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decoding capitals response: %w", err)
	}
	if parsed.Error {
		return nil, fmt.Errorf("capitals API reported an error")
	}

	seen := make(map[string]bool)
	capitals := make([]Capital, 0, len(parsed.Data))
	for _, entry := range parsed.Data {
		if entry.Capital == "" || seen[entry.Capital] {
			continue
		}
		seen[entry.Capital] = true
		capitals = append(capitals, Capital{Country: entry.Name, City: entry.Capital})
	}

	if len(capitals) < 3 {
		return nil, fmt.Errorf("not enough capitals returned to play (%d)", len(capitals))
	}

	return capitals, nil
}
