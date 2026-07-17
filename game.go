package main

import "math/rand"

// Question is one round of the game: a city, 3 shuffled country options,
// and which one is correct.
type Question struct {
	City    string
	Options []string
	Answer  string
}

// NewQuestion picks a random capital as the question, then picks 2 more
// distinct-country capitals as wrong options.
func NewQuestion(capitals []Capital) Question {
	correct := capitals[rand.Intn(len(capitals))]

	options := []string{correct.Country}
	for len(options) < 3 {
		candidate := capitals[rand.Intn(len(capitals))].Country
		if candidate == correct.Country || contains(options, candidate) {
			continue
		}
		options = append(options, candidate)
	}

	rand.Shuffle(len(options), func(i, j int) {
		options[i], options[j] = options[j], options[i]
	})

	return Question{City: correct.City, Options: options, Answer: correct.Country}
}

func contains(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}
