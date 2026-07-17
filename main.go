package main

import (
	"log"
	"net/http"
	"os"
	"strconv"
)

type server struct {
	capitals []Capital
	images   *ImageCache
}

func (s *server) handleQuestion(w http.ResponseWriter, r *http.Request) {
	score, _ := strconv.Atoi(r.URL.Query().Get("score"))
	total, _ := strconv.Atoi(r.URL.Query().Get("total"))

	q := NewQuestion(s.capitals)
	imageURL := s.images.Get(q.City)

	data := struct {
		City     string
		ImageURL string
		Options  []string
		Answer   string
		Score    int
		Total    int
	}{q.City, imageURL, q.Options, q.Answer, score, total}

	if err := templates.ExecuteTemplate(w, "question.html.tmpl", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *server) handleAnswer(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form submission", http.StatusBadRequest)
		return
	}

	choice := r.FormValue("choice")
	answer := r.FormValue("answer")
	score, _ := strconv.Atoi(r.FormValue("score"))
	total, _ := strconv.Atoi(r.FormValue("total"))

	total++
	correct := choice == answer
	if correct {
		score++
	}

	data := struct {
		Correct bool
		Choice  string
		Answer  string
		Score   int
		Total   int
	}{correct, choice, answer, score, total}

	if err := templates.ExecuteTemplate(w, "result.html.tmpl", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func main() {
	capitals, err := FetchCapitals()
	if err != nil {
		log.Fatalf("could not load game data: %v", err)
	}
	log.Printf("loaded %d capitals", len(capitals))

	s := &server{capitals: capitals, images: NewImageCache()}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handleQuestion)
	mux.HandleFunc("POST /answer", s.handleAnswer)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("listening on http://localhost:%s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatal(err)
	}
}
