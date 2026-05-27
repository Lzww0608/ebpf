package main

import (
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"time"
)

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/users/", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Duration(rand.Intn(80)+10) * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	})

	mux.HandleFunc("/api/orders", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Duration(rand.Intn(150)+20) * time.Millisecond)

		if rand.Intn(10) < 2 {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"order_id":123}`)
	})

	log.Println("demo HTTP service listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
