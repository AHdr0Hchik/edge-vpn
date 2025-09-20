package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	log.Println("device-agent bootstrap OK")
	// Заглушка: позже добавим WSS-клиент и сетевую логику.
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	})
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("device-agent listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}