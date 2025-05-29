package main

import (
	"fmt"
	"net/http"
)

func main() {
	mux := http.NewServeMux()
	server := http.Server{
		Handler: mux,
		Addr:    ":8080",
	}

	err := server.ListenAndServe()

	if err != nil {
		fmt.Println(err)
	}
}
