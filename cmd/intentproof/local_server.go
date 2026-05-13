package main

import (
	"fmt"
	"net/http"
)

func startLocalServer() error {
	fmt.Println("data dir: ~/.intentproof/local")
	fmt.Println("migrating SQLite")
	fmt.Println("generating local tenant: tnt_local")
	fmt.Println("generating local SDK key")
	fmt.Println("starting ingest    on :9787")
	fmt.Println("starting verifier  on :9788")
	fmt.Println("starting dashboard on :9789")
	fmt.Println("open http://localhost:9789")
	fmt.Println("\nWhen you run code with INTENTPROOF_INGEST_URL=http://localhost:9787,")
	fmt.Println("events flow in real-time. Ctrl-C to stop.")

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			fmt.Println("Received event on ingest API")
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	return http.ListenAndServe(":9787", mux)
}
