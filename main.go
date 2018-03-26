package main

import (
	"log"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("missing master file name")
	}

	db := newRRDB()
	if err := db.Process(os.Args[1:]); err != nil {
		log.Fatal(err)
	}

	db.UpdateIP("w.jw4.us.", "10.10.11.11")

	if err := db.Write(); err != nil {
		log.Fatal(err)
	}
}
