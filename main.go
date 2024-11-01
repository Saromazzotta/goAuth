package main

import (
	"fmt"
	"net/http"
	"time"
)

type Login struct{
	HashedPassword string
	SessionToken string
	CSRFToken string
}

// key is the username

var users = map[string]Login{}

func main() {
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/protected", protected)
	http.ListenAndServe(":8080", nil)
}

func register(w http.ResponseWriter, r *http.Request){
	if r.Method != http.MethodPost {
		er := http.StatusMethodNotAllowed
		http.Error(w, "invalid method", er)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	if len(username) < 8 || len(password) < 8 {
		er := http.StatusNotAcceptable
		http.Error(w, "invalid username/password", er)
		return 
	}

	if _, ok := users[username]; ok {
		er := http.StatusConflict 
		http.Error(w, "User already exists", er)
		return 
	}

	hashedPassword, _ := hashPassword(password)
	users[username] = Login{
		HashedPassword: hashedPassword,
	}

	fmt.Fprintln(w, "User registered successfully!")
}

func login(w http.ResponseWriter, r *http.Request){}

func logout(w http.ResponseWriter, r *http.Request){}

func protected(w http.ResponseWriter, r *http.Request){}
