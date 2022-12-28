package main

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var jwtKey =[]byte("secret_key")

var Users = map[string]string{
	"user1" : "password1",
	"user2" : "password2",
}

type Credentials struct {
	Username string		`json:"username"`
	Password string		`json:"password"`
}

type Claims struct {
	Username string		`json:"username"`
	jwt.StandardClaims
}

func Login(w http.ResponseWriter, r *http.Request) {
	var credentials Credentials
	// Get data from the request body & decode into credentials
	err := json.NewDecoder(r.Body).Decode(&credentials)
	// Handle error
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Check if the password tallies with the one in credentials
	expectedPassword, ok := Users[credentials.Username]
	
	if !ok || expectedPassword != credentials.Password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Create token expiration time (5 minutes)
	expirationTime := time.Now().Add(time.Minute * 5)

	// Create object for claims
	claims := &Claims{
		Username: credentials.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256,claims)
	tokenString, err := token.SignedString(jwtKey) // token signing string
	// Handle error
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Set cookies
	http.SetCookie(w,
		&http.Cookie{
			Name:	"token",
			Value:	tokenString,
			Expires: expirationTime,
		})

}

func Home(w http.ResponseWriter, r *http.Request) {

}

func Refresh(w http.ResponseWriter, r *http.Request) {

}