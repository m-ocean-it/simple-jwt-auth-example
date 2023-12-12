package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/schema"
)

const (
	SECRET = "my secret" // FIXME: get from env
)

var (
	userPasswords = map[string]string{
		"admin":    "123456",
		"cool_cat": "cool_password",
	}

	decoder = schema.NewDecoder()
)

type JWTToken string

type LoginSubmission struct {
	User     string `schema:"username"`
	Password string `schema:"password"`
}

func main() {
	http.HandleFunc("/", AuthMiddleware(IndexPageHandler))
	http.HandleFunc("/login", LoginPageHandler)
	http.HandleFunc("/login/send", LoginHandler)

	address := ":8888" // FIXME: get from env
	log.Printf("Serving on address %s", address)

	err := http.ListenAndServe(address, nil)
	if err != nil {
		log.Fatalln(err)
	}
}

func IndexPageHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/index.html")
}

func LoginPageHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/login.html")
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var submission LoginSubmission

	err = decoder.Decode(&submission, r.PostForm)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	token, err := generateToken(submission.User, submission.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Set-Cookie", fmt.Sprintf("token=%s; Path=/", string(token)))
	http.Redirect(w, r, "/", http.StatusFound)
}

func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("token")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		tokenValue := cookie.Value

		valid, err := validateToken(JWTToken(tokenValue))
		if err != nil {
			log.Println(err)
		}
		if !valid {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		next(w, r)
	}

}

func generateToken(username string, suppliedPassword string) (JWTToken, error) {
	dbPassword, ok := userPasswords[username]
	if !ok {
		return "", errors.New("no such user")
	}

	if suppliedPassword != dbPassword {
		return "", errors.New("wrong password")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		IssuedAt: time.Now().Unix(),
		Issuer:   username,
	})

	jwtString, err := token.SignedString([]byte(SECRET))
	if err != nil {
		return "", err
	}

	return JWTToken(jwtString), nil
}

func validateToken(token JWTToken) (bool, error) {
	parsedToken, err := jwt.Parse(string(token), func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}

		return []byte(SECRET), nil
	})

	if err != nil {
		return false, err
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return false, errors.New("could not extract claims")
	}

	log.Printf("Verified JWT token for issuer '%s'", claims["iss"])

	return true, nil
}
