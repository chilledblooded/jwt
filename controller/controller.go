package controller

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"runtime/debug"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/jwt/models"
	"github.com/jwt/utils"
	"gopkg.in/mgo.v2/bson"
)

//RunController  This is used to creating  server
func RunController(host string) {

	r := mux.NewRouter()
	r.Handle("/api/login", RecoveryHandler(http.HandlerFunc(login))).Methods("POST")
	r.Handle("/api/home", RecoveryHandler(jwtMiddleware(http.HandlerFunc(home)))).Methods("GET")
	log.Println("Starting server on port :: ", host)
	http.ListenAndServe(host, r)
}

func home(w http.ResponseWriter, r *http.Request) {
	email, _ := utils.ParseJwtToken(r)
	response := models.Response{
		Message: "Successfully reached home using JWT token, Email :: " + email,
	}
	w = utils.WriteJSONResponse(w, response, "", http.StatusOK)
}

func login(w http.ResponseWriter, r *http.Request) {
	var user models.User
	var response models.Response
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		log.Printf("Body failed to decode, ERROR ::%v\n ", err)
		response.Message = "Body failed to decode, Invalid data provided"
		response.Error = err.Error()
		w = utils.WriteJSONResponse(w, response, "", http.StatusBadRequest)
		return
	}
	var dbuser models.User

	collection, ctx, err := utils.GetCollectionInstance("user")
	if err != nil {
		log.Println("error occured in getting collection instance :: ", err)
		response.Message = "error occured in getting collection instance"
		response.Error = err.Error()
		w = utils.WriteJSONResponse(w, response, "", http.StatusInternalServerError)
		return

	}
	idDoc := bson.M{"email": user.Email}
	err = collection.FindOne(ctx, idDoc).Decode(&dbuser)
	if err != nil {
		log.Println("error occured finding user:: ", err)
		response.Message = "No such user found with email : " + user.Email
		response.Error = err.Error()
		w = utils.WriteJSONResponse(w, response, "", http.StatusBadRequest)
		return
	}
	h := sha256.New()
	h.Write([]byte(user.Password))
	p := fmt.Sprintf("%x", h.Sum(nil))
	if p == dbuser.Password && user.Email == dbuser.Email {
		token, err := utils.GetJwt(user)
		if err != nil {
			log.Printf("LOGIN :: Error occurred while genetrating token, ERROR ::%v\n ", err)
			response.Message = "Error creating JWT token"
			response.Data = err.Error()
			w = utils.WriteJSONResponse(w, response, "", http.StatusInternalServerError)
			return
		}

		response.Message = "Authentication successful"
		w.Header().Set("Authorization", "Bearer "+token)
		w = utils.WriteJSONResponse(w, response, token, http.StatusOK)
		return

	}
	response.Message = "Authentication failed"
	w = utils.WriteJSONResponse(w, response, "", http.StatusBadRequest)
}

func jwtMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if len(tokenString) == 0 {
			log.Println("Error: JWT token not provided")
			http.Error(w, " authorization token not provided", http.StatusBadRequest)
			return
		}
		token, err := jwt.ParseWithClaims(tokenString, &models.JwtClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(utils.Secret), nil
		})
		if err != nil {
			log.Printf("Error: JWT token Parsing :: %v\n", err)
			http.Error(w, "Error in parsing jwt token or Inavlid Token", http.StatusBadRequest)
			return
		}
		if claims, ok := token.Claims.(*models.JwtClaims); ok && token.Valid {
			if !claims.VerifyIssuer(utils.Issuer, true) {
				log.Printf("Error: JWT token verifying Issuer :: %v\n", err)
				http.Error(w, "Invalid Token", http.StatusBadRequest)
				return
			}
		}
		next.ServeHTTP(w, r)
	}
}

//RecoveryHandler for handling the server's panic situation.
func RecoveryHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if r := recover(); r != nil {
				errorResponse := fmt.Sprintf("Unexpected Error : %v", r)
				stack := debug.Stack()
				log.Println(string(stack))
				log.Printf("%s\n", errorResponse)
				http.Error(w, errorResponse, http.StatusInternalServerError)
			}
		}()
		h.ServeHTTP(w, r)
	})
}
