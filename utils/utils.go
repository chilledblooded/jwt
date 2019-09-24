package utils

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/jwt/models"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	//Secret is the secret used to sign the jwt token
	Secret = "qazxswedc"
	//Issuer name of the isser of jwt token
	Issuer = "max"
)

var (
	mongoURL     = "mongodb+srv://root:abcd1234@cluster0-flom1.mongodb.net/demo"
	mongoConnect = mongo.Connect
)

//GetCollectionInstance will return the database collection reference
func GetCollectionInstance(collectionName string) (*mongo.Collection, context.Context, error) {
	ctx := context.TODO()
	client, err := mongoConnect(ctx, options.Client().ApplyURI(mongoURL))
	if err != nil {
		return nil, nil, err
	}
	collection := client.Database("demo").Collection(collectionName)
	return collection, ctx, nil
}

//GetJwt is used to get jwt token for authentication
func GetJwt(user models.User) (string, error) {
	time := time.Now().Local().AddDate(24, 0, 0).Unix()
	claims := models.JwtClaims{
		user.Email,
		jwt.StandardClaims{
			ExpiresAt: time,
			Issuer:    Issuer,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	/* Set token claims */

	/* Sign the token with our secret */
	return token.SignedString([]byte(Secret))
}

//ParseJwtToken is used to parse jwt token
func ParseJwtToken(r *http.Request) (email string, err error) {
	tokenString := r.Header.Get("Authorization")
	if len(tokenString) == 0 {
		log.Println("Error: JWT token not provided")
		err = errors.New("JWT token not found")
		return
	}
	token, err := jwt.ParseWithClaims(tokenString, &models.JwtClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(Secret), nil
	})
	if err != nil {
		log.Printf("Error: JWT token Parsing :: %v\n", err)
		return
	}
	if claims, ok := token.Claims.(*models.JwtClaims); ok && token.Valid {
		if !claims.VerifyIssuer("max", true) {
			log.Printf("Error: JWT token verifying Issuer")
			err = errors.New("Error: JWT token verifying Issuer")
			return
		}
		email = claims.User
	}
	return
}

//WriteJSONResponse will write the response in response writer
func WriteJSONResponse(w http.ResponseWriter, response models.Response, token string, status int) http.ResponseWriter {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(response)
	return w
}
