package models

import "github.com/dgrijalva/jwt-go"

//User model is use to login
type User struct {
	//ID       bson.ObjectId `json:"id,omitempty" bson:"_id,omitempty"`
	Name     string `json:"name" bson:"name"`
	Email    string `json:"email" bson:"email"`
	Password string `json:"password" bson:"password"`
}

//JwtClaims will store the claims for the JWT token
type JwtClaims struct {
	User string `json:"user"`
	jwt.StandardClaims
}

//JwtToken will have to jwt token used for authentication
type JwtToken struct {
	Email string `bson:"email" json:"email"`
	Token string `bson:"token" json:"token"`
}
