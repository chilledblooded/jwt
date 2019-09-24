package utils

import (
	"testing"

	"github.com/jwt/models"
)

func testGetCollectionInstance(t *testing.T) {
	temp := mongoURL
	mongoURL = "test"
	defer func() {
		mongoURL = temp
	}()
	_, _, err := GetCollectionInstance("test")
	if err == nil {
		t.Fail()
	}
}

func testGetJwt(t *testing.T) {
	user := models.User{
		Email: "test",
	}
	token, err := GetJwt(user)
	if token == "" && err != nil {
		t.Fail()
	}
}

func TestMaster(t *testing.T) {
	t.Run("testGetCollectionInstance", testGetCollectionInstance)
	t.Run("testGetJwt", testGetJwt)
}
