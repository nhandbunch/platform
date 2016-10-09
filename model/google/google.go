// Copyright (c) 2015 Mattermost, Inc. All Rights Reserved.
// See License.txt for license information.

package oauthgoogle

import (
	"encoding/json"
	"github.com/mattermost/platform/einterfaces"
	"github.com/mattermost/platform/model"
	"io"
	"strconv"
	"strings"
	"fmt"
)

func getOauthType() string {
	return model.USER_AUTH_SERVICE_GOOGLE
}

type GoogleProvider struct {
}

type GoogleUser struct {
	Id         int64  `json:"sub"`
	Username   string `json:"sub"`
	Email      string `json:"email"`
	Name       string `json:"name"`
	GivenName  string `json:"given_name"`
	FamilyName string `json:"family_name"`
}

func init() {
	provider := &GoogleProvider{}
	einterfaces.RegisterOauthProvider(getOauthType(), provider)
}

func userFromGoogleUser(ggu *GoogleUser) *model.User {
	user := &model.User{}
	user.Username = model.CleanUsername(ggu.Username)

	if len(ggu.FamilyName) == 0 && len(ggu.GivenName) == 0 {
		splitName := strings.Split(ggu.Name, " ")
		if len(splitName) == 2 {
			user.FirstName = splitName[0]
			user.LastName = splitName[1]
		} else if len(splitName) >= 2 {
			user.FirstName = splitName[0]
			user.LastName = strings.Join(splitName[1:], " ")
		} else {
			user.FirstName = ggu.Name
		}
	} else {
		user.FirstName = ggu.GivenName
		user.LastName = ggu.FamilyName
	}

	user.Email = strings.TrimSpace(ggu.Email)
	userId := strconv.FormatInt(ggu.Id, 10)
	user.AuthData = &userId
	user.AuthService = getOauthType()

	return user
}

func googleUserFromJson(data io.Reader) *GoogleUser {
	decoder := json.NewDecoder(data)
	var ggu GoogleUser
	err := decoder.Decode(&ggu)
	fmt.Println("email: " + ggu.Email)
	if err == nil {
		return &ggu
	} else {
		return nil
	}
}

func (ggu *GoogleUser) IsValid() bool {
	if ggu.Id == 0 {
		return false
	}

	if len(ggu.Email) == 0 {
		return false
	}

	return true
}

func (ggu *GoogleUser) getAuthData() string {
	return strconv.FormatInt(ggu.Id, 10)
}

func (m *GoogleProvider) GetIdentifier() string {
	return getOauthType()
}

func (m *GoogleProvider) GetUserFromJson(data io.Reader) *model.User {
	ggu := googleUserFromJson(data)
	if ggu.IsValid() {
		return userFromGoogleUser(ggu)
	}

	return &model.User{}
}

func (m *GoogleProvider) GetAuthDataFromJson(data io.Reader) string {
	ggu := googleUserFromJson(data)

	if ggu.IsValid() {
		return ggu.getAuthData()
	}

	return ""
}
