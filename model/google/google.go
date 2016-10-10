// Copyright (c) 2015 Mattermost, Inc. All Rights Reserved.
// See License.txt for license information.

package oauthgoogle

import (
	"encoding/json"
	"github.com/mattermost/platform/einterfaces"
	"github.com/mattermost/platform/model"
	"io"
	"strings"
	"fmt"
)

func getOauthType() string {
	return model.USER_AUTH_SERVICE_GOOGLE
}

type GoogleProvider struct {
}

//type GoogleUser struct {
//	Id         string `json:"sub"`
//	Email      string `json:"email"`
//	Name       string `json:"name"`
//	GivenName  string `json:"given_name"`
//	FamilyName string `json:"family_name"`
//}

type GoogleUser struct {
	Id          string              `json:"id"`
	DisplayName string              `json:"displayName"`
	Emails      []map[string]string `json:"emails"`
	Names       map[string]string   `json:"name"`

	Username    string
	FamilyName  string
	GivenName   string
	Email       string
}

func (ggu *GoogleUser) ToString() string {
	return fmt.Sprintf("Id: %s, Email: %s, Name: %s, GivenName: %s, FamilyName: %s", ggu.Id, ggu.Email, ggu.DisplayName, ggu.GivenName, ggu.FamilyName)
}

func init() {
	provider := &GoogleProvider{}
	einterfaces.RegisterOauthProvider(getOauthType(), provider)
}

func (ggu *GoogleUser) ParseInfo() {
	ggu.FamilyName = ggu.Names["familyName"]
	ggu.GivenName = ggu.Names["givenName"]

	if len(ggu.FamilyName) == 0 && len(ggu.GivenName) == 0 {
		splitName := strings.Split(ggu.DisplayName, " ")
		if len(splitName) == 2 {
			ggu.GivenName = splitName[0]
			ggu.FamilyName = splitName[1]
		} else if len(splitName) >= 2 {
			ggu.GivenName = splitName[0]
			ggu.FamilyName = strings.Join(splitName[1:], " ")
		} else {
			ggu.GivenName = ggu.DisplayName
		}
	}

	for _, e := range ggu.Emails {
		if e["type"] == "account" {
			ggu.Email = e["value"]
			ggu.Username = strings.Split(ggu.Email, "@")[0]
			break
		}
	}
}

func userFromGoogleUser(ggu *GoogleUser) *model.User {
	user := &model.User{}

	user.FirstName = ggu.GivenName
	user.LastName = ggu.FamilyName

	user.Username = model.CleanUsername(ggu.Username)
	user.Email = strings.TrimSpace(ggu.Email)

	userId := strings.TrimSpace(ggu.Id)
	user.AuthData = &userId

	user.AuthService = getOauthType()

	return user
}

func googleUserFromJson(data io.Reader) *GoogleUser {
	decoder := json.NewDecoder(data)
	var ggu GoogleUser
	err := decoder.Decode(&ggu)
	if err == nil {
		ggu.ParseInfo()
		return &ggu
	} else {
		return nil
	}
}

func (ggu *GoogleUser) IsValid() bool {
	if len(ggu.Id) == 0 {
		return false
	}

	if len(ggu.Email) == 0 {
		return false
	}

	return true
}

func (ggu *GoogleUser) getAuthData() string {
	return strings.TrimSpace(ggu.Id)
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
