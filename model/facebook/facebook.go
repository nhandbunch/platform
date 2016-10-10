package oauthfacebook

import (
	"github.com/mattermost/platform/model"
	"io"
	"github.com/mattermost/platform/einterfaces"
	"strings"
	"encoding/json"
)

type FacebookProvider struct {
}

type FacebookUser struct {
	Id       string  `json:"id"`
	Email    string `json:"email"`
	Name     string `json:"name"`

	Username string
}

func getOauthType() string {
	return model.USER_AUTH_SERVICE_FACEBOOK
}

func init() {
	provider := &FacebookProvider{}
	einterfaces.RegisterOauthProvider(getOauthType(), provider)
}

func userFromFacebookUser(fbu *FacebookUser) *model.User {
	user := &model.User{}

	username := strings.Split(fbu.Email, "@")[0]
	user.Username = model.CleanUsername(username)

	splitName := strings.Split(fbu.Name, " ")
	if len(splitName) == 2 {
		user.FirstName = splitName[0]
		user.LastName = splitName[1]
	} else if len(splitName) >= 2 {
		user.FirstName = splitName[0]
		user.LastName = strings.Join(splitName[1:], " ")
	} else {
		user.FirstName = fbu.Name
	}
	user.Email = strings.TrimSpace(fbu.Email)
	userId := strings.TrimSpace(fbu.Id)
	user.AuthData = &userId
	user.AuthService = getOauthType()

	return user
}

func facebookUserFromJson(data io.Reader) *FacebookUser {
	decoder := json.NewDecoder(data)
	var fbu FacebookUser
	err := decoder.Decode(&fbu)
	if err == nil {
		return &fbu
	} else {
		return nil
	}
}

func (fbu *FacebookUser) IsValid() bool {
	if len(fbu.Id) == 0 {
		return false
	}

	if len(fbu.Email) == 0 {
		return false
	}

	return true
}

func (fbu *FacebookUser) getAuthData() string {
	return strings.TrimSpace(fbu.Id)
}

func (m *FacebookProvider) GetIdentifier() string {
	return getOauthType()
}

func (m *FacebookProvider) GetUserFromJson(data io.Reader) *model.User {
	fbu := facebookUserFromJson(data)
	if fbu.IsValid() {
		return userFromFacebookUser(fbu)
	}

	return &model.User{}
}

func (m *FacebookProvider) GetAuthDataFromJson(data io.Reader) string {
	fbu := facebookUserFromJson(data)

	if fbu.IsValid() {
		return fbu.getAuthData()
	}
	return ""
}
