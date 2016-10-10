package oauthfacebook

import (
	"strconv"
	"github.com/mattermost/platform/model"
	"io"
	"github.com/mattermost/platform/einterfaces"
	"strings"
	"encoding/json"
)

type FacebookProvider struct {
}

type FacebookUser struct {
	Id       int64  `json:"id"`
	Username string `json:"username"`
	Login    string `json:"login"`
	Email    string `json:"email"`
	Name     string `json:"name"`
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
	username := fbu.Username
	if username == "" {
		username = fbu.Login
	}
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
	strings.TrimSpace(user.Email)
	user.Email = fbu.Email
	userId := strconv.FormatInt(fbu.Id, 10)
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
	if fbu.Id == 0 {
		return false
	}

	if len(fbu.Email) == 0 {
		return false
	}

	return true
}

func (fbu *FacebookUser) getAuthData() string {
	return strconv.FormatInt(fbu.Id, 10)
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
