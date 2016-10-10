// Copyright (c) 2015 Mattermost, Inc. All Rights Reserved.
// See License.txt for license information.

package api

import (
	"github.com/mattermost/platform/model"
	"github.com/mattermost/platform/utils"
	"net/url"
	"testing"
	b64 "encoding/base64"
	"fmt"
	//"github.com/gorilla/mux"
	"strings"
	"io/ioutil"
	//"net/http"
	"io"
	"bytes"
	"github.com/mattermost/platform/einterfaces"
	//"github.com/mattermost/platform/store"
	//"strconv"
	//"time"
	//"github.com/mssola/user_agent"
	//"crypto/tls"

	// Plugins
	_ "github.com/mattermost/platform/model/gitlab"
	"net/http"
	"crypto/tls"
	//"os/user"
	"encoding/json"
	"github.com/mattermost/platform/model/google"
)

func TestLoginWithOAuthGoogle(t *testing.T) {
	utils.LoadConfig("config.json")
	//Setup().InitBasic()
	//th := Setup().InitBasic().InitSystemAdmin()
	//Client := th.BasicClient
	//AdminClient := th.SystemAdminClient

	service := "google"
	loginHint := ""
	redirectTo := ""

	teamId := ""

	stateProps := map[string]string{}
	stateProps["action"] = model.OAUTH_ACTION_LOGIN
	if len(teamId) != 0 {
		stateProps["team_id"] = teamId
	}

	if len(redirectTo) != 0 {
		stateProps["redirect_to"] = redirectTo
	}

	sso := utils.Cfg.GetSSOService(service)
	//fmt.Println(sso)
	if sso != nil && !sso.Enable {
		fmt.Println(model.NewLocAppError("GetAuthorizationCode", "api.user.get_authorization_code.unsupported.app_error", nil, "service=" + service).ToJson())
	}

	clientId := sso.Id
	endpoint := sso.AuthEndpoint
	scope := sso.Scope
	responseType := sso.ResponseType
	stateProps["hash"] = model.HashPassword(clientId)
	state := b64.StdEncoding.EncodeToString([]byte(model.MapToJson(stateProps)))

	redirectUri := "http://chat.demomattermost.com:8065/signup/" + service + "/complete"

	authUrl := endpoint + "?response_type=" + utils.UrlEncode(responseType) + "&client_id=" + clientId + "&state=" + url.QueryEscape(state)

	if len(scope) > 0 {
		authUrl += "&scope=" + utils.UrlEncode(scope)
	}

	if len(loginHint) > 0 {
		authUrl += "&login_hint=" + utils.UrlEncode(loginHint)
	}

	authUrl += "&redirect_uri=" + url.QueryEscape(redirectUri)

	fmt.Println(authUrl)

	//tr := &http.Transport{
	//	TLSClientConfig: &tls.Config{InsecureSkipVerify: *utils.Cfg.ServiceSettings.EnableInsecureOutgoingConnections},
	//}
	//client := &http.Client{Transport: tr}
	//req, _ := http.NewRequest("GET", authUrl, strings.NewReader(url.Values{}.Encode()))
	//if resp, err := client.Do(req); err != nil {
	//	fmt.Println("get authUrl fail")
	//	return
	//} else {
	//	fmt.Println(resp)
	//}
}

func TestCompleteAuthGoogle(t *testing.T) {
	TestLoginWithOAuthGoogle(t)

	utils.LoadConfig("config.json")

	service := "google"

	code := "4/3H1FxQ3gTxQgOmmn6s8kJm7r9bpEsQY5KpkJ_jaZC5o"
	if len(code) == 0 {
		fmt.Println(model.NewLocAppError("completeOAuth", "api.oauth.complete_oauth.missing_code.app_error", map[string]interface{}{"service": strings.Title(service)}, "").ToJson())
		return
	}

	state := "eyJhY3Rpb24iOiJsb2dpbiIsImhhc2giOiIkMmEkMTAkMDFZdUtUd2x6SGpJQVpwOGxVMi51dThhbHZEOU1HRmlMT1lPWEFGZE1jcGd3ZS8wTFNLdXEifQ=="

	uri := "http://chat.demomattermost.com:8065/signup/" + service + "/complete"

	if body, teamId, props, err := AuthorizeOAuthUserTest(service, code, state, uri); err != nil {
		fmt.Println(err)
		return
	} else {
		fmt.Println("AuthorizeOAuthUser success")
		defer func() {
			ioutil.ReadAll(body)
			body.Close()
		}()

		action := props["action"]

		//fmt.Println(teamId)
		//fmt.Println(action)

		switch action {
		//case model.OAUTH_ACTION_SIGNUP:
		//	CreateOAuthUser(c, w, r, service, body, teamId)
		//	if c.Err == nil {
		//		http.Redirect(w, r, GetProtocol(r) + "://" + r.Host, http.StatusTemporaryRedirect)
		//	}
		//	break
		case model.OAUTH_ACTION_LOGIN:
			fmt.Println("doLogin")
			user := LoginByOAuthTest(service, body)
			if len(teamId) > 0 {
				fmt.Println(JoinUserToTeamById(teamId, user))
			}
			//if c.Err == nil {
			if val, ok := props["redirect_to"]; ok {
				fmt.Println(val)
				//http.Redirect(w, r, c.GetSiteURL() + val, http.StatusTemporaryRedirect)
				return
			}
			fmt.Println("Redirect root")
			//http.Redirect(w, r, GetProtocol(r) + "://" + r.Host, http.StatusTemporaryRedirect)
			//}
			break
		//case model.OAUTH_ACTION_EMAIL_TO_SSO:
		//	CompleteSwitchWithOAuth(c, w, r, service, body, props["email"])
		//	if c.Err == nil {
		//		http.Redirect(w, r, GetProtocol(r) + "://" + r.Host + "/login?extra=signin_change", http.StatusTemporaryRedirect)
		//	}
		//	break
		//case model.OAUTH_ACTION_SSO_TO_EMAIL:
		//	LoginByOAuth(c, w, r, service, body)
		//	if c.Err == nil {
		//		http.Redirect(w, r, GetProtocol(r) + "://" + r.Host + "/claim?email=" + url.QueryEscape(props["email"]), http.StatusTemporaryRedirect)
		//	}
		//	break
		//default:
		//	LoginByOAuth(c, w, r, service, body)
		//	if c.Err == nil {
		//		http.Redirect(w, r, GetProtocol(r) + "://" + r.Host, http.StatusTemporaryRedirect)
		//	}
		//	break
		}
	}
}

func AuthorizeOAuthUserTest(service, code, state, redirectUri string) (io.ReadCloser, string, map[string]string, *model.AppError) {
	sso := utils.Cfg.GetSSOService(service)
	if sso == nil || !sso.Enable {
		return nil, "", nil, model.NewLocAppError("AuthorizeOAuthUser", "api.user.authorize_oauth_user.unsupported.app_error", nil, "service=" + service)
	}

	stateStr := ""
	if b, err := b64.StdEncoding.DecodeString(state); err != nil {
		return nil, "", nil, model.NewLocAppError("AuthorizeOAuthUser", "api.user.authorize_oauth_user.invalid_state.app_error", nil, err.Error())
	} else {
		stateStr = string(b)
	}

	stateProps := model.MapFromJson(strings.NewReader(stateStr))

	if !model.ComparePassword(stateProps["hash"], sso.Id) {
		return nil, "", nil, model.NewLocAppError("AuthorizeOAuthUser", "api.user.authorize_oauth_user.invalid_state.app_error", nil, "")
	}

	teamId := stateProps["team_id"]

	p := url.Values{}
	p.Set("client_id", sso.Id)
	p.Set("client_secret", sso.Secret)
	p.Set("code", code)
	p.Set("grant_type", model.ACCESS_TOKEN_GRANT_TYPE)
	p.Set("redirect_uri", redirectUri)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: *utils.Cfg.ServiceSettings.EnableInsecureOutgoingConnections},
	}
	client := &http.Client{Transport: tr}

	fmt.Println("Req1: " + sso.TokenEndpoint + " - " + p.Encode())

	req, _ := http.NewRequest("POST", sso.TokenEndpoint, strings.NewReader(p.Encode()))

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	var ar *model.AccessResponse
	var respBody []byte
	if resp, err := client.Do(req); err != nil {
		return nil, "", nil, model.NewLocAppError("AuthorizeOAuthUser", "api.user.authorize_oauth_user.token_failed.app_error", nil, err.Error())
	} else {
		ar = model.AccessResponseFromJson(resp.Body)
		fmt.Println("Resp1: " + ar.ToJson())
		defer func() {
			ioutil.ReadAll(resp.Body)
			resp.Body.Close()
		}()
		if ar == nil {
			return nil, "", nil, model.NewLocAppError("AuthorizeOAuthUser", "api.user.authorize_oauth_user.bad_response.app_error", nil, "")
		}
	}

	if strings.ToLower(ar.TokenType) != model.ACCESS_TOKEN_TYPE {
		return nil, "", nil, model.NewLocAppError("AuthorizeOAuthUser", "api.user.authorize_oauth_user.bad_token.app_error", nil, "token_type=" + ar.TokenType + ", response_body=" + string(respBody))
	}

	if len(ar.AccessToken) == 0 {
		return nil, "", nil, model.NewLocAppError("AuthorizeOAuthUser", "api.user.authorize_oauth_user.missing.app_error", nil, "")
	}

	fmt.Println(ar.ToJson())

	//accessToken := "ya29.CjB2AyaknSPv6gWAd937ygrOvYO_KynTWcYyKe23wl5_m_4i0fFJcnBEp7fnMT55hZM"
	//tokenType := "Bearer"

	p = url.Values{}
	p.Set("access_token", ar.AccessToken)
	req, _ = http.NewRequest("GET", sso.UserApiEndpoint, strings.NewReader(""))

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer " + ar.AccessToken)

	if resp, err := client.Do(req); err != nil {
		return nil, "", nil, model.NewLocAppError("AuthorizeOAuthUser", "api.user.authorize_oauth_user.service.app_error",
			map[string]interface{}{"Service": service}, err.Error())
	} else {
		return resp.Body, teamId, stateProps, nil
	}

	//p = url.Values{}
	//p.Set("id_token", ar.IdToken)
	//req, _ = http.NewRequest("GET", sso.UserApiEndpoint, strings.NewReader(""))
	//
	//req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	//req.Header.Set("Accept", "application/json")
	////req.Header.Set("Authorization", "Bearer " + ar.AccessToken)
	//
	//if resp, err := client.Do(req); err != nil {
	//	return nil, "", nil, model.NewLocAppError("AuthorizeOAuthUser", "api.user.authorize_oauth_user.service.app_error",
	//		map[string]interface{}{"Service": service}, err.Error())
	//} else {
	//	return resp.Body, teamId, stateProps, nil
	//}

}

func LoginByOAuthTest(service string, userData io.Reader) *model.User {

	buf := bytes.Buffer{}
	buf.ReadFrom(userData)

	authData := ""
	provider := einterfaces.GetOauthProvider(service)
	if provider == nil {
		fmt.Println(model.NewLocAppError("LoginByOAuth", "api.user.login_by_oauth.not_available.app_error",
			map[string]interface{}{"Service": strings.Title(service)}, "").ToJson())
		return nil
	} else {
		authData = provider.GetAuthDataFromJson(bytes.NewReader(buf.Bytes()))
	}
	fmt.Println("authData: " + authData)

	if len(authData) == 0 {
		fmt.Println(model.NewLocAppError("LoginByOAuth", "api.user.login_by_oauth.parse.app_error",
			map[string]interface{}{"Service": service}, "").ToJson())
		return nil
	}


	//var user *model.User
	//if result := <-Srv.Store.User().GetByAuth(&authData, service); result.Err != nil {
	//	if result.Err.Id == store.MISSING_AUTH_ACCOUNT_ERROR {
	//		return CreateOAuthUserTest(service, bytes.NewReader(buf.Bytes()), "")
	//	}
	//	fmt.Println(result.Err)
	//	return nil
	//} else {
	//	user = result.Data.(*model.User)
	//	//doLoginTest(c, w, r, user, "")
	//	//if c.Err != nil {
	//	//	return nil
	//	//}
	//	return user
	//}
	return nil
}

type Foo struct {
	Bar string
}

func TestGetInfoUserGoogle(t *testing.T) {
	utils.LoadConfig("config.json")

	service := "google"
	sso := utils.Cfg.GetSSOService(service)

	//idToken := "eyJhbGciOiJSUzI1NiIsImtpZCI6ImY5ZWU5MjQ3ODhiZTQzNTM1MGRhZjI5ZjY0Njg1YjUzOTcxNGFlN2UifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhdF9oYXNoIjoiN0F2UVZCbDhEektnS1l1eVRYQ2NEQSIsImF1ZCI6IjMwNzczMzA3NzgyNC1hcjVvYTJyMnBrbGljYWhlZDh2ZWxqZDNxbXNqZTk4ZS5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsInN1YiI6IjExMTM5NjA2NzI4MzM2NzI2MjA3NCIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJhenAiOiIzMDc3MzMwNzc4MjQtYXI1b2EycjJwa2xpY2FoZWQ4dmVsamQzcW1zamU5OGUuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJlbWFpbCI6Im5oYW5kYnVuY2hAZ21haWwuY29tIiwiaWF0IjoxNDc2MDMxNzMwLCJleHAiOjE0NzYwMzUzMzAsIm5hbWUiOiJQaOG6oW0gTmfhu41jIFPGoW4iLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tLy13MDljRnQybTVoTS9BQUFBQUFBQUFBSS9BQUFBQUFBQUEwZy9WYXh6eVR5aXlGVS9zOTYtYy9waG90by5qcGciLCJnaXZlbl9uYW1lIjoiUGjhuqFtIiwiZmFtaWx5X25hbWUiOiJOZ-G7jWMgU8ahbiIsImxvY2FsZSI6InZpIn0.V9sS7p019Rbs-XVh79vUza4btH4HqDbFLLhQMWM-k1NBHniRkw2LMLI7WFhIodgikSzukYEfNQvRXDrOw6RpY3pyN_26JVgTlYHxwksp-9is8oXtFH6RngGvW-3rYBeNDmGb9_TTx-wp1fcwUgkY0nXff_lmnFpD1MZbhMP2tGOiyu4LWUUxqzgrIPBnOxTG7YYAsKqOiidNQzLcq891pOEM1xYjkEUdy0QY4z9GvxVNXGQdSn5U0OU6JbK2FDuUul65dKD7WQ8svmpc0VraCdf-8ugz7TZ0ToSXdTaeZRiPcLPczI8Doh-p7UxHTxwKjoQlvgpUholZxtfjQ9yxyw"
	accessToken := "ya29.CjR3A28y34vawAh63WQPHaa1IOdhI5-XKugDtmri1I-dk9u2JLaSh2QubLb2d8JgNI8viDma"
	//tokenType := "Bearer"

	//url := sso.UserApiEndpoint + "?id_token=" + idToken


	url := sso.UserApiEndpoint //+ "?access_token=" + accessToken
	req, _ := http.NewRequest("GET", url, nil)
	query := req.URL.Query()
	query.Add("access_token", accessToken)

	req.URL.RawQuery = query.Encode()


	//fmt.Println(query.Encode())
	//fmt.Println(query)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer " + accessToken)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: *utils.Cfg.ServiceSettings.EnableInsecureOutgoingConnections},
	}
	client := &http.Client{Transport: tr}

	fmt.Println(req)
	fmt.Println(req.Body)
	//fmt.Println(p)

	if resp, err := client.Do(req); err != nil {
		fmt.Println(model.NewLocAppError("AuthorizeOAuthUser", "api.user.authorize_oauth_user.service.app_error",
			map[string]interface{}{"Service": service}, err.Error()).ToJson())
	} else {
		//s, _ := ioutil.ReadAll(resp.Body)
		//fmt.Println(string(s))


		var ggu oauthgoogle.GoogleUser
		//ggu := new(Foo)
		json.NewDecoder(resp.Body).Decode(&ggu)
		ggu.ParseInfo()



		fmt.Print("ggu: ")
		fmt.Println(ggu.ToString())
		fmt.Print("err: ")
		fmt.Println(err)


		//LoginByOAuthTest(service,  resp.Body)
		//return resp.Body, teamId, stateProps, nil
	}

	//p = url.Values{}
	//p.Set("id_token", ar.IdToken)
	//req, _ = http.NewRequest("GET", sso.UserApiEndpoint, strings.NewReader(""))
	//
	//req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	//req.Header.Set("Accept", "application/json")
	////req.Header.Set("Authorization", "Bearer " + ar.AccessToken)
	//
	//if resp, err := client.Do(req); err != nil {
	//	return nil, "", nil, model.NewLocAppError("AuthorizeOAuthUser", "api.user.authorize_oauth_user.service.app_error",
	//		map[string]interface{}{"Service": service}, err.Error())
	//} else {
	//	return resp.Body, teamId, stateProps, nil
	//}
}

//func CreateOAuthUserTest(service string, userData io.Reader, teamId string) *model.User {
//	var user *model.User
//	provider := einterfaces.GetOauthProvider(service)
//	if provider == nil {
//		c.Err = model.NewLocAppError("CreateOAuthUser", "api.user.create_oauth_user.not_available.app_error", map[string]interface{}{"Service": strings.Title(service)}, "")
//		return nil
//	} else {
//		user = provider.GetUserFromJson(userData)
//	}
//
//	if user == nil {
//		c.Err = model.NewLocAppError("CreateOAuthUser", "api.user.create_oauth_user.create.app_error", map[string]interface{}{"Service": service}, "")
//		return nil
//	}
//
//	suchan := Srv.Store.User().GetByAuth(user.AuthData, service)
//	euchan := Srv.Store.User().GetByEmail(user.Email)
//
//	found := true
//	count := 0
//	for found {
//		if found = IsUsernameTaken(user.Username); found {
//			user.Username = user.Username + strconv.Itoa(count)
//			count += 1
//		}
//	}
//
//	if result := <-suchan; result.Err == nil {
//		c.Err = model.NewLocAppError("CreateOAuthUser", "api.user.create_oauth_user.already_used.app_error",
//			map[string]interface{}{"Service": service}, "email="+user.Email)
//		return nil
//	}
//
//	if result := <-euchan; result.Err == nil {
//		authService := result.Data.(*model.User).AuthService
//		if authService == "" {
//			c.Err = model.NewLocAppError("CreateOAuthUser", "api.user.create_oauth_user.already_attached.app_error",
//				map[string]interface{}{"Service": service, "Auth": model.USER_AUTH_SERVICE_EMAIL}, "email="+user.Email)
//		} else {
//			c.Err = model.NewLocAppError("CreateOAuthUser", "api.user.create_oauth_user.already_attached.app_error",
//				map[string]interface{}{"Service": service, "Auth": authService}, "email="+user.Email)
//		}
//		return nil
//	}
//
//	user.EmailVerified = true
//
//	ruser, err := CreateUser(user)
//	if err != nil {
//		c.Err = err
//		return nil
//	}
//
//	if len(teamId) > 0 {
//		err = JoinUserToTeamById(teamId, user)
//		if err != nil {
//			c.Err = err
//			return nil
//		}
//
//		go addDirectChannels(teamId, user)
//	}
//
//	doLogin(c, w, r, ruser, "")
//	if c.Err != nil {
//		return nil
//	}
//
//	return ruser
//}

//func doLoginTest(user *model.User, deviceId string) {
//
//	session := &model.Session{UserId: user.Id, Roles: user.GetRawRoles(), DeviceId: deviceId, IsOAuth: false}
//
//	maxAge := *utils.Cfg.ServiceSettings.SessionLengthWebInDays * 60 * 60 * 24
//
//	if len(deviceId) > 0 {
//		session.SetExpireInDays(*utils.Cfg.ServiceSettings.SessionLengthMobileInDays)
//		maxAge = *utils.Cfg.ServiceSettings.SessionLengthMobileInDays * 60 * 60 * 24
//
//		// A special case where we logout of all other sessions with the same Id
//		if result := <-Srv.Store.Session().GetSessions(user.Id); result.Err != nil {
//			c.Err = result.Err
//			c.Err.StatusCode = http.StatusInternalServerError
//			return
//		} else {
//			sessions := result.Data.([]*model.Session)
//			for _, session := range sessions {
//				if session.DeviceId == deviceId {
//					l4g.Debug(utils.T("api.user.login.revoking.app_error"), session.Id, user.Id)
//					RevokeSessionById(c, session.Id)
//					if c.Err != nil {
//						c.LogError(c.Err)
//						c.Err = nil
//					}
//				}
//			}
//		}
//	} else {
//		session.SetExpireInDays(*utils.Cfg.ServiceSettings.SessionLengthWebInDays)
//	}
//
//	ua := user_agent.New(r.UserAgent())
//
//	plat := ua.Platform()
//	if plat == "" {
//		plat = "unknown"
//	}
//
//	os := ua.OS()
//	if os == "" {
//		os = "unknown"
//	}
//
//	bname, bversion := ua.Browser()
//	if bname == "" {
//		bname = "unknown"
//	}
//
//	if bversion == "" {
//		bversion = "0.0"
//	}
//
//	session.AddProp(model.SESSION_PROP_PLATFORM, plat)
//	session.AddProp(model.SESSION_PROP_OS, os)
//	session.AddProp(model.SESSION_PROP_BROWSER, fmt.Sprintf("%v/%v", bname, bversion))
//
//	if result := <-Srv.Store.Session().Save(session); result.Err != nil {
//		c.Err = result.Err
//		c.Err.StatusCode = http.StatusInternalServerError
//		return
//	} else {
//		session = result.Data.(*model.Session)
//		AddSessionToCache(session)
//	}
//
//	w.Header().Set(model.HEADER_TOKEN, session.Token)
//
//	secure := false
//	if GetProtocol(r) == "https" {
//		secure = true
//	}
//
//	expiresAt := time.Unix(model.GetMillis()/1000+int64(maxAge), 0)
//	sessionCookie := &http.Cookie{
//		Name:     model.SESSION_COOKIE_TOKEN,
//		Value:    session.Token,
//		Path:     "/",
//		MaxAge:   maxAge,
//		Expires:  expiresAt,
//		HttpOnly: true,
//		Secure:   secure,
//	}
//
//	http.SetCookie(w, sessionCookie)
//
//	c.Session = *session
//}

func TestRegisterApp(t *testing.T) {
	th := Setup().InitBasic().InitSystemAdmin()
	Client := th.SystemAdminClient

	app := &model.OAuthApp{Name: "TestApp" + model.NewId(), Homepage: "https://nowhere.com", Description: "test", CallbackUrls: []string{"https://nowhere.com"}}

	if !utils.Cfg.ServiceSettings.EnableOAuthServiceProvider {
		if _, err := Client.RegisterApp(app); err == nil {
			t.Fatal("should have failed - oauth providing turned off")
		}

	}

	utils.Cfg.ServiceSettings.EnableOAuthServiceProvider = true

	Client.Logout()

	if _, err := Client.RegisterApp(app); err == nil {
		t.Fatal("not logged in - should have failed")
	}

	th.LoginSystemAdmin()

	if result, err := Client.RegisterApp(app); err != nil {
		t.Fatal(err)
	} else {
		rapp := result.Data.(*model.OAuthApp)
		if len(rapp.Id) != 26 {
			t.Fatal("clientid didn't return properly")
		}
		if len(rapp.ClientSecret) != 26 {
			t.Fatal("client secret didn't return properly")
		}
	}

	app = &model.OAuthApp{Name: "", Homepage: "https://nowhere.com", Description: "test", CallbackUrls: []string{"https://nowhere.com"}}
	if _, err := Client.RegisterApp(app); err == nil {
		t.Fatal("missing name - should have failed")
	}

	app = &model.OAuthApp{Name: "TestApp" + model.NewId(), Homepage: "", Description: "test", CallbackUrls: []string{"https://nowhere.com"}}
	if _, err := Client.RegisterApp(app); err == nil {
		t.Fatal("missing homepage - should have failed")
	}

	app = &model.OAuthApp{Name: "TestApp" + model.NewId(), Homepage: "https://nowhere.com", Description: "test", CallbackUrls: []string{}}
	if _, err := Client.RegisterApp(app); err == nil {
		t.Fatal("missing callback url - should have failed")
	}
}

func TestAllowOAuth(t *testing.T) {
	th := Setup().InitBasic().InitSystemAdmin()
	Client := th.BasicClient
	AdminClient := th.SystemAdminClient

	utils.Cfg.ServiceSettings.EnableOAuthServiceProvider = true
	app := &model.OAuthApp{Name: "TestApp" + model.NewId(), Homepage: "https://nowhere.com", Description: "test", CallbackUrls: []string{"https://nowhere.com"}}
	app = AdminClient.Must(AdminClient.RegisterApp(app)).Data.(*model.OAuthApp)

	state := "123"

	utils.Cfg.ServiceSettings.EnableOAuthServiceProvider = false
	if _, err := Client.AllowOAuth(model.AUTHCODE_RESPONSE_TYPE, app.Id, app.CallbackUrls[0], "all", state); err == nil {
		t.Fatal("should have failed - oauth providing turned off")
	}

	utils.Cfg.ServiceSettings.EnableOAuthServiceProvider = true

	if result, err := Client.AllowOAuth(model.AUTHCODE_RESPONSE_TYPE, app.Id, app.CallbackUrls[0], "all", state); err != nil {
		t.Fatal(err)
	} else {
		redirect := result.Data.(map[string]string)["redirect"]
		if len(redirect) == 0 {
			t.Fatal("redirect url should be set")
		}

		ru, _ := url.Parse(redirect)
		if ru == nil {
			t.Fatal("redirect url unparseable")
		} else {
			if len(ru.Query().Get("code")) == 0 {
				t.Fatal("authorization code not returned")
			}
			if ru.Query().Get("state") != state {
				t.Fatal("returned state doesn't match")
			}
		}
	}

	if _, err := Client.AllowOAuth(model.AUTHCODE_RESPONSE_TYPE, app.Id, "", "all", state); err == nil {
		t.Fatal("should have failed - no redirect_url given")
	}

	if _, err := Client.AllowOAuth(model.AUTHCODE_RESPONSE_TYPE, app.Id, "", "", state); err == nil {
		t.Fatal("should have failed - no redirect_url given")
	}

	if result, err := Client.AllowOAuth("junk", app.Id, app.CallbackUrls[0], "all", state); err != nil {
		t.Fatal(err)
	} else {
		redirect := result.Data.(map[string]string)["redirect"]
		if len(redirect) == 0 {
			t.Fatal("redirect url should be set")
		}

		ru, _ := url.Parse(redirect)
		if ru == nil {
			t.Fatal("redirect url unparseable")
		} else {
			if ru.Query().Get("error") != "unsupported_response_type" {
				t.Fatal("wrong error returned")
			}
			if ru.Query().Get("state") != state {
				t.Fatal("returned state doesn't match")
			}
		}
	}

	if _, err := Client.AllowOAuth(model.AUTHCODE_RESPONSE_TYPE, "", app.CallbackUrls[0], "all", state); err == nil {
		t.Fatal("should have failed - empty client id")
	}

	if _, err := Client.AllowOAuth(model.AUTHCODE_RESPONSE_TYPE, "junk", app.CallbackUrls[0], "all", state); err == nil {
		t.Fatal("should have failed - bad client id")
	}

	if _, err := Client.AllowOAuth(model.AUTHCODE_RESPONSE_TYPE, app.Id, "https://somewhereelse.com", "all", state); err == nil {
		t.Fatal("should have failed - redirect uri host does not match app host")
	}
}

func TestGetOAuthAppsByUser(t *testing.T) {
	th := Setup().InitBasic().InitSystemAdmin()
	Client := th.BasicClient
	AdminClient := th.SystemAdminClient

	if !utils.Cfg.ServiceSettings.EnableOAuthServiceProvider {
		if _, err := Client.GetOAuthAppsByUser(); err == nil {
			t.Fatal("should have failed - oauth providing turned off")
		}

	}

	utils.Cfg.ServiceSettings.EnableOAuthServiceProvider = true

	if _, err := Client.GetOAuthAppsByUser(); err != nil {
		t.Fatal("Should have passed.")
	}

	*utils.Cfg.ServiceSettings.EnableOnlyAdminIntegrations = false
	utils.SetDefaultRolesBasedOnConfig()

	if result, err := Client.GetOAuthAppsByUser(); err != nil {
		t.Fatal(err)
	} else {
		apps := result.Data.([]*model.OAuthApp)

		if len(apps) != 0 {
			t.Fatal("incorrect number of apps should have been 0")
		}
	}

	app := &model.OAuthApp{Name: "TestApp" + model.NewId(), Homepage: "https://nowhere.com", Description: "test", CallbackUrls: []string{"https://nowhere.com"}}
	app = Client.Must(Client.RegisterApp(app)).Data.(*model.OAuthApp)

	if result, err := Client.GetOAuthAppsByUser(); err != nil {
		t.Fatal(err)
	} else {
		apps := result.Data.([]*model.OAuthApp)

		if len(apps) != 1 {
			t.Fatal("incorrect number of apps should have been 1")
		}
	}

	app = &model.OAuthApp{Name: "TestApp4" + model.NewId(), Homepage: "https://nowhere.com", Description: "test", CallbackUrls: []string{"https://nowhere.com"}}
	app = AdminClient.Must(Client.RegisterApp(app)).Data.(*model.OAuthApp)

	if result, err := AdminClient.GetOAuthAppsByUser(); err != nil {
		t.Fatal(err)
	} else {
		apps := result.Data.([]*model.OAuthApp)

		if len(apps) < 4 {
			t.Fatal("incorrect number of apps should have been 4 or more")
		}
	}
}

func TestGetOAuthAppInfo(t *testing.T) {
	th := Setup().InitBasic().InitSystemAdmin()
	Client := th.BasicClient
	AdminClient := th.SystemAdminClient

	if !utils.Cfg.ServiceSettings.EnableOAuthServiceProvider {
		if _, err := Client.GetOAuthAppInfo("fakeId"); err == nil {
			t.Fatal("should have failed - oauth providing turned off")
		}

	}

	utils.Cfg.ServiceSettings.EnableOAuthServiceProvider = true

	app := &model.OAuthApp{Name: "TestApp5" + model.NewId(), Homepage: "https://nowhere.com", Description: "test", CallbackUrls: []string{"https://nowhere.com"}}

	app = AdminClient.Must(AdminClient.RegisterApp(app)).Data.(*model.OAuthApp)

	if _, err := Client.GetOAuthAppInfo(app.Id); err != nil {
		t.Fatal(err)
	}
}

func TestGetAuthorizedApps(t *testing.T) {
	th := Setup().InitBasic().InitSystemAdmin()
	Client := th.BasicClient
	AdminClient := th.SystemAdminClient

	utils.Cfg.ServiceSettings.EnableOAuthServiceProvider = true

	app := &model.OAuthApp{Name: "TestApp5" + model.NewId(), Homepage: "https://nowhere.com", Description: "test", CallbackUrls: []string{"https://nowhere.com"}}

	app = AdminClient.Must(AdminClient.RegisterApp(app)).Data.(*model.OAuthApp)

	if _, err := Client.AllowOAuth(model.AUTHCODE_RESPONSE_TYPE, app.Id, "https://nowhere.com", "user", ""); err != nil {
		t.Fatal(err)
	}

	if result, err := Client.GetOAuthAuthorizedApps(); err != nil {
		t.Fatal(err)
	} else {
		apps := result.Data.([]*model.OAuthApp)

		if len(apps) != 1 {
			t.Fatal("incorrect number of apps should have been 1")
		}
	}
}

func TestDeauthorizeApp(t *testing.T) {
	th := Setup().InitBasic().InitSystemAdmin()
	Client := th.BasicClient
	AdminClient := th.SystemAdminClient

	utils.Cfg.ServiceSettings.EnableOAuthServiceProvider = true

	app := &model.OAuthApp{Name: "TestApp5" + model.NewId(), Homepage: "https://nowhere.com", Description: "test", CallbackUrls: []string{"https://nowhere.com"}}

	app = AdminClient.Must(AdminClient.RegisterApp(app)).Data.(*model.OAuthApp)

	if _, err := Client.AllowOAuth(model.AUTHCODE_RESPONSE_TYPE, app.Id, "https://nowhere.com", "user", ""); err != nil {
		t.Fatal(err)
	}

	if err := Client.OAuthDeauthorizeApp(app.Id); err != nil {
		t.Fatal(err)
	}

	if result, err := Client.GetOAuthAuthorizedApps(); err != nil {
		t.Fatal(err)
	} else {
		apps := result.Data.([]*model.OAuthApp)

		if len(apps) != 0 {
			t.Fatal("incorrect number of apps should have been 0")
		}
	}
}

func TestRegenerateOAuthAppSecret(t *testing.T) {
	th := Setup().InitSystemAdmin()
	AdminClient := th.SystemAdminClient

	utils.Cfg.ServiceSettings.EnableOAuthServiceProvider = true

	app := &model.OAuthApp{Name: "TestApp6" + model.NewId(), Homepage: "https://nowhere.com", Description: "test", CallbackUrls: []string{"https://nowhere.com"}}

	app = AdminClient.Must(AdminClient.RegisterApp(app)).Data.(*model.OAuthApp)

	if regenApp, err := AdminClient.RegenerateOAuthAppSecret(app.Id); err != nil {
		t.Fatal(err)
	} else {
		app2 := regenApp.Data.(*model.OAuthApp)
		if app2.Id != app.Id {
			t.Fatal("Should have been the same app Id")
		}

		if app2.ClientSecret == app.ClientSecret {
			t.Fatal("Should have been diferent client Secrets")
		}
	}
}

func TestOAuthDeleteApp(t *testing.T) {
	th := Setup().InitBasic().InitSystemAdmin()
	Client := th.BasicClient
	AdminClient := th.SystemAdminClient

	if !utils.Cfg.ServiceSettings.EnableOAuthServiceProvider {
		if _, err := Client.DeleteOAuthApp("fakeId"); err == nil {
			t.Fatal("should have failed - oauth providing turned off")
		}

	}

	utils.Cfg.ServiceSettings.EnableOAuthServiceProvider = true
	*utils.Cfg.ServiceSettings.EnableOnlyAdminIntegrations = false
	utils.SetDefaultRolesBasedOnConfig()

	app := &model.OAuthApp{Name: "TestApp5" + model.NewId(), Homepage: "https://nowhere.com", Description: "test", CallbackUrls: []string{"https://nowhere.com"}}

	app = Client.Must(Client.RegisterApp(app)).Data.(*model.OAuthApp)

	if _, err := Client.DeleteOAuthApp(app.Id); err != nil {
		t.Fatal(err)
	}

	app = &model.OAuthApp{Name: "TestApp5" + model.NewId(), Homepage: "https://nowhere.com", Description: "test", CallbackUrls: []string{"https://nowhere.com"}}

	app = Client.Must(Client.RegisterApp(app)).Data.(*model.OAuthApp)

	if _, err := AdminClient.DeleteOAuthApp(app.Id); err != nil {
		t.Fatal(err)
	}
}
