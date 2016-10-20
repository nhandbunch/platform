// Copyright (c) 2015 Mattermost, Inc. All Rights Reserved.
// See License.txt for license information.

package model

import (
	"strings"
	"testing"
	"fmt"
	"github.com/pborman/uuid"
	"bytes"
	"encoding/base32"
)

func TestUUID(t *testing.T) {
	s := uuid.NewRandom().String()
	fmt.Println(s)

	var b bytes.Buffer
	encoder := base32.NewEncoder(encoding, &b)
	encoder.Write(s)
	encoder.Close()
	b.Truncate(26) // removes the '==' padding
	fmt.Println(b.String())

	var b1 bytes.Buffer
	encoder1 := base32.NewEncoder(encoding, &b1)
	encoder1.Write(s)
	encoder1.Close()
	//b.Truncate(26) // removes the '==' padding
	fmt.Println(b1.String())
}

func TestOAuthAppJson(t *testing.T) {
	a1 := OAuthApp{}
	a1.Id = NewId()
	a1.Name = "TestOAuthApp" + NewId()
	a1.CallbackUrls = []string{"https://nowhere.com"}
	a1.Homepage = "https://nowhere.com"
	a1.IconURL = "https://nowhere.com/icon_image.png"
	a1.ClientSecret = NewId()

	json := a1.ToJson()
	ra1 := OAuthAppFromJson(strings.NewReader(json))

	if a1.Id != ra1.Id {
		t.Fatal("ids did not match")
	}
}

func TestOAuthAppPreSave(t *testing.T) {
	a1 := OAuthApp{}
	a1.Id = NewId()
	a1.Name = "TestOAuthApp" + NewId()
	a1.CallbackUrls = []string{"https://nowhere.com"}
	a1.Homepage = "https://nowhere.com"
	a1.IconURL = "https://nowhere.com/icon_image.png"
	a1.ClientSecret = NewId()
	a1.PreSave()
	a1.Etag()
	a1.Sanitize()
}

func TestOAuthAppPreUpdate(t *testing.T) {
	a1 := OAuthApp{}
	a1.Id = NewId()
	a1.Name = "TestOAuthApp" + NewId()
	a1.CallbackUrls = []string{"https://nowhere.com"}
	a1.Homepage = "https://nowhere.com"
	a1.IconURL = "https://nowhere.com/icon_image.png"
	a1.ClientSecret = NewId()
	a1.PreUpdate()
}

func TestOAuthAppIsValid(t *testing.T) {
	app := OAuthApp{}

	if err := app.IsValid(); err == nil {
		t.Fatal()
	}

	app.Id = NewId()
	if err := app.IsValid(); err == nil {
		t.Fatal()
	}

	app.CreateAt = 1
	if err := app.IsValid(); err == nil {
		t.Fatal()
	}

	app.UpdateAt = 1
	if err := app.IsValid(); err == nil {
		t.Fatal()
	}

	app.CreatorId = NewId()
	if err := app.IsValid(); err == nil {
		t.Fatal()
	}

	app.ClientSecret = NewId()
	if err := app.IsValid(); err == nil {
		t.Fatal()
	}

	app.Name = "TestOAuthApp"
	if err := app.IsValid(); err == nil {
		t.Fatal()
	}

	app.CallbackUrls = []string{"https://nowhere.com"}
	if err := app.IsValid(); err == nil {
		t.Fatal()
	}

	app.Homepage = "https://nowhere.com"
	if err := app.IsValid(); err != nil {
		t.Fatal()
	}

	app.IconURL = "https://nowhere.com/icon_image.png"
	if err := app.IsValid(); err != nil {
		t.Fatal()
	}
}
