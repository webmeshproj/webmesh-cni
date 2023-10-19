/*
Copyright 2023 Avi Zimmerman <avi.zimmerman@gmail.com>.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package metadata

import (
	"time"

	"github.com/google/uuid"
	"github.com/zitadel/oidc/pkg/oidc"
	"golang.org/x/text/language"
)

// AuthRequest implements the op.AuthRequest interface.
type AuthRequest struct {
	ID            string
	CreationDate  time.Time
	ApplicationID string
	CallbackURI   string
	TransferState string
	Prompt        []string
	UiLocales     []language.Tag
	LoginHint     string
	MaxAuthAge    *time.Duration
	UserID        string
	Scopes        []string
	ResponseType  oidc.ResponseType
	Nonce         string
	CodeChallenge *oidc.CodeChallenge

	done     bool
	authTime time.Time
}

// NewAuthRequest creates an auth request from an oidc.AuthRequest.
func NewAuthRequest(req *oidc.AuthRequest, userID string) *AuthRequest {
	return &AuthRequest{
		ID:            uuid.NewString(),
		CreationDate:  time.Now(),
		ApplicationID: req.ClientID,
		CallbackURI:   req.RedirectURI,
		TransferState: req.State,
		Prompt:        promptToInternal(req.Prompt),
		UiLocales:     req.UILocales,
		LoginHint:     req.LoginHint,
		MaxAuthAge:    maxAgeToInternal(req.MaxAge),
		UserID:        userID,
		Scopes:        req.Scopes,
		ResponseType:  req.ResponseType,
		Nonce:         req.Nonce,
		CodeChallenge: &oidc.CodeChallenge{
			Challenge: req.CodeChallenge,
			Method:    req.CodeChallengeMethod,
		},
	}
}

func promptToInternal(oidcPrompt oidc.SpaceDelimitedArray) []string {
	prompts := make([]string, len(oidcPrompt))
	for _, oidcPrompt := range oidcPrompt {
		switch oidcPrompt {
		case oidc.PromptNone,
			oidc.PromptLogin,
			oidc.PromptConsent,
			oidc.PromptSelectAccount:
			prompts = append(prompts, oidcPrompt)
		}
	}
	return prompts
}

func maxAgeToInternal(maxAge *uint) *time.Duration {
	if maxAge == nil {
		return nil
	}
	dur := time.Duration(*maxAge) * time.Second
	return &dur
}

func (a *AuthRequest) GetID() string {
	return a.ID
}

func (a *AuthRequest) GetACR() string {
	// We won't handle acr in this example
	return ""
}

func (a *AuthRequest) GetAMR() []string {
	if a.done {
		// We use user presence as an amr value
		return []string{"user"}
	}
	return nil
}

func (a *AuthRequest) GetAudience() []string {
	return []string{a.ApplicationID} // this example will always just use the client_id as audience
}

func (a *AuthRequest) GetAuthTime() time.Time {
	return a.authTime
}

func (a *AuthRequest) GetClientID() string {
	return a.ApplicationID
}

func (a *AuthRequest) GetCodeChallenge() *oidc.CodeChallenge {
	return &oidc.CodeChallenge{
		Challenge: a.CodeChallenge.Challenge,
		Method:    oidc.CodeChallengeMethod(a.CodeChallenge.Method),
	}
}

func (a *AuthRequest) GetNonce() string {
	return a.Nonce
}

func (a *AuthRequest) GetRedirectURI() string {
	return a.CallbackURI
}

func (a *AuthRequest) GetResponseType() oidc.ResponseType {
	return a.ResponseType
}

func (a *AuthRequest) GetResponseMode() oidc.ResponseMode {
	return "" // we won't handle response mode in this example
}

func (a *AuthRequest) GetScopes() []string {
	return a.Scopes
}

func (a *AuthRequest) GetState() string {
	return a.TransferState
}

func (a *AuthRequest) GetSubject() string {
	return a.UserID
}

func (a *AuthRequest) Done() bool {
	return a.done
}
