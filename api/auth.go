/*
Copyright © 2023 Syro team <info@syro.com>
*/
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"syro/model"

	"github.com/go-resty/resty/v2"
)

func Login(email string, password string) (companyId string, expiresAt string, memberId string, sessionToken string, err error) {
	client := resty.New()
	requestBody := fmt.Sprintf(`{"email":"%s", "password":"%s"}`, email, password)

	response, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("X-Parse-Application-Id", "paysail_local_app_id").
		SetHeader("X-Parse-REST-API-Key", "paysail_local_app_master_key").
		SetBody(requestBody).
		Post("http://localhost:1337/v1/functions/cli_login")

	if err != nil {
		fmt.Printf("Something went wrong while authenticating.")
		fmt.Printf("Error :: %v", err)
		return "", "", "", "", err
	}

	loginResponse := model.LoginResponse{}
	if err := json.Unmarshal(response.Body(), &loginResponse); err != nil {
		fmt.Printf("Could not unmarshal response from authentication.")
		fmt.Printf("Error :: %v", err)
		return "", "", "", "", err
	}

	if len(loginResponse.Error) > 0 {
		return "", "", "", "", errors.New(loginResponse.Error)
	}

	return loginResponse.Result.CompanyId, loginResponse.Result.ExpiresAt, loginResponse.Result.MemberId, loginResponse.Result.SessionToken, nil
}

func ValidateAccessTokenAndProjectId(accessToken string, projectId string) (companyId string, verifiedAccessToken string, verifiedProjectId string, err error) {
	client := resty.New()
	requestBody := fmt.Sprintf(`{"accessToken":"%s", "projectId":"%s"}`, accessToken, projectId)

	response, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("X-Parse-Application-Id", "paysail_local_app_id").
		SetHeader("X-Parse-REST-API-Key", "paysail_local_app_master_key").
		SetBody(requestBody).
		Post("http://localhost:1337/v1/functions/cli_validate_access_token_and_project_id")

	if err != nil {
		fmt.Printf("Something went wrong while validating your access token and project ID.")
		fmt.Printf("Error :: %v", err)
		return "", "", "", err
	}

	validateAccessTokenAndProjectIdResponse := model.ValidateAccessTokenAndProjectIdResponse{}
	if err := json.Unmarshal(response.Body(), &validateAccessTokenAndProjectIdResponse); err != nil {
		fmt.Printf("Could not unmarshal response from validate access token and project ID request.")
		fmt.Printf("Error :: %v", err)
		return "", "", "", err
	}

	if len(validateAccessTokenAndProjectIdResponse.Error) > 0 {
		return "", "", "", errors.New(validateAccessTokenAndProjectIdResponse.Error)
	}

	return validateAccessTokenAndProjectIdResponse.Result.CompanyId, validateAccessTokenAndProjectIdResponse.Result.VerifiedAccessToken, validateAccessTokenAndProjectIdResponse.Result.VerifiedProjectId, nil
}

func ValidateSessionToken(sessionToken string) (isSessionTokenValid bool, err error) {
	client := resty.New()
	requestBody := fmt.Sprintf(`{"sessionToken":"%s"}`, sessionToken)

	response, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("X-Parse-Application-Id", "paysail_local_app_id").
		SetHeader("X-Parse-REST-API-Key", "paysail_local_app_master_key").
		SetBody(requestBody).
		Post("http://localhost:1337/v1/functions/cli_validate_session_token")

	if err != nil {
		fmt.Printf("Something went wrong while validating your session token.")
		fmt.Printf("Error :: %v", err)
		return false, err
	}

	validateSessionTokenResponse := model.ValidateSessionTokenResponse{}
	if err := json.Unmarshal(response.Body(), &validateSessionTokenResponse); err != nil {
		fmt.Printf("Could not unmarshal response from validate session token request.")
		fmt.Printf("Error :: %v", err)
		return false, err
	}

	if len(validateSessionTokenResponse.Error) > 0 {
		return false, errors.New(validateSessionTokenResponse.Error)
	}

	return validateSessionTokenResponse.Result.IsSessionTokenValid, nil
}
