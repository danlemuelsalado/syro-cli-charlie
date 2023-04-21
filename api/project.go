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

func ValidateProjectId(companyId string, memberId string, projectId string, sessionToken string) (isProjectIdValid bool, err error) {
	client := resty.New()
	requestBody := fmt.Sprintf(`{"companyId":"%s", "memberId":"%s", "projectId":"%s", "sessionToken":"%s"}`, companyId, memberId, projectId, sessionToken)

	response, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("X-Parse-Application-Id", "paysail_local_app_id").
		SetHeader("X-Parse-REST-API-Key", "paysail_local_app_master_key").
		SetBody(requestBody).
		Post("http://localhost:1337/v1/functions/cli_validate_project_id")

	if err != nil {
		fmt.Printf("Something went wrong while validating project ID.")
		fmt.Printf("Error :: %v", err)
		return false, err
	}

	validateProjectIdResponse := model.ValidateProjectIdResponse{}
	if err := json.Unmarshal(response.Body(), &validateProjectIdResponse); err != nil {
		fmt.Printf("Could not unmarshal response from the validate project ID request.")
		fmt.Printf("Error :: %v", err)
		return false, err
	}

	if len(validateProjectIdResponse.Error) > 0 {
		return false, errors.New(validateProjectIdResponse.Error)
	}

	return validateProjectIdResponse.Result.IsProjectIdValid, nil
}

func FetchProjectItems(companyId string, memberId string, projectId string, sessionToken string) (secrets []model.ItemDetails, err error) {
	client := resty.New()
	requestBody := fmt.Sprintf(`{"companyId":"%s", "memberId":"%s", "projectId":"%s", "sessionToken":"%s"}`, companyId, memberId, projectId, sessionToken)

	response, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("X-Parse-Application-Id", "paysail_local_app_id").
		SetHeader("X-Parse-REST-API-Key", "paysail_local_app_master_key").
		SetBody(requestBody).
		Post("http://localhost:1337/v1/functions/cli_project_items")

	if err != nil {
		fmt.Printf("Something went wrong while fetching project secrets.")
		fmt.Printf("Error :: %v", err)
		return []model.ItemDetails{}, err
	}

	fetchProjectSecretsResponse := model.FetchProjectSecretsResponse{}
	if err := json.Unmarshal(response.Body(), &fetchProjectSecretsResponse); err != nil {
		fmt.Printf("Could not unmarshal response from the fetch project secrets request.")
		fmt.Printf("Error :: %v", err)
		return []model.ItemDetails{}, err
	}

	if len(fetchProjectSecretsResponse.Error) > 0 {
		return []model.ItemDetails{}, errors.New(fetchProjectSecretsResponse.Error)
	}

	return fetchProjectSecretsResponse.Result.Items, nil
}

func PullProjectItems(accessToken string, companyId string, projectId string) (secrets []model.ItemDetails, err error) {
	client := resty.New()
	requestBody := fmt.Sprintf(`{"accessToken":"%s", "companyId":"%s", "projectId":"%s"}`, accessToken, companyId, projectId)

	response, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("X-Parse-Application-Id", "paysail_local_app_id").
		SetHeader("X-Parse-REST-API-Key", "paysail_local_app_master_key").
		SetBody(requestBody).
		Post("http://localhost:1337/v1/functions/cli_pull_project_items")

	if err != nil {
		fmt.Printf("Something went wrong while pulling project secrets.")
		fmt.Printf("Error :: %v", err)
		return []model.ItemDetails{}, err
	}

	pullProjectSecretsResponse := model.FetchProjectSecretsResponse{}
	if err := json.Unmarshal(response.Body(), &pullProjectSecretsResponse); err != nil {
		fmt.Printf("Could not unmarshal response from the pull project secrets request.")
		fmt.Printf("Error :: %v", err)
		return []model.ItemDetails{}, err
	}

	if len(pullProjectSecretsResponse.Error) > 0 {
		return []model.ItemDetails{}, errors.New(pullProjectSecretsResponse.Error)
	}

	return pullProjectSecretsResponse.Result.Items, nil
}
