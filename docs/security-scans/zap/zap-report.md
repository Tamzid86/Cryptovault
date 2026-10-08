# ZAP Scanning Report

ZAP by [Checkmarx](https://checkmarx.com/).


## Summary of Alerts

| Risk Level | Number of Alerts |
| --- | --- |
| High | 0 |
| Medium | 0 |
| Low | 0 |
| Informational | 5 |




## Insights

| Level | Reason | Site | Description | Statistic |
| --- | --- | --- | --- | --- |
| Low | Exceeded High | http://host.docker.internal:8000 | Percentage of responses with status code 4xx | 99 % |
| Info | Informational | http://host.docker.internal:8000 | Percentage of endpoints with content type application/json | 100 % |
| Info | Informational | http://host.docker.internal:8000 | Percentage of endpoints with method DELETE | 4 % |
| Info | Informational | http://host.docker.internal:8000 | Percentage of endpoints with method GET | 61 % |
| Info | Informational | http://host.docker.internal:8000 | Percentage of endpoints with method POST | 32 % |
| Info | Informational | http://host.docker.internal:8000 | Percentage of endpoints with method PUT | 2 % |
| Info | Informational | http://host.docker.internal:8000 | Count of total endpoints | 96    |







## Alerts

| Name | Risk Level | Number of Instances |
| --- | --- | --- |
| A Client Error response code was returned by the server | Informational | 101 |
| Authentication Request Identified | Informational | 1 |
| Information Disclosure - Sensitive Information in URL | Informational | 1 |
| Non-Storable Content | Informational | Systemic |
| Storable and Cacheable Content | Informational | 1 |




## Alert Detail



### [ A Client Error response code was returned by the server ](https://www.zaproxy.org/docs/alerts/100000/)



##### Informational (High)

### Description

A response code of 422 was returned by the server.
This may indicate that the application is failing to handle unexpected input correctly.
Raised by the 'Alert on HTTP Response Code Error' script

* URL: http://host.docker.internal:8000/api/v1/files/file_id
  * Node Name: `http://host.docker.internal:8000/api/v1/files/file_id`
  * Method: `DELETE`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/files/file_id/
  * Node Name: `http://host.docker.internal:8000/api/v1/files/file_id/`
  * Method: `DELETE`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/files/file_id/shares/recipient_id
  * Node Name: `http://host.docker.internal:8000/api/v1/files/file_id/shares/recipient_id`
  * Method: `DELETE`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/files/file_id/shares/recipient_id/
  * Node Name: `http://host.docker.internal:8000/api/v1/files/file_id/shares/recipient_id/`
  * Method: `DELETE`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``
* URL: http://host.docker.internal:8000
  * Node Name: `http://host.docker.internal:8000`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/
  * Node Name: `http://host.docker.internal:8000/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/4058836585463187070
  * Node Name: `http://host.docker.internal:8000/4058836585463187070`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api
  * Node Name: `http://host.docker.internal:8000/api`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/
  * Node Name: `http://host.docker.internal:8000/api/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/1018531955149156856
  * Node Name: `http://host.docker.internal:8000/api/1018531955149156856`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1
  * Node Name: `http://host.docker.internal:8000/api/v1`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/
  * Node Name: `http://host.docker.internal:8000/api/v1/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/186601538922823577
  * Node Name: `http://host.docker.internal:8000/api/v1/186601538922823577`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth
  * Node Name: `http://host.docker.internal:8000/api/v1/auth`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/2366365275070156252
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/2366365275070156252`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/login
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/login`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `405`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/login/
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/login/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `405`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/login/326322551019989277
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/login/326322551019989277`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/login/mfa
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/login/mfa`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/login/mfa/
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/login/mfa/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/login/mfa/7832510561039521089
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/login/mfa/7832510561039521089`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/login/mfa/actuator/health
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/login/mfa/actuator/health`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/totp
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/totp`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/totp/
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/totp/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/totp/2412946469193441767
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/totp/2412946469193441767`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/webauthn
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/webauthn`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/webauthn/
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/webauthn/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/webauthn/3771991553900887163
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/webauthn/3771991553900887163`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/webauthn/login
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/webauthn/login`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/webauthn/login/
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/webauthn/login/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/webauthn/login/8230203974200297776
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/webauthn/login/8230203974200297776`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/webauthn/register
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/webauthn/register`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/webauthn/register/
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/webauthn/register/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/webauthn/register/6823709376597686051
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/webauthn/register/6823709376597686051`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/files
  * Node Name: `http://host.docker.internal:8000/api/v1/files`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/files/
  * Node Name: `http://host.docker.internal:8000/api/v1/files/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/files/4689928945892212034
  * Node Name: `http://host.docker.internal:8000/api/v1/files/4689928945892212034`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `405`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/files/file_id
  * Node Name: `http://host.docker.internal:8000/api/v1/files/file_id`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `405`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/files/file_id/
  * Node Name: `http://host.docker.internal:8000/api/v1/files/file_id/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `405`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/files/file_id/2340704125073564566
  * Node Name: `http://host.docker.internal:8000/api/v1/files/file_id/2340704125073564566`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/files/file_id/chunks
  * Node Name: `http://host.docker.internal:8000/api/v1/files/file_id/chunks`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/files/file_id/chunks/
  * Node Name: `http://host.docker.internal:8000/api/v1/files/file_id/chunks/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/files/file_id/chunks/10
  * Node Name: `http://host.docker.internal:8000/api/v1/files/file_id/chunks/10`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/files/file_id/chunks/10/
  * Node Name: `http://host.docker.internal:8000/api/v1/files/file_id/chunks/10/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/files/file_id/chunks/6100567012594240062
  * Node Name: `http://host.docker.internal:8000/api/v1/files/file_id/chunks/6100567012594240062`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/files/file_id/shares
  * Node Name: `http://host.docker.internal:8000/api/v1/files/file_id/shares`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/files/file_id/shares/
  * Node Name: `http://host.docker.internal:8000/api/v1/files/file_id/shares/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/files/file_id/shares/4119842272728907115
  * Node Name: `http://host.docker.internal:8000/api/v1/files/file_id/shares/4119842272728907115`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `405`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/users
  * Node Name: `http://host.docker.internal:8000/api/v1/users`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/users/
  * Node Name: `http://host.docker.internal:8000/api/v1/users/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/users/4998171271653281301
  * Node Name: `http://host.docker.internal:8000/api/v1/users/4998171271653281301`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/users/lookup
  * Node Name: `http://host.docker.internal:8000/api/v1/users/lookup`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/users/lookup%3Femail=zaproxy@example.com
  * Node Name: `http://host.docker.internal:8000/api/v1/users/lookup (email)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/users/lookup/
  * Node Name: `http://host.docker.internal:8000/api/v1/users/lookup/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/users/me
  * Node Name: `http://host.docker.internal:8000/api/v1/users/me`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/users/me/
  * Node Name: `http://host.docker.internal:8000/api/v1/users/me/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/users/me/4303601932200955026
  * Node Name: `http://host.docker.internal:8000/api/v1/users/me/4303601932200955026`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/users/me/login-events
  * Node Name: `http://host.docker.internal:8000/api/v1/users/me/login-events`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/users/me/login-events/
  * Node Name: `http://host.docker.internal:8000/api/v1/users/me/login-events/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/users/me/mfa-status
  * Node Name: `http://host.docker.internal:8000/api/v1/users/me/mfa-status`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/users/me/mfa-status/
  * Node Name: `http://host.docker.internal:8000/api/v1/users/me/mfa-status/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/login
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/login ()({email,password})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/login
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/login ()({email,password})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/login
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/login ()({email,password})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `429`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/login/
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/login/ ()({email,password})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `429`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/login/mfa/totp
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/login/mfa/totp ()({mfa_token,code})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/login/mfa/totp
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/login/mfa/totp ()({mfa_token,code})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `429`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/login/mfa/totp/
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/login/mfa/totp/ ()({mfa_token,code})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `429`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/register
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/register ()({email,password,public_key,encrypted_private_key,private_key_kdf_salt,private_key_nonce})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `400`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/register
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/register ()({email,password,public_key,encrypted_private_key,private_key_kdf_salt,private_key_nonce})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/register
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/register ()({email,password,public_key,encrypted_private_key,private_key_kdf_salt,private_key_nonce})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `429`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/register/
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/register/ ()({email,password,public_key,encrypted_private_key,private_key_kdf_salt,private_key_nonce})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/totp/disable
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/totp/disable ()({password})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/totp/disable/
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/totp/disable/ ()({password})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/totp/setup
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/totp/setup`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/totp/setup/
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/totp/setup/`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/totp/verify
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/totp/verify ()({code})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/totp/verify/
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/totp/verify/ ()({code})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/webauthn/login/options
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/webauthn/login/options ()({mfa_token})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/webauthn/login/options
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/webauthn/login/options ()({mfa_token})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `429`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/webauthn/login/options/
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/webauthn/login/options/ ()({mfa_token})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `429`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/webauthn/login/verify
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/webauthn/login/verify ()({mfa_token,credential})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/webauthn/login/verify/
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/webauthn/login/verify/ ()({mfa_token,credential})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/webauthn/register/options
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/webauthn/register/options`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/webauthn/register/options/
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/webauthn/register/options/`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/webauthn/register/verify
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/webauthn/register/verify ()({credential})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/webauthn/register/verify/
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/webauthn/register/verify/ ()({credential})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/files
  * Node Name: `http://host.docker.internal:8000/api/v1/files ()({encrypted_filename,filename_nonce,size_bytes,chunk_size,num_chunks,ephemeral_public_key,wrapped_key,wrap_nonce})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/files/
  * Node Name: `http://host.docker.internal:8000/api/v1/files/ ()({encrypted_filename,filename_nonce,size_bytes,chunk_size,num_chunks,ephemeral_public_key,wrapped_key,wrap_nonce})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/files/file_id/shares
  * Node Name: `http://host.docker.internal:8000/api/v1/files/file_id/shares ()({recipient_email,ephemeral_public_key,wrapped_key,wrap_nonce})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/files/file_id/shares/
  * Node Name: `http://host.docker.internal:8000/api/v1/files/file_id/shares/ ()({recipient_email,ephemeral_public_key,wrapped_key,wrap_nonce})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``
* URL: http://host.docker.internal:8000/computeMetadata/v1/
  * Node Name: `http://host.docker.internal:8000/computeMetadata/v1/ ()({mfa_token,code})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/latest/meta-data/
  * Node Name: `http://host.docker.internal:8000/latest/meta-data/ ()({mfa_token,code})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/metadata/instance
  * Node Name: `http://host.docker.internal:8000/metadata/instance ()({mfa_token,code})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/metadata/v1
  * Node Name: `http://host.docker.internal:8000/metadata/v1 ()({mfa_token,code})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/opc/v1/instance/
  * Node Name: `http://host.docker.internal:8000/opc/v1/instance/ ()({mfa_token,code})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/opc/v2/instance/
  * Node Name: `http://host.docker.internal:8000/opc/v2/instance/ ()({mfa_token,code})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/openstack/latest/meta_data.json
  * Node Name: `http://host.docker.internal:8000/openstack/latest/meta_data.json ()({mfa_token,code})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/files/file_id/chunks/10
  * Node Name: `http://host.docker.internal:8000/api/v1/files/file_id/chunks/10`
  * Method: `PUT`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/files/file_id/chunks/10/
  * Node Name: `http://host.docker.internal:8000/api/v1/files/file_id/chunks/10/`
  * Method: `PUT`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``


Instances: 101

### Solution



### Reference



#### CWE Id: [ 388 ](https://cwe.mitre.org/data/definitions/388.html)


#### WASC Id: 20

#### Source ID: 4

### [ Authentication Request Identified ](https://www.zaproxy.org/docs/alerts/10111/)



##### Informational (High)

### Description

The given request has been identified as an authentication request. The 'Other Info' field contains a set of key=value lines which identify any relevant fields. If the request is in a context which has an Authentication Method set to "Auto-Detect" then this rule will change the authentication to match the request identified.

* URL: http://host.docker.internal:8000/api/v1/auth/login
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/login ()({email,password})`
  * Method: `POST`
  * Parameter: `email`
  * Attack: ``
  * Evidence: `password`
  * Other Info: `userParam=email
userValue=zaproxy@example.com
passwordParam=password`


Instances: 1

### Solution

This is an informational alert rather than a vulnerability and so there is nothing to fix.

### Reference


* [ https://www.zaproxy.org/docs/desktop/addons/authentication-helper/auth-req-id/ ](https://www.zaproxy.org/docs/desktop/addons/authentication-helper/auth-req-id/)



#### Source ID: 3

### [ Information Disclosure - Sensitive Information in URL ](https://www.zaproxy.org/docs/alerts/10024/)



##### Informational (Medium)

### Description

The request appeared to contain sensitive information leaked in the URL. This can violate PCI and most organizational compliance policies. You can configure the list of strings for this check to add or remove values specific to your environment.

* URL: http://host.docker.internal:8000/api/v1/users/lookup%3Femail=zaproxy@example.com
  * Node Name: `http://host.docker.internal:8000/api/v1/users/lookup (email)`
  * Method: `GET`
  * Parameter: `email`
  * Attack: ``
  * Evidence: `zaproxy@example.com`
  * Other Info: `The URL contains email address(es).`


Instances: 1

### Solution

Do not pass sensitive information in URIs.

### Reference



#### CWE Id: [ 598 ](https://cwe.mitre.org/data/definitions/598.html)


#### WASC Id: 13

#### Source ID: 3

### [ Non-Storable Content ](https://www.zaproxy.org/docs/alerts/10049/)



##### Informational (Medium)

### Description

The response contents are not storable by caching components such as proxy servers. If the response does not contain sensitive, personal or user-specific information, it may benefit from being stored and cached, to improve performance.

* URL: http://host.docker.internal:8000/api/v1/files/file_id
  * Node Name: `http://host.docker.internal:8000/api/v1/files/file_id`
  * Method: `DELETE`
  * Parameter: ``
  * Attack: ``
  * Evidence: `DELETE `
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/files
  * Node Name: `http://host.docker.internal:8000/api/v1/files`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/files/file_id/chunks/10
  * Node Name: `http://host.docker.internal:8000/api/v1/files/file_id/chunks/10`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/auth/login/mfa/totp
  * Node Name: `http://host.docker.internal:8000/api/v1/auth/login/mfa/totp ()({mfa_token,code})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/files
  * Node Name: `http://host.docker.internal:8000/api/v1/files ()({encrypted_filename,filename_nonce,size_bytes,chunk_size,num_chunks,ephemeral_public_key,wrapped_key,wrap_nonce})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``

Instances: Systemic


### Solution

The content may be marked as storable by ensuring that the following conditions are satisfied:
The request method must be understood by the cache and defined as being cacheable ("GET", "HEAD", and "POST" are currently defined as cacheable)
The response status code must be understood by the cache (one of the 1XX, 2XX, 3XX, 4XX, or 5XX response classes are generally understood)
The "no-store" cache directive must not appear in the request or response header fields
For caching by "shared" caches such as "proxy" caches, the "private" response directive must not appear in the response
For caching by "shared" caches such as "proxy" caches, the "Authorization" header field must not appear in the request, unless the response explicitly allows it (using one of the "must-revalidate", "public", or "s-maxage" Cache-Control response directives)
In addition to the conditions above, at least one of the following conditions must also be satisfied by the response:
It must contain an "Expires" header field
It must contain a "max-age" response directive
For "shared" caches such as "proxy" caches, it must contain a "s-maxage" response directive
It must contain a "Cache Control Extension" that allows it to be cached
It must have a status code that is defined as cacheable by default (200, 203, 204, 206, 300, 301, 404, 405, 410, 414, 501).

### Reference


* [ https://datatracker.ietf.org/doc/html/rfc7234 ](https://datatracker.ietf.org/doc/html/rfc7234)
* [ https://datatracker.ietf.org/doc/html/rfc7231 ](https://datatracker.ietf.org/doc/html/rfc7231)
* [ https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html ](https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html)


#### CWE Id: [ 524 ](https://cwe.mitre.org/data/definitions/524.html)


#### WASC Id: 13

#### Source ID: 3

### [ Storable and Cacheable Content ](https://www.zaproxy.org/docs/alerts/10049/)



##### Informational (Medium)

### Description

The response contents are storable by caching components such as proxy servers, and may be retrieved directly from the cache, rather than from the origin server by the caching servers, in response to similar requests from other users. If the response data is sensitive, personal or user-specific, this may result in sensitive information being leaked. In some cases, this may even result in a user gaining complete control of the session of another user, depending on the configuration of the caching components in use in their environment. This is primarily an issue where "shared" caching servers such as "proxy" caches are configured on the local network. This configuration is typically found in corporate or educational environments, for instance.

* URL: http://host.docker.internal:8000/health
  * Node Name: `http://host.docker.internal:8000/health`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `In the absence of an explicitly specified caching lifetime directive in the response, a liberal lifetime heuristic of 1 year was assumed. This is permitted by rfc7234.`


Instances: 1

### Solution

Validate that the response does not contain sensitive, personal or user-specific information. If it does, consider the use of the following HTTP response headers, to limit, or prevent the content being stored and retrieved from the cache by another user:
Cache-Control: no-cache, no-store, must-revalidate, private
Pragma: no-cache
Expires: 0
This configuration directs both HTTP 1.0 and HTTP 1.1 compliant caching servers to not store the response, and to not retrieve the response (without validation) from the cache, in response to a similar request.

### Reference


* [ https://datatracker.ietf.org/doc/html/rfc7234 ](https://datatracker.ietf.org/doc/html/rfc7234)
* [ https://datatracker.ietf.org/doc/html/rfc7231 ](https://datatracker.ietf.org/doc/html/rfc7231)
* [ https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html ](https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html)


#### CWE Id: [ 524 ](https://cwe.mitre.org/data/definitions/524.html)


#### WASC Id: 13

#### Source ID: 3


