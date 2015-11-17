# passport-azure-oauth Versions

## Version 0.1.2
- Remove check if a user is permitted on a special application; User from foreign tenants has no rights on all apps ==> they would never has permissions

## Version 0.1.1
- Add a check if a user is permitted on a special application; if not, return a noAccess Error (also return the profile, if you want to go further with the current authenticated user)

## Version 0.1.0
- Handle 'you have no access to any service' error

## Version 0.0.9
- Add "user" parameter to automatically fill the user input in the login page 

## Version 0.0.8
- Update azure login url to prevent a redirect from login.windows.net to login.microsoftonline.com

## Version 0.0.7
- Implement autodetection of available endpoints  for granted app permissions.

## Version 0.0.6
- fixed invalid grant error
- fixed always needed redirect url issue
- updates readme.md

## Version 0.0.3
- enable the opportunity to pass a redirectURL to your passport use
- now its possible to pass optional parameters to your passport use, to work with them in your callback action
- pass proxy settings to oauth call
- fix misspelling in profile => rawOjet to rawObject
- 

## Version 0.0.2
- json parse (ascii to utf-8)
- oauthazure strategy lowercase

## Version 0.0.1

- initial versions