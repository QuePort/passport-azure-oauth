# Passport-Azure-OAuth

[Passport](http://passportjs.org/) strategy for authenticating with [Azure](https://login.windows.net/common/oauth2) OAuth 2.0 API.

This module lets you authenticate using Azure in your Node.js applications.
By plugging into Passport, Azure / Office 365 authentication can be easily and unobtrusively integrated into any application or framework that supports [Connect](http://www.senchalabs.org/connect/)-style middleware, including [Express](http://expressjs.com/).

## Installation

    $ npm install passport-azure-oauth

## Usage

#### Configure Strategy

The Azure authentication strategy authenticates users using a Azure / Microsoft Office 365
account using OAuth 2.0.  The strategy requires a `verify` callback, which
accepts these credentials and calls `done` providing a user, as well as
`options` specifying a client ID, client secret, tenant id, resource and redirect URL.

    passport.use(new AzureOAuthStrategy({
        clientId	: AzureOAuth_ClientId,
    	clientSecret: AzureOAuth_ClientSecret,
		tenantId 	: AzureOAuth_AppTenantId,
		resource 	: AzureOAuth_AuthResource,
		redirectURL : AzureOAuth_RedirectURL,
		proxy : {
			host : 'myProxyHost',
			port : 'myProxyPort',
			protocol : 'https' // http / https
		}
      },
      function(accessToken, refreshToken, profile, done) {
      	return done(err, user);
      }
    ));

* clientId : Id of the registered azure online application.
* clientSecret : Password of the registered azure online application.
* tenantId : Open Azure Online, navigate to the application, click on "VIEW ENDPOINTS", copy the GUID after the host url.
* resource : Url to the Azure / Office 365 resource your app wants to access.
	* e.g.: "https://outlook.office365.com/" to access Office 365 Mail Api
* redirectURL : The redirect url after the authentication. </br>
You can pass additional parameters to your "passport use", to work with them in your callback action.
All parameters given in the new AzureOAuthStrategy({ }) will be passed to your redirectURL.
E.g 
	```javascript  

        clientId	: AzureOAuth_ClientId,
    	clientSecret: AzureOAuth_ClientSecret,
		tenantId 	: AzureOAuth_AppTenantId,
		resource 	: AzureOAuth_AuthResource,
		redirectURL : AzureOAuth_RedirectURL,
		proxy : {
			host : 'myProxyHost',
			port : 'myProxyPort',
			protocol : 'https' // http / https
		},
		myParameter : 'Im a parameter'

    ));
	```  

The callback url looks like <br>
	
	"redirectURL + '?redirectUrl=' + redirectUrl + "&" + myParameter="Im a parameter"

* The proxy settings passed through the oauth2 module, wich handles the authorization requests.

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'azureoauth'` strategy, to
authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

    app.get('/auth/azureOAuth',
      passport.authenticate('azureoauth'),
      function(req, res){
        // The request will be redirected to SharePoint for authentication, so
        // this function will not be called.
      });

    app.get('/auth/azureOAuth/callback', 
      passport.authenticate('azureoauth', { 
		failureRedirect: '/login',
		refreshToken: azureOAuth_RefreshToken 
	  }),
      function(req, res) {
        // Successful authentication, redirect home.
        res.redirect('/');
      });

* refreshToken : After one initial authentication, you get a refresh token. You can pass it to the authenticate method to simply renew your access token without a new callback.
## Credits

  - [QuePort](https://github.com/QuePort)
  - [Thomas Herbst](https://github.com/macrauder)
  - [Tobias Winkler](https://github.com/Tschuck)

## License

(The MIT License)

Copyright (c) 2013 Thomas Herbst / QuePort

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
