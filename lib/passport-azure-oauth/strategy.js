/**
 * Module dependencies.
 */
var passport = require('passport-strategy')
  , url = require('url')
  , https = require('https')
  , util = require('util')
  , utils = require('./utils')
  , jwt = require('jwt-simple')
  , OAuth2 = require('oauth').OAuth2
  , InternalOAuthError = require('./internaloautherror')
  , async = require('async');


/**
 * `Strategy` constructor.
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {}
  passport.Strategy.call(this);
  this.name = 'azureoauth';
  this._verify = verify;

  this._clientId = options.clientId;
  this._clientSecret = options.clientSecret;
  this._tenantId = options.tenantId;
  if (options.loginUrl) {
    this._loginUrl = options.loginUrl;
  } else {
    this._loginUrl = 'https://login.microsoftonline.com/';
  }
  if (options.authRelativeURL) {
    this._authRelativeURL = options.authRelativeURL;
  } else {
    this._authRelativeURL = '/oauth2/authorize';
  }
  if (options.tokenRelativeURL) {
    this._tokenRelativeURL = options.tokenRelativeURL;
  } else {
    this._tokenRelativeURL = '/oauth2/token';
  }
  if (options.redirectURL) {
    this.redirectURL = options.redirectURL;
  }
  if (options.proxy) {
    this.proxy = options.proxy;
  }
  if (options.user) {
    this.login_hint = options.user;
  }

  this._authURL = this._loginUrl + this._tenantId + this._authRelativeURL;
  this._tokenURL = this._loginUrl + this._tenantId + this._tokenRelativeURL;
  this._resource = options.resource;

  this._scopeSeparator = options.scopeSeparator || ' ';
  this._passReqToCallback = options.passReqToCallback;
  this._skipUserProfile = (options.skipUserProfile === undefined) ? false : options.skipUserProfile;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);


/**
 * Authenticate request by delegating to the Azure OAuth 2.0 provider.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var self = this;

  if (req != undefined && req.query && req.query.error) {
    // TODO: Error information pertaining to OAuth 2.0 flows is encoded in the
    //       query parameters, and should be propagated to the application.
    return this.fail();
  }

  // you can pass the appId and Secret in every round
  if (options.clientId)
    this._clientId = options.clientId;
  if (options.clientSecret)
    this._clientSecret = options.clientSecret;
  if (options.tenantId)
    this._tenantId = options.tenantId;

  if (options.loginUrl) {
    this._loginUrl = options.loginUrl;
  } else if (!this._loginUrl) {
    this._loginUrl = 'https://login.windows.net/';
  }

  if (options.authRelativeURL) {
    this._authRelativeURL = options.authRelativeURL;
  } else if (!this._authRelativeURL) {
    this._authRelativeURL = '/oauth2/authorize';
  }

  if (options.tokenRelativeURL) {
    this._tokenRelativeURL = options.tokenRelativeURL;
  } else if (!this._tokenRelativeURL) {
    this._tokenRelativeURL = '/oauth2/token';
  }
  if (options.redirectURL) {
    this.redirectURL = options.redirectURL;
  }
  if (options.proxy) {
    this.proxy = options.proxy;
  }
  if (options.user) {
    this.login_hint = options.user;
  }

  this._authURL = this._loginUrl + this._tenantId + this._authRelativeURL;
  this._tokenURL = this._loginUrl + this._tenantId + this._tokenRelativeURL;

  if (options.resource){
    this._resource = options.resource;
  } else {
    this._resource = "https://api.office.com/discovery/";
  }
  if (options.refreshToken)
    this._refreshToken = options.refreshToken;

  if (!this._clientId) throw new Error('AzureOAuthStrategy requires a clientId.');
  if (!this._clientSecret) throw new Error('AzureOAuthStrategy requires a clientSecret.');
  if (!this._tenantId) throw new Error('AzureOAuthStrategy requires a tenant id.');

  // check if there is a app token present
  if (typeof this._refreshToken != 'undefined') {
    var redirectURL = this.redirectURL;

    this._oauth2 = new OAuth2(this._clientId,  this._clientSecret, '', this._authURL, this._tokenURL, '', this.proxy);
    this._oauth2.getOAuthAccessToken(
        this._refreshToken,
        {grant_type: 'refresh_token', refresh_token: this._refreshToken, resource: this._resource, redirect_uri : redirectURL},
        function (err, accessToken, refreshToken, params) {
            if (err) { return self.error(new InternalOAuthError('failed to obtain access token', err)); }
            if (!refreshToken)
              refreshToken = self._refreshToken;

            self._loadUserProfile(accessToken, refreshToken, function(err, profile) {
              if (err) { return self.error(err); };

              function verified(err, user, info) {
                if (err) { return self.error(err); }
                if (!user) { return self.fail(info); }
                self.success(user, info);
              }

              if (self._passReqToCallback) {
                var arity = self._verify.length;
                if (arity == 6) {
                  self._verify(req, accessToken, refreshToken, params, profile, verified);
                } else { // arity == 5
                  self._verify(req, accessToken, refreshToken, profile, verified);
                }
              } else {
                var arity = self._verify.length;
                if (arity == 5) {
                  self._verify(accessToken, refreshToken, params, profile, verified);
                } else { // arity == 4
                  self._verify(accessToken, refreshToken, profile, verified);
                }
              }
            });
        });
  } else if (req != undefined && req.query && req.query.code) {
    this._oauth2    = new OAuth2(this._clientId, this._clientSecret, '', this._authURL, this._tokenURL, '', this.proxy);
    var code        = req.query.code;
    
    var requestParams = {};
    requestParams.grant_type = 'authorization_code';
    requestParams.resource = this._resource;
    if (this.redirectURL) {
      requestParams.redirect_uri =  this.redirectURL;
    }
    
    // NOTE: The module oauth (0.9.5), which is a dependency, automatically adds
    //       a 'type=web_server' parameter to the percent-encoded data sent in
    //       the body of the access token request.  This appears to be an
    //       artifact from an earlier draft of OAuth 2.0 (draft 22, as of the
    //       time of this writing).  This parameter is not necessary, but its
    //       presence does not appear to cause any issues.
    this._oauth2.getOAuthAccessToken(code, requestParams,
      function(err, accessToken, refreshToken, params) {
        if (err) { return self.error(new InternalOAuthError('failed to obtain access token', err)); }

        self._loadUserProfile(accessToken, refreshToken, function(err, profile) {
          if (err) { return self.error(err); };

          function verified(err, user, info) {
            if (err) { return self.error(err); }
            if (!user) { return self.fail(info); }
            self.success(user, info);
          }

          if (self._passReqToCallback) {
            var arity = self._verify.length;
            if (arity == 6) {
              self._verify(req, accessToken, refreshToken, params, profile, verified);
            } else { // arity == 5
              self._verify(req, accessToken, refreshToken, profile, verified);
            }
          } else {
            var arity = self._verify.length;
            if (arity == 5) {
              self._verify(accessToken, refreshToken, params, profile, verified);
            } else { // arity == 4
              self._verify(accessToken, refreshToken, profile, verified);
            }
          }
        });
      }
    );
  } else {
    this._oauth2 = new OAuth2(this._clientId,  this._clientSecret, '', this._authURL, this._tokenURL, '', this.proxy);
    var params = this.authorizationParams(options);
    params['response_type'] = 'code';
    if (this.redirectURL) {
      params['redirect_uri'] = this.redirectURL;
    }
    var scope = options.scope || this._scope;
    if (scope) {
      if (Array.isArray(scope)) { scope = scope.join(this._scopeSeparator); }
      params.scope = scope;
    }
    if (options.state) { params.state = options.state; }
    if (options.user) { params.login_hint = options.user; delete params.user;}

    var location = this._oauth2.getAuthorizeUrl(params);
    this.redirect(location);
  }
}

/**
 * Retrieve user profile from Azure.
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(accessToken, refreshToken, done) {
  var profile = { provider : 'azureoauth'};
  //try get user informations from the accessToken
  try {
    var stringUserInfo = new Buffer(accessToken.split('.')[1], 'base64').toString('utf-8');
    profile.raw = stringUserInfo;
    var objUserInfo = JSON.parse(stringUserInfo);
    profile.rawObject = objUserInfo;
    profile.username = objUserInfo.unique_name;
    profile.displayname = objUserInfo.given_name + ' ' + objUserInfo.family_name;
  } catch(exception) {
    console.log("Can't get profile informations!");
    return done('Authentication failed during Profile parsing: ' + exception , null);
  }

  if(this._resource === "https://api.office.com/discovery/"){
    profile.endpoints = {}; 
    var headers = {
      'Authorization' : 'BEARER ' + accessToken
    };
    var options = {
      host : "api.office.com", 
      path : '/discovery/v1.0/me/services',
      method : 'GET',
      headers : headers
    };
    var that = this;

    //get all service endpoints
    sendRestRequest(options, function(err, services) {
      if (services) {
        async.each(services, function(item, callback) {
          that._oauth2.getOAuthAccessToken(refreshToken, {
            grant_type: 'refresh_token', 
            refresh_token: refreshToken, 
            resource: item.serviceResourceId
          },
            function (err, accessToken, refreshToken, params) {
              if(err){
                console.log('Error getting Access Token for Service: '+item.serviceName+ ' -> '+err);
              } else {
                profile.endpoints[item.entityKey] = {
                  accessToken: accessToken,
                  serviceName : item.serviceName,
                  serviceEndpointUri: item.serviceEndpointUri
                };
              }
              callback();
          });
        }, function() {
          done(null, profile);
        });
      } else {
        done(null, profile);
      }
    });
  } else {
    done(null, profile);
  }
};

/**
 * Check if the current user is allowed to use this application.
 */
var isUserPermittedForApp = function(graphEndpoint, profile, callback) {
  var headers = {
    'Authorization' : 'BEARER ' + graphEndpoint.accessToken
  };

  var roleAssignmentOpts = {
    host : 'graph.windows.net', 
    path : '/me/appRoleAssignments?api-version=1.6',
    method : 'GET',
    headers : headers
  };

  var appOpts = {
    host : 'graph.windows.net', 
    path : '/' + profile.rawObject.tid + '/applications?api-version=1.6',
    method : 'GET',
    headers : headers
  };

  //get all role assignments for the current user
  sendRestRequest(roleAssignmentOpts, function(err, roleAssignments) {
    if (roleAssignments && Array.isArray(roleAssignments) && roleAssignments.length > 0) {
      //get all apps that exists
      sendRestRequest(appOpts, function(err, apps) {
        if (apps && Array.isArray(apps)) {
          //iterate through all existing apps and check if the current app id exists
          for (var i = 0; i < apps.length; i++) {
            if (apps[i].appId === profile.rawObject.appid) {
              //get the display name of the application to check it against the role assignments
              var appName = apps[i].displayName;
              for (var x = 0; x < roleAssignments.length; x++) {
                //if an role assignment with the current appname exists, return isPermitted = true
                if (appName === roleAssignments[x].resourceDisplayName) {
                  callback(null, true);
                  return;
                }
              }
            }
          }
          //if no role assignment was found, return isPermitted = false
          callback(null, false);
        } else {
          callback(err, false);
        }
      });
    } else {
      callback(err, false);
    }
  });
};

//Send a rest request and parse the result value as json.
var sendRestRequest = function(options, callback) {
  var req = https.get(options, function(res) {
    res.setEncoding('utf8');
    var result = '';
    
    res.on('data', function(data) {
      result += data;
    });
    
    res.on('end', function() {
      try {
        result = JSON.parse(result);
      } catch(ex) {
        result = {
          error : ex
        };
      }
      if (result.value) {
        callback(null, result.value);
      } else {
        callback(result.error, false);
      }
    });
  }).on('error', function(e) {
    return callback('Request failed: ' + e , false);
  });
};

/**
 * Return extra parameters to be included in the authorization request.
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
Strategy.prototype.authorizationParams = function(options) {
  var extendedOptions = {};
  for (var attr in options) {
    if (attr != 'clientId' && attr != 'clientSecret' && attr != 'resource' && attr != 'tenantId') {
      extendedOptions[attr] = options[attr];
    }
  }
  return extendedOptions;
}

/**
 * Load user profile, contingent upon options.
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api private
 */
Strategy.prototype._loadUserProfile = function(accessToken, refreshToken, done) {
  var self = this;

  function loadIt() {
    return self.userProfile(accessToken, refreshToken, done);
  }
  function skipIt() {
    return done(null);
  }

  if (typeof this._skipUserProfile == 'function' && this._skipUserProfile.length > 1) {
    // async
    this._skipUserProfile(accessToken, function(err, skip) {
      if (err) { return done(err); }
      if (!skip) { return loadIt(); }
      return skipIt();
    });
  } else {
    var skip = (typeof this._skipUserProfile == 'function') ? this._skipUserProfile() : this._skipUserProfile;
    if (!skip) { return loadIt(); }
    return skipIt();
  }
}


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;