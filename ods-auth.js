/**
 * The Openlink Data Spaces client lib version 1.0.
 *
 * The central object is the {@link ODS.Session} which can be created through one
 * of the session creation functions provided by ODS.
 *
 * @namespace
 * @name ODS
 */
var ODS = (function($) {

    /// The ODS instance host (private vars)
    // TODO: add a way to change this without having the SSL host being fetched twice!
    var odsHost = window.location.host;
    var odsSSLHost = null;

    /**
     * The generic error handler which is used as a fallback
     * if clients do not provide anything else.
     * @private
     */
    var odsGenericErrorHandler = function(result) {
      console.log(result);

      if (result.responseText)
        result = result.responseText;

      if(ODS.isErrorResult(result))
        alert(ODS.extractErrorResultMessage(result));
      else
        alert(result);
    };

    /**
     * The default error handler which can be changed via ODS.setDefaultErrorHandler().
     * @private
     */
    var defaultErrorHandler = odsGenericErrorHandler;


    /**
     * Parses a session result from ODS authentication methods.
     * @return the session id on success, null on error
     * @private
     */
    var parseOdsSession = function(sessXml) {
      var x = $(sessXml);
      var sid = x.find('userSession sid');
      if(sid.length > 0) {
        return new Session(sid.text(), parseInt(x.find('user new').text(), 10));
      }
      else {
        return null;
      }
    };

    /**
     * @private
     */
    var parseOdsAuthConfirmSession = function(sessXml) {
      var x = $(sessXml);
      x = $(x.find('confirmSession'));
      return {
        cid: x.find('cid').text(),
        user: {
          name: x.find('user name').text(),
          email: x.find('user email').text()
        },
        onlineAccount: {
          service: x.find('onlineAccount service').text(),
          uid: x.find('onlineAccount uid').text()
        },
        reason: {
          code: x.find('reason code').text(),
          msg: x.find('reason msg').text()
        }
      };
    };

    /* BROWSER ID ************************************/

    /// global variable to remember which action we took for browser id.
    var s_browserIdAction = null;
    /// global variable to remember which comfirmation mode we took for browser id
    var s_browserIdConfirm = null;
    /// the ODS session from which the connection call was made
    var s_browserIdOdsSession = null;
    /// the success callback for browserid
    var s_browseridSuccessHandler = null;
    /// the auth confirm handler for broswerid
    var s_browseridAuthConfirmHandler = null;
    /// the error callback for browserid
    var s_browseridErrorHandler = null;

    /**
     * Setup the BrowserID integration. This will be called when the document
     * is ready. See below.
     *
     * @private
     */
    var setupBrowserId = function() {
      console.log("ODS: Setting up BrowserID integration");
      navigator.id.watch({
        // We use ODS' session management, thus the logged in user from the BrowserID point of view os always null
        loggedInUser: null,

        // the actual ODS BrowserID login
        onlogin: function(assertion) {
          console.log("ODS BrowserID login: " + s_browserIdAction);
          // We use ODS session management, thus, we never want BrowserID auto-login
          navigator.id.logout();

          // build the audience address as required by Mozilla Persona
          var audience = window.location.protocol + "//" + window.location.hostname + ":" + (window.location.port || (window.location.protocol === "http:" ? "80" : "443"));

          // connect requires authentication...
          if(s_browserIdAction === "connect") {
            s_browserIdOdsSession.apiCall("user.authenticate.browserid", { action: "connect", "audience": audience, "assertion": assertion }).success(function() {
              s_browseridSuccessHandler(s_browserIdOdsSession);
            }).error(s_browseridErrorHandler);
          }

          // ...everything else does not
          else {
            // Log into ODS via the BrowserID, requesting a new session ID
            s_browserIdConfirm = s_browserIdConfirm || 'auto';
            $.get(ODS.apiUrl('user.authenticate.browserid'), { assertion: assertion, "audience": audience, action: s_browserIdAction, confirm: s_browserIdConfirm }).success(function(result) {
              console.log("Browser ID Login result:");
              console.log(result);
              var s = parseOdsSession(result);
              if(!s) {
                // confirm session
                s_browseridAuthConfirmHandler(parseOdsAuthConfirmSession(result));
              }
              else {
                s_browseridSuccessHandler(s);
              }
            }).error(s_browseridErrorHandler || defaultErrorHandler);
          }
        },

        // we do nothing here as we do logout the ods way
        onlogout: function() {
        }
      });
    };

    if(navigator.id)
      setupBrowserId();

    /*********************** BrowserID end*/


    /**
     * Fetch the SSL host if it is not set and when done fire the ODS.ready event.
     * This will be called when the document is ready. See below.
     *
     * @private
     */
    var fetchSslHost = function() {
        // fetch the SSL host and port from ODS
        if(odsSSLHost == null) {
          console.log("ODS: Fetching SSL host from ODS instance");
          $.get(odsApiUrl("server.getInfo", 0), {info: "sslPort"}).success(function(result) {
            if(result.sslHost) {
              odsSSLHost = result.sslHost + ":" + result.sslPort;
              console.log("Fetched SSL Host from ODS: " + odsSSLHost);
              }
            else {
              console.log("Could not fetch SSL Host from ODS.");
            }

            $(document).trigger('ods-ready-event');
          });
        }
        else {
            // nothing to do
          $(document).trigger('ods-ready-event');
        }
    };

    /**
     * ODS initialization.
     */
    $(document).ready(function() {
      fetchSslHost();
    });

    /**
     * Construct an ODS API URL with optional ssl.
     *
     * @param methodName The name of the method to call.
     * @param ssl If <em>1</em> the returned URL will use the "https" protocol, if <em>0</em>
     * "http" will be used. If undefined the same protocol as the current window will be used.
     *
     * @private
     */
    var odsApiUrl = function(methodName, ssl) {
      if(ssl != 1)
        ssl = (window.location.protocol === "https:") ? 1 : 0;

      if(ssl == 1 && odsSSLHost != null) {
        return "https://" + odsSSLHost + "/ods/api/" + methodName;
      }
      else {
        return "http://" + odsHost + "/ods/api/" + methodName;
      }
    };

    /** @private */
    var Session = function(sessionId, isNewUser) {
        if(sessionId == null || sessionId == undefined || typeof sessionId != "string" || sessionId.length == 0) {
          console.log("Cannot create a session with an empty session ID.");
          return null;
        }

        /**
         * ODS Session main object.
         * The main ODS session object provides methods to all the ODS
         * functionality.
         *
         * Create an instance of a session via one of the ODS.authenticate methods.
         *
         * @class
         * @name ODS.Session
         */
        var m_sessionId = sessionId;
        var m_newUser = (isNewUser ? true : false);

        /** @lends ODS.Session# */
        return {
            /**
             * <p>Perform an HTTP request against this ODS session.</p>
             *
             * <p>The request will be authenticated using the session ID.</p>
             *
             * @param method The ODS method to call (Example: <em>user.onlineAccounts.list</em>).
             * @param params The query parameters as a dictionary.
             * @param type The type of data that is expected as result. Can be one of <em>text</em>, <em>json</em>, or <em>xml</em>.
             * @returns A jQuery jqXHR object which can be used to add handlers.
             */
            apiCall: function(method, params, type) {
                return $.get(odsApiUrl(method), $.extend({ realm: "wa", sid: m_sessionId }, params), type);
            },

            /**
             * The ODS session ID accociated with this Session object.
             * Normally there is no need to access the ID as it is used automatically
             * in any ODS API call made via {@link ODS.Session#apiCall}.
             *
             * @returns {String} The session ID.
             */
            sessionId: function() { return m_sessionId; },

            /**
             * <p>Fetch information about a user.</p>
             *
             * <p>The function has up to three parameters:</p>
             * <li>An optional first parameter which refers to the username, by default the
             * authenticated user is assumed.</li>
             * <li>An optional function to be called on successful retrieval of the user info.
             * This function has one parameter: the map of user details.</li>
             * <li>An optional error function which is called in case the call fails. This
             * function has one parameter: the error message.</li>
             */
            userInfo: function() {
                var success = null,
                error = null,
                parameters = {},
                i = 0;

                // parse arguments
                if(arguments[0] && typeof arguments[0] === "string") {
                    parameters = { name: arguments[0] };
                    i = 1;
                }
                if(typeof arguments[i] === "function") {
                    success = arguments[i];
                    if(typeof arguments[i+1] === "function") {
                        error = arguments[i+1];
                    }
                }

                // perform the call
                this.apiCall("user.info", parameters).success(function(result) {
                    if(ODS.isErrorResult(result)) {
                      (error || defaultErrorHandler)(result);
                    }
                    else {
                        // build our dict
                        var propDict = {};

                        // parse the result.
                        $(result).find("user").children().each(function() {
                            propDict[this.nodeName] = $(this).text();
                        });

                        // call the client
                        if(success) {
                            success(propDict);
                        }
                    }
                }).error(error || defaultErrorHandler);
            },

            /**
             * <p>Connect an ODS account to a third-party account to enable authentication.</p>
             *
             * <p>ODS supports a variety of services (a list can be obtained via {@link ODS#authenticationMethods})
             * for registration and authentication. This method is used to connect an account from one of
             * those services to the authenticated ODS account.</p>
             *
             * <p>A successful call to this method results in a redirect to the third-party service's authentication
             * page which in turn will result in yet another redirect to the given url.</p>
             *
             * <p>The helper function {@link ODS#handleAuthenticationCallback} will help with completing the
             * connection.</p>
             *
             * @param {String} type The name of the third-party service to connect to.
             * @param {String} url The callback URL ODS should redirect the user to after completing the process.
             * @param {Function} error An optional error handler in case of a failure.
             */
            connectToThirdPartyService: function(type, url, error) {
              if(error == null) {
                error = defaultErrorHandler;
              }

              this.apiCall("user.authenticate.authenticationUrl", { action: "connect", service: type, "callback": url }).success(function(result) {
                window.location.href = result;
              }).error(function(jqXHR) {
                // FIXME: handle HTTP errors
                error(jqXHR);
              });
            },

            /**
             * <p>Connect an ODS account to an OpenID to enable authentication.</p>
             *
             * <p>ODS supports a variety of services (a list can be obtained via {@link ODS#authenticationMethods})
             * for registration and authentication. This method is used to connect an OpenID to the authenticated ODS account.</p>
             *
             * <p>A successful call to this method results in a redirect to the OpenID service's authentication
             * page which in turn will result in yet another redirect to the given url.</p>
             *
             * <p>The helper function {@link ODS#handleAuthenticationCallback} will help with completing the
             * connection.</p>
             *
             * @param {String} openid The OpenID to connect to.
             * @param {String} url The callback URL ODS should redirect the user to after completing the process.
             * @param {Function} errorHandler An optional error handler in case of a failure.
             */
            connectToOpenId: function(openid, url, errorHandler) {
              this.apiCall("user.authenticate.authenticationUrl", { action: "connect", service: 'openid', "callback": url, data: openid }).success(function(result) {
                window.location.href = result;
              }).error(errorHandler || defaultErrorHandler);
            },

            /**
             * <p>Connect this session's account to a BrowserID.</p>
             *
             * <p>In case the client includes the BrowserID JavaScript library as below this call will initiate
             * BrowserID login resulting in a connection of the BrowserID with the current ODS account.</p>
             *
             * <pre>&lt;script src="https://login.persona.org/include.js"&gt;&lt;/script&gt;</pre>
             *
             * @param {Function} successHandler A handler function which is called on success with one parameter: the current Session object.
             * @param {Function} errorHandler A handler function which is called in case of an error.
             */
            connectToBrowserId: function(successHandler, errorHandler) {
              if(navigator.id) {
                s_browserIdOdsSession = this;
                s_browserIdAction = 'connect';
                s_browseridSuccessHandler = successHandler;
                s_browseridErrorHandler = errorHandler || defaultErrorHandler;
                navigator.id.request();
              }
            },

            /**
             * <p>Connect this session's account to a WebID via an X.509 certificate.</p>
             *
             * <p>This method should be called in an SSL context for ODS to be able to request
             * a client certificate.</p>
             *
             * @param {Function} successHandler A handler function which is called on success with one parameter: the current Session object.
             * @param {Function} errorHandler A handler function which is called in case of an error.
             */
            connectToWebId: function(successHandler, errorHandler) {
              this.apiCall("user.authenticate.webid", { action: "connect" }).success(function() {
                successHandler(this);
              }).error(errorHandler || defaultErrorHandler);
            },

            /**
             * <p>Log out of this session.</p>
             *
             * <p>This will invalidate the session ID and this Session instance.</p>
             *
             * @param {Function} success A handler function which is called on successful logout.
             * @param {Function} error A handler function which is called in case of an error.
             */
            logout: function(successHandler, errorHandler) {
                this.apiCall("user.logout").success(function() {
                    this.m_sessionId = null;
                    successHandler();
                }).error(errorHandler || defaultErrorHandler);
            },

            /**
             * Check if this session is the result of a newly created user account.
             * This is useful for showing welcome messages and the like.
             *
             * @return <em>true</em> if this session is the result of a newly created
             * user account.
             */
            isNewUser: function() {
              return m_newUser;
            }
        };
    };


    /**
     * Extract query parameters from a URL
     *
     * @private
     */
    var getParameterByName = function(url, name) {
        name = name.replace(/[\[]/, "\\[").replace(/[\]]/, "\\]");
        var regexS = "[\\?&]" + name + "=([^&#]*)";
        var regex = new RegExp(regexS);
        var results = regex.exec(url.substring(url.indexOf('?')));
        if(results == null)
            return "";
        else
            return decodeURIComponent(results[1].replace(/\+/g, " "));
    };



    // ===========================================================================
    // PUBLIC API of namespace "ODS"
    // ===========================================================================

    /** @lends ODS# */
    return {
        /**
         * Bind a function to the custom event of ODS being ready for action.
         *
         * @param callback The function to call once ODS is ready.
         */
        ready: function(callback) {
          $(document).bind('ods-ready-event', callback);
        },

        /**
         * <p>Generic error handler which display an <em>alert</em> showing the
         * error message.</p>
         * <p>This is the default error handler used if nothing else is specified
         * by the client and no default has been set via {@link ODS#setDefaultErrorHandler}.</p>
         */
        genericErrorHandler: function(result) {
          odsGenericErrorHandler(result);
        },

        /**
         * The configured ODS host (defaults to the current domain). See also {@link ODS#setOdsHost}.
         */
        host: function() {
          return odsHost;
        },

        /**
         * The configured ODS SSL host (by default this is fetched automatically). See also {@link ODS#setOdsHost}.
         */
        sslHost: function() {
          return odsSSLHost;
        },

        /**
         * Creates a URL to an ODS DAV resource.
         *
         * @param path The absolute path to the DAV resource.
         */
        davUrl: function(path) {
          var url = "http://" + odsHost;
          if(path.substring(0, 4) != '/DAV')
            url += "/DAV";
          if(path.substring(0, 1) != "/")
            url += "/";
          return url + path;
        },

        /**
         * Construct an ODS API URL with optional ssl.
         * @param {String} methodName The name of the method to call.
         * @param {Boolean} ssl If <em>true</em> the returned URL will use the https protocol.
         */
        apiUrl: function(methodName, ssl) {
            return odsApiUrl(methodName, ssl);
        },

        /**
         * Retrieve the supported authentication methods. This list can for example be used to
         * create authentication buttons which, when clicked, trigger a call to {@link ODS#createThirdPartyServiceSession}.
         *
         * @param {Function} callback A function which gets one parameter: a list of supported
         * authentication methods like <em>webid</em>, <em>facebook</em>, <em>browserid</em>, ...
         */
        authenticationMethods: function(callback) {
            var methods = [];
            $.get(odsApiUrl("server.getInfo", 0), {info: "regData"}).success(function(result) {
              for(var a in result.authenticate) {
                if(result.authenticate[a])
                  methods.push(a);
              }
              callback(methods);
            });
        },

        registrationMethods: function(callback) {
            var methods = [];
            $.get(odsApiUrl("server.getInfo", 0), {info: "regData"}).success(function(result) {
              for(var a in result.register) {
                if(result.register[a])
                  methods.push(a);
              }
              callback(methods);
            });
        },

        connectionMethods: function(callback) {
            var methods = [];
            $.get(odsApiUrl("server.getInfo", 0), {info: "regData"}).success(function(result) {
              for(var a in result.connect) {
                if(result.connect[a])
                  methods.push(a);
              }
              callback(methods);
            });
        },

        /**
         * Create a new ODS session from a session ID without any checks.
         *
         * This method should only be used from php or vsp code when it is sure that the given
         * session id is valid. In all other cases ODS#createSessionFromId is the correct choice.
         *
         * @param {String} sid The session ID to create the Session object from.
         *
         * @return A new (@link ODS.Session} object which can be used right away.
         */
        newSessionFromVerifiedId: function(sid) {
          return new Session(sid);
        },

        /**
         * Create a new ODS session with password hash authentication.
         *
         * @param {String} usr The user name.
         * @param {String} pwd The password.
         * @param newSessionHandler A callback function which has one parameter: the new
         * ODS {@link ODS.Session} object.
         * @param {Function} errorHandler An optional error callback function. See also {@link ODS#setDefaultErrorHandler}.
         */
        createSession: function(usr, pwd, newSessionHandler, errorHandler) {
            var authenticationUrl = odsApiUrl("user.authenticate", 0),
            authenticationParams = {
                user_name : usr,
                password_hash : $.sha1(usr + pwd)
            };

            $.get(authenticationUrl, authenticationParams).success(function(result) {
                var s = $(result).find("sid").text();

                console.log("Authentication result: " + s);

                if(s.length > 0) {
                    // login succeeded
                    newSessionHandler(new Session(s));
                }
                else {
                    // login failed
                    (errorHandler || defaultErrorHandler)(result);
                }
            });
        },

        /**
         * Create a new ODS session through WebID authentication.
         *
         * The browser will automatically request the WebID certificate from
         * the user.
         *
         * @param {Function} newSessionHandler A callback function with a single parameter: the new
         * {@link ODS.Session} object.
         * @param {Function} errorHandler optional error callback function which is called if the
         * session is no longer valid or the ODS call failed. See also {@link ODS#setDefaultErrorHandler}.
         */
        createWebIdSession: function(newSessionHandler, errorHandler) {
            $.get(odsApiUrl("user.authenticate.webid", 1), {}).success(function(result) {
                var s = parseOdsSession(result);

                console.log("Authentication result: " + s);
                newSessionHandler(s);
            }).error(errorHandler || defaultErrorHandler);
        },

        /**
         * Create a new ODS session via an existing OpenID.
         *
         * Creating an ODS session via OpenID is a two-step process:
         * <li>Request the authentication URL from ODS and let the user authenticate and get the redirection</li>
         * <li>Get the new session ID from the redirected URL parameter or parse the error.</li>
         *
         * For the first step pass the <em>openid</em> the user wants to login with to this function as well as
         * the redirection URL to which the OpenID provider should redirect once the OpenID authentication
         * was sucessful. This function will then navigate the user to the OpenID provider's login page.
         * Once the redirection is done this function needs to be called again, this time leaving both
         * parameters empty.
         *
         * @param {String} openid The OpenID the user wants to login with. This needs to be specified for step 1.
         * @param {String} url The callback URL.
         * @param {Function} errorHandler An optional error callback function which is called if the ODS call failed.
         *        See also {@link ODS#setDefaultErrorHandler}.
         */
        createOpenIdSession: function(openid, url, errorHandler) {
            $.get(odsApiUrl("user.authenticate.authenticationUrl", 0), { service: "openid", callback: url, data: openid }, "text/plain").success(function(result) {
              window.location.href = result;
            }).error(errorHandler || defaultErrorHandler);
        },

        /**
         * Create a new ODS session by authenticating via a third-party account.
         *
         * <p>ODS supports a variety of services (a list can be obtained via {@link ODS#authenticationMethods})
         * for registration and authentication.</p>
         *
         * <p>A successful call to this method results in a redirect to the third-party service's authentication
         * page which in turn will result in yet another redirect to the given url.</p>
         *
         * <p>The helper function {@link ODS#handleAuthenticationCallback} will help with completing the
         * connection.</p>
         *
         * @param {String} type The name of the third-party service to connect to.
         * @param {String} url The callback URL ODS should redirect the user to after completing the process.
         * @param {Function} errorHandler An optional error handler in case of a failure.
         *        See also {@link ODS#setDefaultErrorHandler}.
         */
        createThirdPartyServiceSession: function(type, url, errorHandler) {
          $.get(odsApiUrl("user.authenticate.authenticationUrl", 0), { service: type, "callback": url }, "text/plain").success(function(result) {
            window.location.href = result;
          }).error(errorHandler || defaultErrorHandler);
        },

        /**
         * <p>Create a new session via BrowserID/Mozilla Personal login.</p>
         *
         * @param {Function} newSessionHandler A function which handles a successful authentication. It has one
         * parameter: the new {@link ODS.Session} object.
         * @param {Function} errorHandler An optional error callback function which is called if the
         * session is no longer valid or the ODS call failed. See also {@link ODS#setDefaultErrorHandler}.
         */
        createBrowserIdSession: function(newSessionHandler, errorHandler) {
          if(navigator.id) {
            s_browserIdAction = 'authenticate';
            s_browseridSuccessHandler = newSessionHandler;
            s_browseridErrorHandler = errorHandler || defaultErrorHandler;
            navigator.id.request();
          }
        },

        /**
         * <p>Create a new ODS session from an existing session id.</p>
         *
         * <p>This is for example useful for storing the session id in a cookie.
         * The function will check if the session is still valid and if so
         * create a corresponding Session object.</p>
         *
         * @param {String} sessionId The id of the session.
         * @param {Function} newSessionHandler A function which handles a successful authentication. It has one
         * parameter: the new {@link ODS.Session} object.
         * @param {Function} errorHandler An optional error callback function which is called if the
         * session is no longer valid or the ODS call failed. See also {@link ODS#setDefaultErrorHandler}.
         */
        createSessionFromId: function(sessionId, newSessionHandler, errorHandler) {
            console.log("ODS: createSessionFromId: " + sessionId);

            // check if the session is still valid by fetching user details
            $.get(odsApiUrl("user.info"), { realm: "wa", sid: sessionId }).success(function(result) {
                var name = $(result).find("name").text();
                if(name == null || name == "") {
                    sessionId = null;
                    errorHandler("Session timed out: " + sessionId);
                }
                else {
                    newSessionHandler(new Session(sessionId));
                }
            }).error(errorHandler || defaultErrorHandler);
        },

        /**
         * <p>Register a new ODS account with classical username and password credentials.</p>
         *
         * @param {String} uname The wanted username.
         * @param {String} email The email address accociated with the new account.
         * @param {String} password The password for the account.
         * @param {Function} newSessionHandler A function which handles a successful authentication. It has one
         * parameter: the new {@link ODS.Session} object.
         * @param {Function} errorHandler An optional error callback function which is called if the
         * session is no longer valid or the ODS call failed. See also {@link ODS#setDefaultErrorHandler}.
         */
        register: function(uname, email, password, newSessionHandler, errorHandler) {
          $.get(odsApiUrl('user.register'), { name: uname, "password": password, "email": email }).success(function(result) {
            if(ODS.isErrorResult(result))
              (errorHandler || defaultErrorHandler)(result);
            else
              newSessionHandler(parseOdsSession(result));
          }).error(errorHandler || defaultErrorHandler);
        },

        /**
         * <p>Register a new ODS account via a third-party service.</p>
         *
         * <p>ODS supports a variety of services (a list can be obtained via {@link ODS#registrationMethods})
         * for registration.</p>
         *
         * <p>A successful call to this method results in a redirect to the third-party service's authentication
         * page which in turn will result in yet another redirect to the given url.</p>
         *
         * <p>The helper function {@link ODS#handleAuthenticationCallback} will help with completing the
         * connection.</p>
         *
         * @param {String} type The type of service to register with.
         * See <a href="http://web.ods.openlinksw.com/odsdox/group__ods__module__user.html#ods_authentication_url_services">the ODS API documentation</a> for details.
         * @param {String} url The callback URL ODS should redirect the user to after completing the process.
         * @param {String} confirm The confirmation setting, can be one of "auto", "always", or "never".
         * See <a href="http://web.ods.openlinksw.com/odsdox/group__ods__module__user.html#ods_authentication_url_confirm">the ODS API documentation</a> for details.
         * @param {Function} errorHandler A function which handles the error case. It has one parameter:
         * the error message. See also {@link ODS#setDefaultErrorHandler}.
         */
        registerViaThirdPartyService: function(type, url, confirm, errorHandler) {
          $.get(odsApiUrl("user.authenticate.authenticationUrl", 0), { action: "register", "confirm": confirm || 'auto', "service": type, "callback": url }, "text/plain").success(function(result) {
            window.location.href = result;
          }).error(errorHandler || defaultErrorHandler);
        },

        /**
         * <p>Create a new ODS account by identifying with a WebID (X.509 certificate).</p>
         *
         * <p>See also <a href="http://web.ods.openlinksw.com/odsdox/group__ods__module__user.html#gacc9b0a34fd501b1723e780fc6b520a46">
         * The ODS HTTP API: user.authenticate.webid</a>.</p>
         *
         * @param {String} confirm The optional confirmation setting, can be one of "auto", "always", or "never".
         * See <a href="http://web.ods.openlinksw.com/odsdox/group__ods__module__user.html#ods_authentication_url_confirm">Authentication Confirmation Mode</a> for details.
         * @param {Function} newSessionHandler A function which handles a successful authentication. It has one
         * parameter: the new {@link ODS.Session} object.
         * @param {Function} confirmHandler A function which handles an authentication confirmation. This is only
         * required if a registration has been started with <em>confirm</em> mode <em>auto</em> or
         * <em>always</em>. The function gets one Json object parameter as follows:
         * <pre>{
         *   cid: "xxxxxxxxxxxxx",
         *   user: {
         *     name: "foobar",
         *     email: "foobar@gmail.com"
         *   },
         *   onlineAccount: {
         *     service: "webid",
         *     uid: "http://foobar.com/people/foobar#this"
         *   }
         * }</pre>
         * The confirmation session id <em>cid</em> as well as the confirmed and optionally modified values of
         * <em>user.name</em> and <em>user.email</em> should be passed to {@link ODS.confirmAuthentication} to
         * complete the authentication/registration.
         * @param {Function} errorHandler A function which handles the error case. It has one parameter:
         * the error message. See also {@link ODS#setDefaultErrorHandler}.
         */
        registerViaWebId: function(confirm, newSessionHandler, confirmHandler, errorHandler) {
          if(typeof confirm === "function") {
            confirmHandler = errorHandler;
            errorHandler = newSessionHandler;
            newSessionHandler = confirm;
            confirm = 'auto';
          }

          $.get(odsApiUrl("user.authenticate.webid", 1), { action: "register", "confirm": confirm }).success(function(result) {
            var s = parseOdsSession(result);
            if(!s) {
              // confirm session
              confirmHandler(parseOdsAuthConfirmSession(result));
            }
            else {
              newSessionHandler(s);
            }
          }).error(errorHandler || defaultErrorHandler);
        },

        registerViaOpenId: function(openid, url, confirm, errorHandler) {
            $.get(odsApiUrl("user.authenticate.authenticationUrl", 0), { action: "register", service: "openid", "confirm": confirm || 'auto', callback: url, data: openid }, "text/plain").success(function(result) {
              window.location.href = result;
            }).error(errorHandler || defaultErrorHandler);
        },

        registerViaBrowserId: function(confirm, newSessionHandler, confirmHandler, errorHandler) {
          if(typeof confirm === "function") {
            confirmHandler = errorHandler;
            errorHandler = newSessionHandler;
            newSessionHandler = confirm;
            confirm = null;
          }
          if(navigator.id) {
            s_browserIdAction = 'register';
            s_browserIdConfirm = confirm;
            s_browseridSuccessHandler = newSessionHandler;
            s_browseridAuthConfirmHandler = confirmHandler;
            s_browseridErrorHandler = errorHandler || defaultErrorHandler;
            navigator.id.request();
          }
        },

        registerOrLoginViaThirdPartyService: function(type, url, confirm, errorHandler) {
          $.get(odsApiUrl("user.authenticate.authenticationUrl", 0), { action: "auto", service: type, "confirm": confirm || 'auto', "callback": url }, "text/plain").success(function(result) {
            window.location.href = result;
          }).error(errorHandler || defaultErrorHandler);
        },

        /**
         * <p>Register or login via a WebID (X.509 client certificate).</p>
         *
         * <p>The parameters are exactly the same as in {@link ODS#registerViaWebId}. The only
         * difference is that this method will simply log into ODS if the given WebID is already
         * connected to an ODS account.</p>
         *
         * @param {String} confirm The optional confirmation setting, can be one of "auto", "always", or "never".
         * See <a href="FIXME">the ODS API documentation</a> for details.
         * @param newSessionHandler A function which handles a successful authentication. It has one
         * parameter: the new {@link ODS.Session} object.
         * @param confirmHandler A function which handles an authentication confirmation. This is only
         * required if a registration has been started with <em>confirm</em> mode <em>auto</em> or
         * <em>always</em>. See {@link ODS#registerViaWebId} for details.
         * @param errorHandler A function which handles the error case. It has one parameter:
         * the error message.
         */
        registerOrLoginViaWebId: function(confirm, newSessionHandler, confirmHandler, errorHandler) {
          if(typeof confirm === "function") {
            confirmHandler = errorHandler;
            errorHandler = newSessionHandler;
            newSessionHandler = confirm;
            confirm = 'auto';
          }

          $.get(odsApiUrl("user.authenticate.webid", 1), { action: "auto", "confirm": confirm }).success(function(result) {
            var s = parseOdsSession(result);
            if(!s) {
              // confirm session
              confirmHandler(parseOdsAuthConfirmSession(result));
            }
            else {
              newSessionHandler(s);
            }
          }).error(errorHandler || defaultErrorHandler);
        },

        registerOrLoginViaBrowserId: function(confirm, newSessionHandler, confirmHandler, errorHandler) {
          if(typeof confirm === "function") {
            confirmHandler = errorHandler;
            errorHandler = newSessionHandler;
            newSessionHandler = confirm;
            confirm = 'auto';
          }
          if(navigator.id) {
            s_browserIdAction = 'auto';
            s_browserIdConfirm = confirm;
            s_browseridSuccessHandler = newSessionHandler;
            s_browseridErrorHandler = errorHandler || defaultErrorHandler;
            navigator.id.request();
          }
        },

        registerOrLoginViaOpenId: function(openid, url, confirm, errorHandler) {
          $.get(odsApiUrl("user.authenticate.authenticationUrl", 0), { action: "auto", service: "openid", "confirm": confirm || 'auto', callback: url, data: openid }, "text/plain").success(function(result) {
            window.location.href = result;
          }).error(errorHandler || defaultErrorHandler);
        },

        confirmAuthentication: function(cid, username, email, newSessionHandler, errorHandler) {
          $.get(odsApiUrl("user.authenticate.confirm"), { "cid": cid, "username": username, "email": email }).success(function(result) {
            newSessionHandler(parseOdsSession(result));
          }).error(errorHandler || defaultErrorHandler);
        },

        /**
         * A callback handler which interprets the results from an authentication call
         * via methods like {@link createThirdPartyServiceSession} or {@link registerViaOpenId}.
         *
         * The method will parse the result from the current URL and provide it to the
         * given handler functions in an appropriate form.
         *
         * @param {Function} newSessionHandler A function which handles a successful authentication. It has one
         * parameter: the new {@link ODS.Session} object.
         * @param {Function} confirmHandler A function which handles an authentication confirmation. This is only
         * required if a registration has been started with <em>confirm</em> mode <em>auto</em> or
         * <em>always</em>. The function gets one parameter as described in {@link ODS#registerViaWebId}.
         * @param {Function} errorHandler A function which handles the error case. It has one parameter:
         * the error message. See also {@link ODS#setDefaultErrorHandler}.
         *
         * @returns If there was a result to process <em>true</em> is returned, <em>false</em>
         * otherwise. In the latter case none of the handler functions is called. Thus, this
         * method can also be used to check if the current URL contains any ODS authentication
         * result.
         */
        handleAuthenticationCallback: function(newSessionHandler, confirmHandler, errorHandler) {
          errorHandler = errorHandler || defaultErrorHandler;
          var sid = getParameterByName(window.location.href, 'userSession.sid');
          var cid = getParameterByName(window.location.href, 'confirmSession.cid');
          var err = getParameterByName(window.location.href, 'error.msg');
          if(sid.length > 0) {
            newSessionHandler(new Session(sid));
          }
          else if(cid.length > 0) {
            confirmHandler({
              "cid": cid,
              "user": {
                "name": getParameterByName(window.location.href, "user.name"),
                "email": getParameterByName(window.location.href, "user.email")
              },
              "onlineAccount": {
                "service": getParameterByName(window.location.href, "onlineAccount.service"),
                "uid": getParameterByName(window.location.href, "onlineAccount.uid")
              },
              "reason": {
                "code": getParameterByName(window.location.href, "confirmSession.reason.code"),
                "msg": getParameterByName(window.location.href, "confirmSession.reason.msg")
              }
            });
            return true;
          }
          else if(err.length > 0) {
            errorHandler(err);
            return true;
          }
          else {
            return false;
          }
        },

        /**
         * Check if an email address is properly formatted.
         *
         * @param {String} email The candidate email address.
         *
         * @returns <em>true</em> if the email address is properly formatted.
         */
        verifyEmailAddressFormat: function(email) {
            var filter = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
            return filter.test(email);
        },

        /**
         * Check if a standard ODS error code result is an error or not.
         *
         * @param result The result XML element as returned by the ODS REST call.
         *
         * @returns <em>true</em> if it is in fact an error.
         */
        isErrorResult: function(result) {
          if(typeof result == 'string') {
            try {
              result = $.parseXML(result);
            }
            catch(err) {
              return false;
            }
          }

          var error = result.getElementsByTagName('failed')[0];
          if (error)
            return true;
          else
            return false;
        },

        /**
         * Extract the error message from an ODS XML result block.
         *
         * @param result The XML block as returned by many ODS functions.
         */
         extractErrorResultMessage: function(result) {
           if(typeof result == 'string') {
            try {
              result = $.parseXML(result);
            }
            catch(err) {
              // fallback to the plain string
              return result;
            }
          }
          return $(result).find('message').text();
        },

        /**
         * <p>Set the host the ODS instance is running on.</p>
         *
         * <p>By default the client's host address is assumed and the
         * SSL host is determined by calling ODS' <em>getDefaultHttps</em>.</p>
         *
         * <p>This method can be used to override the defaults and avoid
         * the additional HTTP call mentioned above. It is recommended to set
         * the ODS host before the document is fully loaded, ie. <em>not</em>
         * in a handler of the document.ready event.</p>
         */
        setOdsHost: function(host, sslHost) {
          odsHost = host;
          odsSSLHost = sslHost;
          if(odsHost.substring(0,7) == "http://")
            odsHost = odsHost.substring(7);
          if(odsSSLHost.substring(0,8) == "https://")
            odsSSLHost = odsSSLHost.substring(8);
        },

        /**
         * <p>Set the default error handler for all functions in ODS and {@link ODS.Session}
         * which have an optional <em>errorHandler</em> parameter.</p>
         * <p>When not calling this function the {@link ODS#genericErrorHandler} function will
         * be used as a fallback for all functions if no <em>errorHandler</em> is specified.</p>
         *
         * @param {Function} handler The new default error handler function.
         */
        setDefaultErrorHandler: function(handler) {
          defaultErrorHandler = handler;
        },

        /**
         * Removes any parameters ODS.js added to an URL.
         */
        cleanupUrl: function(url) {
          if(url.indexOf('?') >= 0) {
            // extract params
            var params = url.substring(url.indexOf('?')+1).split('&');
            var newUrl = url.substring(0, url.indexOf('?'));
            var first = true;
            for (var i = 0; i < params.length; i++) {
              if(params[i].length > 0) {
                var key = params[i].split("=")[0];
                if (key.substring(0, 6) == "error." ||
                  key.substring(0, 12) == "userSession." ||
                  key.substring(0, 15) == "confirmSession." ||
                  key.substring(0, 5) == "user." ||
                  key.substring(0, 14) == "onlineAccount.") {
                    continue;
                }
                else {
                  if (first) {
                    newUrl += '?';
                    first = false;
                  }
                  else {
                    newUrl += '&';
                  }
                  newUrl += params[i];
                }
              }
            }
            return newUrl;
          }
          else {
            return url;
          }
        }
    };
})(jQuery);
