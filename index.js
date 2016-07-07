// Fork from `hapi-auth-cookie`
// Extended with the config-property `loginView`, which should be a view
// with a login-form which stes the cookie after succesful login


// Load modules

"use strict";

require('itsa-jsext/lib/object');

var Boom = require('boom');
var Hoek = require('hoek');

// Declare internals

var internals = {};

exports.register = function (server, options, next) {

    server.auth.scheme('itsa-auth', internals.implementation);
    next();
};


exports.register.attributes = {
    pkg: require('./package.json')
};


internals.implementation = function (server, options) {

    Hoek.assert(options, 'Missing cookie auth strategy options');
    Hoek.assert(typeof options.validateCookie === 'function', 'Invalid validateCookie method in configuration');
    Hoek.assert(options.keyGen, 'Missing required keyGen in configuration');
    Hoek.assert(options.loginView, 'Missing required loginView in configuration');
    Hoek.assert(!options.keepAlive || options.ttl, 'Cannot configure keepAlive without ttl');

    var settings = Hoek.clone(options); // Options can be reused
    settings.cookie = settings.cookie || 'sid';

    var cookieOptions = {
        encoding: 'iron',
        password: settings.keyGen,
        isSecure: settings.isSecure !== false,                  // Defaults to true
        path: '/',
        isHttpOnly: settings.isHttpOnly !== false,              // Defaults to true
        clearInvalid: settings.clearInvalid,
        ignoreErrors: true
    };

    if (settings.ttl) {
        cookieOptions.ttl = settings.ttl;
    }

    if (settings.domain) {
        cookieOptions.domain = settings.domain;
    }

    if (settings.path) {
        cookieOptions.path = settings.path;
    }

    if (typeof settings.appendNext === 'boolean') {
        settings.appendNext = (settings.appendNext ? 'next' : '');
    }

    server.state(settings.cookie, cookieOptions);

    server.ext('onPreResponse', function (request, reply) {
        var response = request.response;
        if (response.isBoom && response.output && (response.output.statusCode===403)) {
            return reply.reactview(settings.loginView, {__sendRequireId__: true});
        }
        return reply.continue();
    });

    server.ext('onPreAuth', function (request, reply) {
        request.auth.retries = settings.retries;
        request.auth.session = {
            set: function (session, ttl) {
                var options;
                if (typeof session==='object') {
                    if (typeof ttl==='number') {
                        session.ttl = ttl;
                        options = {
                            ttl: ttl
                        };
                    }
                    reply.state(settings.cookie, session, options);
                }
            },
            update: function (sessionid, value, ttl) {
                var session;
                if ((typeof sessionid==='string') && (typeof value==='object')) {
                    session = request.state[sessionid];
                    if (session) {
                        session.itsa_merge(value, {force: true});
                        if (typeof ttl==='number') {
                            session.ttl = ttl;
                        }
                        else {
                            ttl = session.ttl;
                        }
                        reply.state(settings.cookie, session, ttl && {ttl: ttl});
                    }
                }
            },
            clear: function (key) {
                var session, options;
                if (arguments.length) {
                    if (typeof key==='string') {
                        session = request.state[settings.cookie];
                        if (session) {
                            delete session[key];
                            if (session.ttl) {
                                options = {
                                    ttl: session.ttl
                                };
                            }
                            reply.state(settings.cookie, session, options);
                        }
                    }
                }
                else {
                    reply.unstate(settings.cookie);
                }
            },
            ttl: function (msecs) {
                var session = request.state[settings.cookie];
                if (session) {
                    session.ttl=msecs;
                    reply.state(settings.cookie, session, { ttl: msecs });
                }
            }
        };

        return reply.continue();
    });

    var scheme = {
        authenticate: function (request, reply) {
            request._itsaAuthenticationId = settings.cookie;

            var validate = function () {
                // Check cookie
                var session = request.state[settings.cookie];
                if (!session) {
                    reply.reactview(settings.loginView, {__sendRequireId__: true});
                }
                else {
                    settings.validateCookie.call(request, session, function (err, isValid, artifacts) {
                        var options;
                        if (err || !isValid) {
                            if (settings.clearInvalid) {
                                reply.unstate(settings.cookie);
                            }
                            reply.reactview(settings.loginView, {__sendRequireId__: true});
                        }
                        else {
                            // keepAlive:
                            if (session.ttl) {
                                options = {
                                    ttl: session.ttl
                                };
                            }
                            reply.state(settings.cookie, session, options);
                            reply.continue({credentials: session, artifacts: artifacts});
                        }
                    });
                }
            };

            validate();
        }
    };

    return scheme;
};
