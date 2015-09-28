var OAuth2Provider = require('oauth2-express').OAuth2Provider;
var oauthProvider;

var path = require('path');

var injector = undefined;

module.exports = function (_injector, cfg) {
    oauthProvider = new OAuth2Provider(cfg);
    oauthProvider.middleware(_injector.app);
    injector = _injector;
    return module.exports;
};

function checkRole(role) {
    //return oauthProvider.needsOAuth(role);
    return function (req, res, next) {
        if (req.oauth) {
            var userRole = req.oauth.scope;
            injector.log.debug("[CheckRole] Required=[", role, "] - Current role is [", userRole, "]");

            if (injector.config.permissions.adminRole && injector.config.permissions.adminRole === userRole) {
                injector.log.debug("Access granted for", req.oauth.user_id);
                return next();
            }

            if ((role instanceof Array) && (role.indexOf(userRole) != -1)) {
                injector.log.debug("Access granted for", req.oauth.user_id);
                return next();
            } else if (role === userRole) {
                injector.log.debug("Access granted for", req.oauth.user_id);
                return next();
            } else {
                injector.log.debug("Access denied for", req.oauth.user_id);
                res.statusCode = 401;
                res.json({
                    error: "Unauthorized"
                })
                return res.end();
            }
        } else {
            injector.log.debug("Access denied for unknown user");
            res.statusCode = 401;
            res.json({
                error: "Unauthorized"
            })
            return res.end();
        }
    }
}

function getUserIfExists(req, res, next) {
    var auth = req.headers['authorization'];
    injector.log.debug("[GetUserIfExists] -> Has auth header [", auth != undefined, "]");
    if (auth) {
        oauthProvider.needsOAuth("")(req, res, next);
    } else {
        next();
    }
}

module.exports.checkRole = function (role) {
    return {
        name: "checkRole(" + role + ")",
        middleware: checkRole(role)
    }
};

module.exports.getUserIfExists = {
    name: "getUserIfExists",
    middleware: getUserIfExists
};
