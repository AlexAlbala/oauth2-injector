module.exports.config = require('./plugin.json');

module.exports.init = function(injector, oauthConfig){
	oauthConfig.storage = require('./lib/storage.js');	
	oauthConfig.authorize_uri = '/oauth/authorize';
	oauthConfig.login_uri = '/oauth/login';
	oauthConfig.access_token_uri = '/oauth/token';
	module.exports.preInject = function(app, cb) {
	injector.security = require('./lib')(injector, oauthConfig);
		return cb();
	}
}
