module.exports = {

    getClient: function (client_id, client_secret, callback) {
        Application.findOne({'tokens.client_id': client_id}, function (err, doc) {
            if (err) {
                callback(false);
            } else if (!doc) {
                callback(false);
            } else {
                var client = {
                    client_id: doc.tokens.client_id,
                    redirect_uri: doc.tokens.redirect_uri
                };
                callback(client);
            }
        });
    },

    getUserOrLoadLogin: function (req, res, authorize_uri, callback) {
        if (req.session.userId) {
            callback(req.session.userId);
        } else {
            res.render('oauth_login', {next: encodeURIComponent(authorize_uri)});
        }
    },

    loginUser: function (req, callback) {
        User.login(req.body.username, req.body.pasword, function (doc) {
            if (!doc) {
                callback(false);
            } else {
                req.session.userId = doc;
                callback(doc);
            }
        });
        //User.findOne({'email': req.body.username, 'password': req.body.password}, function (err, doc) {
        //    if (err || !doc) {
        //        callback(false);
        //    } else {
        //        req.session.userId = doc.email;
        //        callback(doc.email);
        //    }
        //});
    },

    loadAuthorizeForm: function (req, res, client_id, authorize_uri) {
        res.render('oauth_authorization', {client_id: client_id, authorize_url: authorize_uri})
    },

    saveCode: function (code, client_id, user_id, expires) {
        codes[code] = {
            client_id: client_id,
            user_id: user_id,
            expires: expires
        };
        console.log(codes);
    },

    removeCode: function (code) {
        codes[code] = undefined;
    },

    getCode: function (code, callback) {
        callback(codes[code]);
    },

    addFieldsToAccessToken: function (client_id, client_secret, user_id, callback) {
        User.scope(user_id, function(scope){
            //var fields = {
            //    test_field: 'test test'
            //};
            callback(scope);
        });
    },

    saveAccessToken: function (access_token) {

    },

    passwordGrantType: function (client_id, client_secret, username, password, callback) {
        User.login(username, password, function (doc) {
            if (!doc) {
                callback(false);
            } else {
                callback(doc);
            }
        });
    }
};