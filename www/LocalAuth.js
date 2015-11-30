var exec = require('cordova/exec');

exports.initialize = function(appKey, success, error) {
    exec(success, error, "LocalAuth", "initialize", [appKey]);
};

exports.user = function(email, password, success, error) {
	var params = [];
	if (email) {
		params.push(email);
		if (password) {
			params.push(password);
		}
	}
	exec(success, error, "LocalAuth", "user", params);
}

exports.isAvailable = function() {
	exec(success, error, "LocalAuth", "isAvailable", []);
}

exports.authenticate = function(success, error) {
	exec(success, error, "LocalAuth", "authenticate", []);
}
