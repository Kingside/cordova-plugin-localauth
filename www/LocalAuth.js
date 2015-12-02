var exec = require('cordova/exec');

exports.user = function(email, password, success, error) {
	var params = [];
	if (email) {
		params.push(email);
		if (password) {
			params.push(password);
		}
	}
	if (params.length != 2) {
		exec(success, error, "LocalAuth", "clearUser");
	} else {
		exec(success, error, "LocalAuth", "user", params);
	}
};

exports.checkAvailable = function() {
	return new Promise(function(resolve, reject) {
		exec(resolve, reject, "LocalAuth", "isAvailable", []);
	}).catch(function(e) {
		console.log('fail', e);
	});
};

exports.enrolled = function() {
	return new Promise(function(resolve, reject) {
		exec(resolve, reject, "LocalAuth", "enrolled", []);
	}).catch(function(e) {
		console.log('fail', e);
	});
};

exports.authenticate = function(success, error) {
	return new Promise(function(resolve, reject) {
		exec(resolve, reject, "LocalAuth", "authenticate", []);
	}).catch(function(response) {
		try {
			console.log(JSON.parse(response));
		} catch(e) {
			console.log(e, response);
		}
	});
};
