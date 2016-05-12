var localAuth = {
	authenticate: function(string){
		return new Promise(function(resolve, reject) {
			cordova.exec(
				resolve,
				reject,
				"LocalAuth",
				"authenticate",
				[string,
					{
						clientId: "hello world",//alias for app package name
                		clientSecret: "foo bar"//client secret for android key store

					}
				]
			);
		});
	},
	supported: function(){
		return new Promise(function(resolve, reject) {
			cordova.exec(
				resolve,
				reject,
				"LocalAuth",
				"capable",
				[]
			);
		});
	}
};

module.exports = localAuth;
