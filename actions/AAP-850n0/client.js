function(properties, context) {
    const inputServiceEmail = 'based-on-website@service-account-holder-296723.iam.gserviceaccount.com';
    const inputScope = ['https://www.googleapis.com/auth/admin.directory.group.readonly'];
    var inputKeyFile = context.pem_file;
    const inputImpersonate = 'nbarrow@risocialstudies.org';
    const crypto = require('crypto');
    const GOOGLE_OAUTH2_URL = 'https://oauth2.googleapis.com/token';

	const options = {
    	// use the email address of the service account, as seen in the API console
    	email: inputServiceEmail,
    	// use the PEM file we generated from the downloaded key
    	keyFile: inputKeyFile,
    	// specify the scopes you which to access
    	scopes: inputScope,
    	// impersonate a super-admin for request
    	delegationEmail: inputImpersonate
	}

	function getToken(options) {

  		var iat = Math.floor(new Date().getTime() / 1000);
  		var exp = iat + Math.floor((options.expiration || 60 * 60 * 1000) / 1000);
    
  		var claims = {
				iss: options.email,
				scope: options.scopes.join(' '),
				aud: GOOGLE_OAUTH2_URL,
				exp: exp,
				iat: iat
  		};
    
  		if (options.delegationEmail) {
			claims.sub = options.delegationEmail;
  		}

  		var JWT_header = new Buffer(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString('base64');
  		var JWT_claimset = new Buffer(JSON.stringify(claims)).toString('base64');
  		var unsignedJWT = [JWT_header, JWT_claimset].join('.');
        
  		return unsignedJWT; //returns an unsigned JWT
	}

	//Generate a signed token
	function signToken(options, unsignedJWT) {

  		var fs = require('fs');
  		var crypto = require('crypto');

  		var key = fs.readFileSync(options.keyFile);

  
  		var JWT_signature = crypto.createSign('RSA-SHA256').update(unsignedJWT).sign(key, 'base64');
  		var signedJWT = [unsignedJWT, JWT_signature].join('.');
  		return signedJWT;
	}
    
    function run_server(options){
		//Generate an unsigned token
		var unsignedToken = getToken(options);
        var signedToken = signToken(options,unsignedToken);
        return {"assertion":signedToken};
    }
    
    return run_server(options);
}