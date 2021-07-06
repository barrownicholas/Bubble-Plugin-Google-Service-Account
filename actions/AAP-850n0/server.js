function(properties, context) {
    const inputServiceEmail = properties.service_account_email;
    const inputScope = [properties.scope];
    const inputImpersonate = properties.email_to_impersonate;
    const crypto = require('crypto');
    const GOOGLE_OAUTH2_URL = 'https://oauth2.googleapis.com/token';

	const options = {
    	// use the email address of the service account, as seen in the API console
    	email: inputServiceEmail,
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
    
    function getMyAssertion(options){
		//Generate an unsigned token
		var unsignedToken = getToken(options);
        var signedToken = signToken(options,unsignedToken);
        return signedToken;
    }
    
    function signit2 (unsignedJWT, key, properties) {
    	var crypto = require('crypto');
    	var JWT_signature = crypto.createSign('RSA-SHA256').update(unsignedJWT).sign(properties.key, 'base64'),
    	signedJWT = [unsignedJWT, JWT_signature].join('.');
    	return signedJWT;
	}
    
    var rAssertion = signit2(getToken(options),properties.key, properties);
    
    
    
    return {
        assertion:rAssertion
    };
}