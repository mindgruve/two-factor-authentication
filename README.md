# Two-Factor-Authentication
This PHP Library implements TOTP algorithm popularized by GoogleAuthenticator.  It provides a simple, secure, and user-friendly 2-Factor-Authentication scheme.

### Algorithm ###
The Time-Based One-Time Password Algorithm is described in RFC 26238 is located at https://tools.ietf.org/html/rfc6238

### Generating Secrets ###
1) Have your users download the GoogleAuthenticator app to their smart phone.  Links to [Android Play Store](https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2&hl=en) and [Apple App Store](https://itunes.apple.com/us/app/google-authenticator/id388497605?mt=8)   

2) Generate a Secret for each user and store it in your application

        use Mindgruve\TwoFactorAuth\Secret;
        $secret = new Secret();
        // Secrets can be Serialized to a Base32 String
        $serializedSecret = $secret->asBase32();
        // Save this $serializedSecret in your application for this user
        
3. Have your user load the secret into GoogleAuthenticator. 

        use Mindgruve\TwoFactorAuth\Secret;
        $secret = new Secret();
        /**
         * Display a QR code for users to scan
         */
        <img src="<?php echo $secret->getGoogleQRCodeUrl(); ?>">
        /**
         *  Display the secret for users to enter manually.
         */
        echo $secret->asBase32();
        
3. GoogleAuthenticator will now generate a new token every 30 seconds for your user

### Validating Tokens ###
When your user logs in, prompt the user for a token.  The user opens their GoogleAuthenticator and enters in the token shown on their screen, which regenerates every 30 seconds.  To validate the token, you load the user's secret (from your database for instance) and use the helper function isValidToken() to validate the user supplied token.

        use Mindgruve\TwoFactorAuth\Authenticator;
        use Mindgruve\TwoFactorAuth\Secret;
        use Mindgruve\TwoFactorAuth\Token;
        
        /**
         * Load the $serializedSecret for the user
         * The $tokenString is value submitted by the user
         */
         $secret = new Secret($serializedSecret);
         $token = new Token($tokenString);
         $authenticator = new Authenticator();
         if($authenticator->isValidToken($secret, $token)){
            // access granted
         } else {
            // access denied
         }
         
         
         