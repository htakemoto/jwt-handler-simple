package com.htakemoto;

import java.security.SignatureException;
import java.util.Map;

import com.htakemoto.jwt.JwtClaims;
import com.htakemoto.jwt.JwtUtil;
import com.htakemoto.yaml.Config;

public class Application {
	
    public static void main(String[] args) throws Exception {
        
        // Test for YAML
        System.out.println("Version  " + Config.getConfigRoot().getVersion());
        System.out.println("Released " + Config.getConfigRoot().getReleased());
        
        // set custom value(s) into jwt
        JwtClaims jwtClaims = new JwtClaims();
        jwtClaims.setUsr("takemohi");
        
        // Encode JWT
        System.out.println("###### Encode JWT ######");
        String jwt = JwtUtil.generateJWT(jwtClaims);
        System.out.println("JWT      " + jwt);
        
        // Decode JWT
        System.out.println("###### Decode JWT ######");
        try {
            // Decode with verification of Token
            Map<String,Object> decodedPayload = JwtUtil.verify(jwt);
            // Check expiry date
            if (decodedPayload.get("exp") != null &&
                    ((Integer)decodedPayload.get("exp") >= (System.currentTimeMillis() / 1000L))) {
                // Get custom fields from decoded Payload
                System.out.println("JWT(iss) " + decodedPayload.get("iss"));
                System.out.println("JWT(iat) " + decodedPayload.get("iat"));
                System.out.println("JWT(exp) " + decodedPayload.get("exp"));
                System.out.println("JWT(aud) " + decodedPayload.get("aud"));
                System.out.println("JWT(usr) " + decodedPayload.get("usr"));
            }
            else {
                System.err.println("Token is expired!");
            }
        } catch (SignatureException signatureException) {
            System.err.println("Invalid signature!");
        } catch (IllegalStateException illegalStateException) {
            System.err.println("Invalid Token! " + illegalStateException);
        }
    }
}
