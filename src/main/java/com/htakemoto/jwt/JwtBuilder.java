package com.htakemoto.jwt;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

import com.google.gson.Gson;
import com.htakemoto.yaml.Config;

public class JwtBuilder {
    
    // NOTE: The JWT must conform with the general format rules specified below
    //       http://tools.ietf.org/html/draft-jones-json-web-token-10
    
    private static final String PRIVATE_KEY = Config.getConfigRoot().getJwtConfig().getPrivateKey();
    private static final String AUDIENCE = Config.getConfigRoot().getJwtConfig().getAudience();
    private static final String ISSUER = Config.getConfigRoot().getJwtConfig().getIssuer(); // (client_id)
//    private static final long TOKEN_EXPIRY_TIME = Config.getGeneralConfig().getJwtConfig().getExpiryTime(); // minutes
    private static final long TOKEN_EXPIRY_TIME = 20L; // minutes
    
    public static String generateJWT(JwtClaims claims) throws InvalidKeyException, NoSuchAlgorithmException, UnrecoverableKeyException, SignatureException, KeyStoreException, CertificateException, FileNotFoundException, IOException {

        StringBuffer token = new StringBuffer();
        
        Gson gson = new Gson();
        
        //Encode JWT Header and add it to token
        JwtHeader header = new JwtHeader();
        header.setAlg("HS256");
        header.setTyp("JWT");
        String headerJsonString = gson.toJson(header);
        token.append(Base64.encodeBase64URLSafeString(headerJsonString.getBytes("UTF-8")));
        
        //Separate with a period
        token.append(".");
        
        //Create JWT Claims and add it to token
        claims.setAud(AUDIENCE);
        claims.setIss(ISSUER);
        claims.setIat(System.currentTimeMillis() / 1000L);
        claims.setExp(claims.getIat() + TOKEN_EXPIRY_TIME * 1000L);
        String claimsJsonString = gson.toJson(claims);
        token.append(Base64.encodeBase64URLSafeString(claimsJsonString.getBytes("UTF-8")));
        
        //Create JWT Footer (signature) and add it to token
        String signed256 = generateSignature(token.toString());
        token.append("." + signed256);
        
        return token.toString();
    }

    private static String generateSignature(String signingInput) throws NoSuchAlgorithmException, InvalidKeyException {
        
        String algorithm = "HmacSHA256";
        Boolean isSecretBase64Encoded = true;

        Mac mac = Mac.getInstance(algorithm);
        
        if (isSecretBase64Encoded) {
            mac.init(new SecretKeySpec(Base64.decodeBase64(PRIVATE_KEY), algorithm));
        }
        else {
            mac.init(new SecretKeySpec(PRIVATE_KEY.getBytes(), algorithm));
        }
        
        return Base64.encodeBase64URLSafeString(mac.doFinal(signingInput.getBytes()));
    }

//    private static String generateSignature(String signingInput, String sharedSecret) 
//            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, KeyStoreException, CertificateException, FileNotFoundException, IOException, UnrecoverableKeyException {
//        //Load the private key from a keystore
//        KeyStore keystore = KeyStore.getInstance("JKS");
//        keystore.load(new FileInputStream("./path/to/keystore.jks"), "keystorepassword".toCharArray());
//        PrivateKey privateKey = (PrivateKey) keystore.getKey("certalias", "privatekeypassword".toCharArray());
//        
//        //Sign the JWT Header + "." + JWT Claims Object
//        Signature signature = Signature.getInstance("SHA256withRSA");
//        signature.initSign(privateKey);
//        signature.update(signingInput.getBytes("UTF-8"));
//        String signedPayload = Base64.encodeBase64URLSafeString(signature.sign());
//        return signedPayload;
//    }
}
