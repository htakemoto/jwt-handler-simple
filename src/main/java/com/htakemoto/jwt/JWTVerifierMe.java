package com.htakemoto.jwt;

import com.auth0.jwt.JWTVerifier;
import com.htakemoto.yaml.Config;


public class JWTVerifierMe extends JWTVerifier {

    private static final String PRIVATE_KEY = Config.getConfigRoot().getJwtConfig().getPrivateKey();
    private static final String AUDIENCE = Config.getConfigRoot().getJwtConfig().getAudience();
    private static final String ISSUER = Config.getConfigRoot().getJwtConfig().getIssuer(); // (client_id)
    
    public JWTVerifierMe() {
        super(PRIVATE_KEY, AUDIENCE, ISSUER);
    }
}

