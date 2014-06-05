package com.htakemoto.jwt;

import lombok.Data;

@Data
public class JwtClaims
{
    private String iss;
    private long iat;
    private long exp;
    private String usr;
    private String aud;
}
