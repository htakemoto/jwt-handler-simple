package com.htakemoto.yaml;

import lombok.Data;

@Data
public final class JwtConfig
{
    private String privateKey;
    private String audience;
    private String issuer;
    private long expiryTime;
}
