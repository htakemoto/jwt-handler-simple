package com.htakemoto.yaml;

import java.util.Date;

import lombok.Data;

@Data
public final class ConfigRoot {
	
    private String version;
    private Date released;
    private JwtConfig jwtConfig;
}
