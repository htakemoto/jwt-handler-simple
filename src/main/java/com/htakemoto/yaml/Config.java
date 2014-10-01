package com.htakemoto.yaml;

import java.io.InputStream;

import org.yaml.snakeyaml.Yaml;

public class Config {
	
    private static ConfigRoot configRoot = new ConfigRoot();
    
    static {
        Yaml yaml = new Yaml();  
        try {
            InputStream in = Config.class.getClassLoader().getResourceAsStream("application.yml");
            Config.configRoot = yaml.loadAs(in, ConfigRoot.class);
            //System.out.println(configModel.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Other methods protected by singleton-ness
    public static ConfigRoot getConfigRoot() {
        return configRoot;
    }
}
