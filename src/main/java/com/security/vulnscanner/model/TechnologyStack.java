package com.security.vulnscanner.model;

import lombok.Data;
import java.util.ArrayList;
import java.util.List;

@Data
public class TechnologyStack {
    private Frontend frontend;
    private Backend backend;
    private Database database;
    private String cdn;
    private String waf;
    private List<Library> jsLibraries = new ArrayList<>();
    private String cms;
    private SecurityFeatures securityFeatures = new SecurityFeatures();
    
    @Data
    public static class Library {
        private String name;
        private String version;
        private int confidence;
    }
    
    @Data
    public static class SecurityFeatures {
        private boolean csrfProtection;
        private String authMethod;
        private boolean hasWAF;
        private boolean hasRateLimiting;
    }
    
    public enum Frontend {
        REACT, ANGULAR, VUE, NEXT_JS, NUXT, SVELTE, UNKNOWN
    }
    
    public enum Backend {
        SPRING_BOOT, DJANGO, EXPRESS, LARAVEL, ASP_NET, RUBY_ON_RAILS, FLASK, FASTAPI, UNKNOWN
    }
    
    public enum Database {
        POSTGRESQL, MYSQL, MONGODB, REDIS, MSSQL, ORACLE, UNKNOWN
    }
}
