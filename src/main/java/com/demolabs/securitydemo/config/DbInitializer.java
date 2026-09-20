package com.demolabs.securitydemo.config;

import org.springframework.boot.CommandLineRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component
public class DbInitializer implements CommandLineRunner {

    // VULNERABLE: hardcoded credential baked into source control.
    // Real SAST tools (semgrep's "hardcoded-credentials" / "secrets" rules,
    // Gitleaks, TruffleHog, etc.) flag this exact pattern.
    public static final String DB_ADMIN_PASSWORD = "SuperSecret123!";

    private final JdbcTemplate jdbcTemplate;

    public DbInitializer(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public void run(String... args) {
        jdbcTemplate.execute(
            "CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(100), secret VARCHAR(100))"
        );
        jdbcTemplate.execute(
            "INSERT INTO users VALUES (1, 'alice', 'alice-internal-note'), " +
            "(2, 'bob', 'bob-internal-note'), " +
            "(3, 'admin', '" + DB_ADMIN_PASSWORD + "')"
        );
    }
}
