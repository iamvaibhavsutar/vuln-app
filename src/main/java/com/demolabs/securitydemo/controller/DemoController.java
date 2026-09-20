package com.demolabs.securitydemo.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.w3c.dom.Document;

/**
 * EVERY endpoint in this controller is intentionally vulnerable.
 * This exists purely so a CI/CD pipeline (SAST + SCA + DAST) has real
 * findings to catch. Compare each method against its twin in the
 * fixed-app module.
 */
@RestController
public class DemoController {

    private static final String DOWNLOAD_BASE_DIR = "/opt/app/files";

    private final JdbcTemplate jdbcTemplate;

    public DemoController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    // ------------------------------------------------------------------
    // 1) SQL INJECTION (CWE-89)
    // ------------------------------------------------------------------
    @GetMapping("/search")
    public List<Map<String, Object>> search(@RequestParam String name) {
        // VULNERABLE: user input concatenated directly into the SQL string.
        // Try:  /search?name=' OR '1'='1
        String sql = "SELECT id, name FROM users WHERE name = '" + name + "'";
        return jdbcTemplate.queryForList(sql);
    }

    // ------------------------------------------------------------------
    // 2) REFLECTED XSS (CWE-79)
    // ------------------------------------------------------------------
    @GetMapping(value = "/greet", produces = MediaType.TEXT_HTML_VALUE)
    public String greet(@RequestParam String name) {
        // VULNERABLE: user input echoed back as raw, unescaped HTML.
        // Try:  /greet?name=<script>alert(document.cookie)</script>
        return "<h1>Hello " + name + "</h1>";
    }

    // ------------------------------------------------------------------
    // 3) OS COMMAND INJECTION (CWE-78)
    // ------------------------------------------------------------------
    @GetMapping("/ping")
    public String ping(@RequestParam String host) throws IOException, InterruptedException {
        // VULNERABLE: user input passed straight into a shell.
        // Try:  /ping?host=127.0.0.1;id
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", "ping -c 1 " + host);
        pb.redirectErrorStream(true);
        Process process = pb.start();
        String output = new String(process.getInputStream().readAllBytes());
        process.waitFor();
        return output;
    }

    // ------------------------------------------------------------------
    // 4) PATH TRAVERSAL (CWE-22)
    // ------------------------------------------------------------------
    @GetMapping("/download")
    public ResponseEntity<byte[]> download(@RequestParam String file) throws IOException {
        // VULNERABLE: filename used to build a path with no normalization/containment check.
        // Try:  /download?file=../../../../etc/passwd
        File target = new File(DOWNLOAD_BASE_DIR, file);
        if (!target.exists()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
        byte[] content = Files.readAllBytes(target.toPath());
        return ResponseEntity.ok(content);
    }

    // ------------------------------------------------------------------
    // 5) XXE - XML EXTERNAL ENTITY INJECTION (CWE-611)
    // ------------------------------------------------------------------
    @PostMapping(value = "/parseXml", consumes = MediaType.APPLICATION_XML_VALUE)
    public String parseXml(@RequestBody String xml) throws Exception {
        // VULNERABLE: default DocumentBuilderFactory resolves external entities/DTDs.
        // Try posting: <?xml version="1.0"?>
        //   <!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new ByteArrayInputStream(xml.getBytes()));
        return doc.getDocumentElement().getTextContent();
    }

    // ------------------------------------------------------------------
    // 6) INSECURE DESERIALIZATION (CWE-502)
    // ------------------------------------------------------------------
    @PostMapping("/deserialize")
    public String deserialize(@RequestBody String base64Payload) throws Exception {
        // VULNERABLE: raw Java deserialization of attacker-controlled bytes.
        // Combined with commons-collections 3.2.1 on the classpath this is a
        // classic ysoserial gadget-chain RCE, not just a theoretical finding.
        byte[] bytes = Base64.getDecoder().decode(base64Payload);
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
            Object obj = ois.readObject();
            return String.valueOf(obj);
        }
    }
}
