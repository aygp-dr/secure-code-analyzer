/**
 * Intentionally vulnerable Java code for testing SecureCodeAnalyzer.
 */
import java.sql.*;
import java.io.*;
import java.util.Random;
import javax.servlet.http.*;

public class VulnerableApp {

    // SQL Injection — string concatenation in executeQuery
    void getUser(Connection conn, String name) throws Exception {
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE name='" + name + "'");
    }

    // Hardcoded secrets
    String password = "database_password_123";
    String api_key = "AKIAIOSFODNN7EXAMPLEQ";

    // Insecure random
    void generateToken() {
        Random rand = new Random();
        int token = rand.nextInt();
    }

    // Path traversal — user input in File constructor
    void readFile(HttpServletRequest request) throws Exception {
        File f = new File(request.getParameter("path"));
        FileInputStream fis = new FileInputStream(f);
    }

    // XSS — unescaped HTML output
    void respond(HttpServletResponse response, String userInput) throws Exception {
        response.getWriter().write("<div>" + userInput + "</div>");
    }

    // CSRF disabled
    void configureSecurity(HttpSecurity http) throws Exception {
        http.csrf().disable();
    }

    // Open redirect
    void handleRedirect(HttpServletRequest request, HttpServletResponse response) throws Exception {
        response.sendRedirect(request.getParameter("url"));
    }

    // Command injection via Runtime.exec
    void execute(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);
    }
}
