(ns secure_code_analyzer.core
  (:require [babashka.cli :as cli]
            [babashka.fs :as fs]
            [clojure.string :as str]
            [cheshire.core :as json]))

;;; ---- Language detection ----

(def extension->lang
  {"py"   "python"
   "pyw"  "python"
   "js"   "javascript"
   "jsx"  "javascript"
   "ts"   "typescript"
   "tsx"  "typescript"
   "java" "java"
   "go"   "go"})

(defn detect-language [filepath]
  (get extension->lang (fs/extension filepath)))

;;; ---- Severity ----

(def severity-levels
  {"critical" 4 "high" 3 "medium" 2 "low" 1 "info" 0})

(defn severity>= [sev min-sev]
  (>= (get severity-levels sev 0)
      (get severity-levels min-sev 0)))

;;; ---- OWASP Vulnerability Rules ----

(def rules
  [;; A03:2021 — SQL Injection (CWE-89)
   {:id "sql-injection"
    :name "SQL Injection"
    :severity "critical"
    :cwe "CWE-89"
    :owasp "A03:2021"
    :description "String concatenation in SQL queries allows injection attacks"
    :patterns
    [;; Python: f-string or .format in execute/query
     {:langs #{"python"}
      :regex #"(?i)(?:execute|query)\s*\(\s*f[\"']"
      :message "SQL query uses f-string in execute/query - use parameterized queries"}
     ;; Python: string concat with SQL keywords
     {:langs #{"python"}
      :regex #"(?i)[\"'](?:SELECT|INSERT|UPDATE|DELETE)\b[^\"']*[\"']\s*\+"
      :message "SQL query built with string concatenation - use parameterized queries"}
     ;; Python: %-formatting with SQL
     {:langs #{"python"}
      :regex #"(?i)[\"'](?:SELECT|INSERT|UPDATE|DELETE)\b[^\"']*%s[^\"']*[\"']\s*%"
      :message "SQL query uses %-formatting - use parameterized queries"}
     ;; JavaScript/TypeScript: template literal
     {:langs #{"javascript" "typescript"}
      :regex #"(?i)(?:query|execute)\s*\(\s*`[^`]*(?:SELECT|INSERT|UPDATE|DELETE)\b"
      :message "SQL query uses template literal - use parameterized queries"}
     ;; JavaScript/TypeScript: string concat
     {:langs #{"javascript" "typescript"}
      :regex #"(?i)[\"'](?:SELECT|INSERT|UPDATE|DELETE)\b[^\"']*[\"']\s*\+"
      :message "SQL query built with string concatenation - use parameterized queries"}
     ;; Java: string concat in executeQuery/executeUpdate
     {:langs #{"java"}
      :regex #"(?i)(?:executeQuery|executeUpdate|execute)\s*\(\s*[\"'](?:SELECT|INSERT|UPDATE|DELETE)\b[^\"']*[\"']\s*\+"
      :message "SQL query with string concatenation - use PreparedStatement with parameters"}
     ;; Go: fmt.Sprintf in Query/Exec
     {:langs #{"go"}
      :regex #"(?i)(?:Query|Exec|QueryRow)\s*\(\s*fmt\.Sprintf\s*\("
      :message "SQL query uses fmt.Sprintf - use parameterized queries"}
     ;; Go: string concat
     {:langs #{"go"}
      :regex #"(?i)(?:Query|Exec|QueryRow)\s*\(\s*[\"'](?:SELECT|INSERT|UPDATE|DELETE)\b[^\"']*[\"']\s*\+"
      :message "SQL query with string concatenation - use parameterized queries"}]}

   ;; A03:2021 — XSS (CWE-79)
   {:id "xss"
    :name "Cross-Site Scripting (XSS)"
    :severity "high"
    :cwe "CWE-79"
    :owasp "A03:2021"
    :description "Unescaped user input rendered in HTML context"
    :patterns
    [{:langs #{"javascript" "typescript"}
      :regex #"\.innerHTML\s*="
      :message "Direct innerHTML assignment - use textContent or sanitize input"}
     {:langs #{"javascript" "typescript"}
      :regex #"document\.write\s*\("
      :message "document.write with potential unsanitized content"}
     {:langs #{"javascript" "typescript"}
      :regex #"dangerouslySetInnerHTML"
      :message "React dangerouslySetInnerHTML - ensure content is sanitized"}
     {:langs #{"python"}
      :regex #"render_template_string\s*\("
      :message "render_template_string with potential user input - use render_template"}
     {:langs #{"python"}
      :regex #"Markup\s*\("
      :message "Markup() bypasses auto-escaping - ensure content is safe"}
     {:langs #{"python"}
      :regex #"\|\s*safe\b"
      :message "Jinja2 |safe filter disables auto-escaping"}
     {:langs #{"java"}
      :regex #"(?:getWriter\(\)|out)\.(?:print|println|write)\s*\(\s*[\"']<"
      :message "Unescaped HTML in response output - use output encoding"}
     {:langs #{"go"}
      :regex #"template\.HTML\s*\("
      :message "template.HTML bypasses Go template auto-escaping"}
     {:langs #{"go"}
      :regex #"fmt\.Fprintf\s*\(\s*w\s*,\s*[\"']<"
      :message "Unescaped HTML written to response - use html/template"}]}

   ;; A01:2021 — Path Traversal (CWE-22)
   {:id "path-traversal"
    :name "Path Traversal"
    :severity "high"
    :cwe "CWE-22"
    :owasp "A01:2021"
    :description "User input used in file path without sanitization"
    :patterns
    [{:langs #{"python"}
      :regex #"open\s*\(\s*request\."
      :message "User input in file open - validate and sanitize path"}
     {:langs #{"python"}
      :regex #"send_file\s*\(\s*request\."
      :message "User input in send_file - validate and restrict path"}
     {:langs #{"python"}
      :regex #"os\.path\.join\s*\([^)]*request\."
      :message "Request data in os.path.join - validate path components"}
     {:langs #{"javascript" "typescript"}
      :regex #"(?:readFile|readFileSync|createReadStream)\s*\(\s*req\."
      :message "User input in file read - validate and sanitize path"}
     {:langs #{"javascript" "typescript"}
      :regex #"path\.join\s*\([^)]*req\."
      :message "Request data in path.join - validate path components"}
     {:langs #{"java"}
      :regex #"new\s+File\s*\(\s*request\.getParameter"
      :message "User input in File constructor - use canonical path validation"}
     {:langs #{"go"}
      :regex #"os\.Open\s*\(\s*r\."
      :message "Request data in os.Open - use filepath.Clean and validate"}
     {:langs #{"python" "javascript" "typescript" "java" "go"}
      :regex #"\.\./|\.\.\\\\|%2e%2e%2f|%2e%2e/"
      :message "Directory traversal sequence detected in code"}]}

   ;; A07:2021 — Hardcoded Secrets (CWE-798)
   {:id "hardcoded-secrets"
    :name "Hardcoded Secrets"
    :severity "critical"
    :cwe "CWE-798"
    :owasp "A07:2021"
    :description "Credentials or API keys hardcoded in source code"
    :patterns
    [{:langs #{"python" "javascript" "typescript" "java" "go"}
      :regex #"(?i)(?:password|passwd|pwd)\s*[:=]\s*[\"'][^\"']{4,}[\"']"
      :message "Hardcoded password - use environment variables or secrets manager"}
     {:langs #{"python" "javascript" "typescript" "java" "go"}
      :regex #"(?i)(?:api[_-]?key|api[_-]?secret|secret[_-]?key|access[_-]?key)\s*[:=]\s*[\"'][^\"']{4,}[\"']"
      :message "Hardcoded API key/secret - use environment variables or secrets manager"}
     {:langs #{"python" "javascript" "typescript" "java" "go"}
      :regex #"(?i)AWS_SECRET_ACCESS_KEY\s*[:=]\s*[\"'][^\"']{4,}[\"']"
      :message "Hardcoded AWS credential - use IAM roles or secrets manager"}
     {:langs #{"python" "javascript" "typescript" "java" "go"}
      :regex #"ghp_[a-zA-Z0-9]{36}|sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}"
      :message "Known secret token pattern detected (GitHub PAT / OpenAI / AWS)"}]}

   ;; A02:2021 — Insecure Random (CWE-330)
   {:id "insecure-random"
    :name "Insecure Random Number Generation"
    :severity "medium"
    :cwe "CWE-330"
    :owasp "A02:2021"
    :description "Weak random number generation used in security context"
    :patterns
    [{:langs #{"javascript" "typescript"}
      :regex #"Math\.random\s*\("
      :message "Math.random() is not cryptographically secure - use crypto.getRandomValues()"}
     {:langs #{"python"}
      :regex #"random\.(?:random|randint|choice|randrange|uniform)\s*\("
      :message "random module is not cryptographically secure - use secrets module"}
     {:langs #{"java"}
      :regex #"new\s+Random\s*\(|Math\.random\s*\("
      :message "java.util.Random is predictable - use java.security.SecureRandom"}
     {:langs #{"go"}
      :regex #"math/rand"
      :message "math/rand is not cryptographically secure - use crypto/rand"}]}

   ;; A03:2021 — Eval / Code Injection (CWE-95)
   {:id "eval-usage"
    :name "Dynamic Code Evaluation"
    :severity "critical"
    :cwe "CWE-95"
    :owasp "A03:2021"
    :description "Dynamic evaluation of code strings enables code injection"
    :patterns
    [{:langs #{"python"}
      :regex #"\beval\s*\("
      :message "eval() enables code injection - use safe alternatives"}
     {:langs #{"python"}
      :regex #"\bexec\s*\("
      :message "exec() enables code injection - use safe alternatives"}
     {:langs #{"python"}
      :regex #"__import__\s*\("
      :message "__import__() with dynamic input enables module injection"}
     {:langs #{"javascript" "typescript"}
      :regex #"\beval\s*\("
      :message "eval() enables code injection - use safe alternatives"}
     {:langs #{"javascript" "typescript"}
      :regex #"new\s+Function\s*\("
      :message "new Function() enables code injection - use safe alternatives"}
     {:langs #{"java"}
      :regex #"Runtime\.getRuntime\(\)\.exec\s*\("
      :message "Runtime.exec() - validate input and use ProcessBuilder with allowlist"}
     {:langs #{"go"}
      :regex #"exec\.Command\s*\("
      :message "exec.Command - validate input and use allowlist for commands"}]}

   ;; A01:2021 — Open Redirect (CWE-601)
   {:id "open-redirect"
    :name "Open Redirect"
    :severity "medium"
    :cwe "CWE-601"
    :owasp "A01:2021"
    :description "Unvalidated URL redirect using user-controlled input"
    :patterns
    [{:langs #{"python"}
      :regex #"redirect\s*\(\s*request\."
      :message "Unvalidated redirect from request data - validate against allowlist"}
     {:langs #{"javascript" "typescript"}
      :regex #"res\.redirect\s*\(\s*req\."
      :message "Unvalidated redirect from request data - validate against allowlist"}
     {:langs #{"java"}
      :regex #"sendRedirect\s*\(\s*request\.getParameter"
      :message "Unvalidated redirect from request parameter - validate against allowlist"}
     {:langs #{"go"}
      :regex #"http\.Redirect\s*\([^,]+,\s*[^,]+,\s*r\."
      :message "Unvalidated redirect from request - validate against allowlist"}]}

   ;; A01:2021 — Missing CSRF (CWE-352)
   {:id "missing-csrf"
    :name "Missing CSRF Protection"
    :severity "medium"
    :cwe "CWE-352"
    :owasp "A01:2021"
    :description "State-changing operations without CSRF protection"
    :patterns
    [{:langs #{"python"}
      :regex #"@csrf_exempt"
      :message "CSRF protection explicitly disabled - ensure this is intentional"}
     {:langs #{"java"}
      :regex #"\.csrf\s*\(\s*\)\s*\.disable\s*\("
      :message "Spring Security CSRF disabled - ensure this is intentional"}
     {:langs #{"javascript" "typescript"}
      :regex #"(?i)csrf.*(?:false|disable|off)"
      :message "CSRF protection may be disabled - verify configuration"}]}])

;;; ---- Scanner ----

(defn find-source-files [dir]
  (let [exts ["py" "pyw" "js" "jsx" "ts" "tsx" "java" "go"]]
    (->> exts
         (mapcat #(fs/glob dir (str "**/*." %)))
         (map str)
         (remove #(str/includes? % "/node_modules/"))
         (remove #(str/includes? % "/.git/"))
         (distinct)
         sort)))

(defn scan-file [filepath]
  (let [lang (detect-language filepath)]
    (when lang
      (try
        (let [lines (str/split-lines (slurp filepath))]
          (->> lines
               (map-indexed
                (fn [idx line]
                  (for [rule rules
                        pattern (:patterns rule)
                        :when (contains? (:langs pattern) lang)
                        :when (re-find (:regex pattern) line)]
                    {:rule-id   (:id rule)
                     :rule-name (:name rule)
                     :severity  (:severity rule)
                     :cwe       (:cwe rule)
                     :owasp     (:owasp rule)
                     :message   (:message pattern)
                     :file      filepath
                     :line      (inc idx)
                     :code      (str/trim line)})))
               (apply concat)
               vec))
        (catch Exception e
          (binding [*out* *err*]
            (println (format "Warning: could not read %s: %s" filepath (.getMessage e))))
          [])))))

(defn scan-directory [dir min-severity]
  (let [files    (find-source-files dir)
        findings (->> files
                      (mapcat scan-file)
                      (filter #(severity>= (:severity %) min-severity))
                      (sort-by (fn [f] [(- (get severity-levels (:severity f) 0))
                                        (:file f)
                                        (:line f)]))
                      vec)]
    {:directory           (str (fs/absolutize dir))
     :files-scanned       (count files)
     :total-findings      (count findings)
     :findings-by-severity (frequencies (map :severity findings))
     :findings-by-rule     (frequencies (map :rule-id findings))
     :findings            findings}))

;;; ---- Output formatting ----

(defn format-text [{:keys [directory files-scanned total-findings
                           findings-by-severity findings]}]
  (let [header [(str "SecureCodeAnalyzer \u2014 Scan Results")
                (str "================================")
                (format "Directory: %s" directory)
                (format "Files scanned: %d" files-scanned)
                (format "Total findings: %d" total-findings)
                ""]
        severity-summary
        (when (pos? total-findings)
          [(format "By severity: %s"
                   (str/join ", "
                     (for [[sev cnt] (sort-by (fn [[s _]] (- (get severity-levels s 0)))
                                              findings-by-severity)]
                       (format "%s=%d" sev cnt))))
           ""])
        finding-lines
        (for [{:keys [severity rule-id file line message code cwe]} findings]
          (format "[%s] %s (%s)\n  %s:%d\n  %s\n  > %s"
                  (str/upper-case severity) rule-id cwe
                  file line
                  message
                  (if (> (count code) 120)
                    (str (subs code 0 117) "...")
                    code)))
        no-findings (when (zero? total-findings)
                      ["No security issues found."])]
    (str/join "\n" (concat header severity-summary finding-lines no-findings [""]))))

(defn format-json [results]
  (json/generate-string results {:pretty true}))

(defn format-edn [results]
  (with-out-str (clojure.pprint/pprint results)))

(defn format-output [results fmt]
  (case fmt
    "json" (format-json results)
    "edn"  (format-edn results)
    (format-text results)))

;;; ---- CLI ----

(def cli-spec
  {:dir      {:desc "Directory to scan" :default "." :alias :d}
   :format   {:desc "Output format: text, json, edn" :default "text" :alias :f}
   :severity {:desc "Minimum severity: info, low, medium, high, critical" :default "medium" :alias :s}
   :help     {:desc "Show help" :alias :h :coerce :boolean}})

(defn -main [& args]
  (let [opts (cli/parse-opts args {:spec cli-spec})]
    (when (:help opts)
      (println "secure-code-analyzer \u2014 Scan code for OWASP security vulnerabilities")
      (println)
      (println "Usage: bb run [options]")
      (println)
      (println (cli/format-opts {:spec cli-spec}))
      (println)
      (println "Supported languages: Python, JavaScript/TypeScript, Java, Go")
      (println "Detects: sql-injection, xss, path-traversal, hardcoded-secrets,")
      (println "         insecure-random, eval-usage, open-redirect, missing-csrf")
      (System/exit 0))
    (let [dir      (:dir opts)
          fmt      (:format opts)
          severity (:severity opts "medium")]
      (when-not (fs/exists? dir)
        (binding [*out* *err*]
          (println (format "Error: directory '%s' does not exist" dir)))
        (System/exit 2))
      (let [results (scan-directory dir severity)
            output  (format-output results fmt)]
        (println output)
        (if (pos? (:total-findings results))
          (System/exit 1)
          (System/exit 0))))))

(when (= *file* (System/getProperty "babashka.file"))
  (apply -main *command-line-args*))
