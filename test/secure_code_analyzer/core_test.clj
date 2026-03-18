(ns secure_code_analyzer.core_test
  (:require [clojure.test :refer [deftest testing is run-tests]]
            [clojure.string :as str]
            [secure_code_analyzer.core :as sca]
            [cheshire.core :as json]))

;; ---- Unit tests ----

(deftest test-detect-language
  (testing "Language detection from file extension"
    (is (= "python" (sca/detect-language "test.py")))
    (is (= "python" (sca/detect-language "script.pyw")))
    (is (= "javascript" (sca/detect-language "app.js")))
    (is (= "javascript" (sca/detect-language "component.jsx")))
    (is (= "typescript" (sca/detect-language "app.ts")))
    (is (= "typescript" (sca/detect-language "component.tsx")))
    (is (= "java" (sca/detect-language "Main.java")))
    (is (= "go" (sca/detect-language "main.go")))
    (is (nil? (sca/detect-language "style.css")))
    (is (nil? (sca/detect-language "README.md")))))

(deftest test-severity-comparison
  (testing "Severity ordering"
    (is (sca/severity>= "critical" "critical"))
    (is (sca/severity>= "critical" "high"))
    (is (sca/severity>= "critical" "medium"))
    (is (sca/severity>= "high" "medium"))
    (is (sca/severity>= "medium" "medium"))
    (is (sca/severity>= "medium" "low"))
    (is (sca/severity>= "medium" "info"))
    (is (not (sca/severity>= "low" "medium")))
    (is (not (sca/severity>= "info" "high")))
    (is (not (sca/severity>= "medium" "critical")))))

;; ---- Integration tests per language ----

(deftest test-python-vulnerabilities
  (testing "Python vulnerability detection"
    (let [results    (sca/scan-directory "test/fixtures" "info")
          findings   (:findings results)
          py-vulns   (filter #(str/ends-with? (:file %) "vulnerable.py") findings)
          rule-ids   (set (map :rule-id py-vulns))]
      (is (pos? (count py-vulns)) "Should find vulnerabilities in vulnerable.py")
      (is (contains? rule-ids "sql-injection"))
      (is (contains? rule-ids "hardcoded-secrets"))
      (is (contains? rule-ids "eval-usage"))
      (is (contains? rule-ids "xss"))
      (is (contains? rule-ids "open-redirect"))
      (is (contains? rule-ids "path-traversal"))
      (is (contains? rule-ids "missing-csrf"))
      (is (contains? rule-ids "insecure-random")))))

(deftest test-javascript-vulnerabilities
  (testing "JavaScript vulnerability detection"
    (let [results    (sca/scan-directory "test/fixtures" "info")
          findings   (:findings results)
          js-vulns   (filter #(str/ends-with? (:file %) "vulnerable.js") findings)
          rule-ids   (set (map :rule-id js-vulns))]
      (is (pos? (count js-vulns)) "Should find vulnerabilities in vulnerable.js")
      (is (contains? rule-ids "sql-injection"))
      (is (contains? rule-ids "xss"))
      (is (contains? rule-ids "hardcoded-secrets"))
      (is (contains? rule-ids "eval-usage"))
      (is (contains? rule-ids "insecure-random"))
      (is (contains? rule-ids "path-traversal"))
      (is (contains? rule-ids "open-redirect")))))

(deftest test-java-vulnerabilities
  (testing "Java vulnerability detection"
    (let [results    (sca/scan-directory "test/fixtures" "info")
          findings   (:findings results)
          java-vulns (filter #(str/ends-with? (:file %) "vulnerable.java") findings)
          rule-ids   (set (map :rule-id java-vulns))]
      (is (pos? (count java-vulns)) "Should find vulnerabilities in vulnerable.java")
      (is (contains? rule-ids "sql-injection"))
      (is (contains? rule-ids "hardcoded-secrets"))
      (is (contains? rule-ids "insecure-random"))
      (is (contains? rule-ids "path-traversal"))
      (is (contains? rule-ids "xss"))
      (is (contains? rule-ids "missing-csrf"))
      (is (contains? rule-ids "eval-usage"))
      (is (contains? rule-ids "open-redirect")))))

(deftest test-go-vulnerabilities
  (testing "Go vulnerability detection"
    (let [results    (sca/scan-directory "test/fixtures" "info")
          findings   (:findings results)
          go-vulns   (filter #(str/ends-with? (:file %) "vulnerable.go") findings)
          rule-ids   (set (map :rule-id go-vulns))]
      (is (pos? (count go-vulns)) "Should find vulnerabilities in vulnerable.go")
      (is (contains? rule-ids "sql-injection"))
      (is (contains? rule-ids "hardcoded-secrets"))
      (is (contains? rule-ids "insecure-random"))
      (is (contains? rule-ids "open-redirect"))
      (is (contains? rule-ids "path-traversal"))
      (is (contains? rule-ids "eval-usage"))
      (is (contains? rule-ids "xss")))))

;; ---- Negative test ----

(deftest test-clean-file-no-findings
  (testing "Clean file produces no findings"
    (let [findings (sca/scan-file "test/fixtures/clean.py")]
      (is (empty? findings) "clean.py should have zero findings"))))

;; ---- Severity filter ----

(deftest test-severity-filter
  (testing "Severity filter excludes lower-severity findings"
    (let [all-results      (sca/scan-directory "test/fixtures" "info")
          critical-results (sca/scan-directory "test/fixtures" "critical")]
      (is (> (:total-findings all-results) (:total-findings critical-results))
          "Filtering to critical should return fewer findings")
      (is (every? #(= "critical" (:severity %)) (:findings critical-results))
          "All findings should be critical"))))

;; ---- Output format tests ----

(deftest test-output-formats
  (testing "JSON output is valid"
    (let [results  (sca/scan-directory "test/fixtures" "info")
          json-str (sca/format-output results "json")]
      (is (string? json-str))
      (is (map? (json/parse-string json-str true)))))
  (testing "Text output contains header"
    (let [results (sca/scan-directory "test/fixtures" "info")
          text    (sca/format-output results "text")]
      (is (str/includes? text "SecureCodeAnalyzer"))))
  (testing "EDN output is valid"
    (let [results (sca/scan-directory "test/fixtures" "info")
          edn-str (sca/format-output results "edn")]
      (is (string? edn-str))
      (is (str/includes? edn-str ":total-findings")))))

;; ---- Finding structure ----

(deftest test-finding-structure
  (testing "Each finding has required keys"
    (let [results  (sca/scan-directory "test/fixtures" "info")
          findings (:findings results)]
      (doseq [f findings]
        (is (contains? f :rule-id))
        (is (contains? f :severity))
        (is (contains? f :cwe))
        (is (contains? f :file))
        (is (contains? f :line))
        (is (contains? f :message))
        (is (contains? f :code))))))

;; ---- Run tests when executed directly ----

(when (= *file* (System/getProperty "babashka.file"))
  (let [{:keys [fail error]} (run-tests)]
    (when (pos? (+ fail error))
      (System/exit 1))))
