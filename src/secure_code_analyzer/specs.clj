(ns secure_code_analyzer.specs
  "Data specs for secure-code-analyzer (https://clojure.org/guides/spec).
  Function specs (s/fdef) live next to each defn in secure_code_analyzer.core."
  (:require [cheshire.core :as json]
            [clojure.edn :as edn]
            [clojure.spec.alpha :as s]
            [clojure.spec.gen.alpha :as gen]
            [clojure.string :as str]))

;; --- Vocabulary ---

(s/def ::lang #{"python" "javascript" "typescript" "java" "go"})
(s/def ::severity #{"critical" "high" "medium" "low" "info"})
;; A severity name as given on the CLI (--severity): unknown names rank as info.
(s/def ::severity-name
  (s/with-gen string? #(gen/elements ["critical" "high" "medium" "low" "info" "bogus"])))
(s/def ::rule-id #{"sql-injection" "xss" "path-traversal" "hardcoded-secrets"
                   "insecure-random" "eval-usage" "open-redirect" "missing-csrf"})
(s/def ::cwe (s/with-gen (s/and string? #(re-matches #"CWE-\d+" %))
               #(gen/fmap (fn [n] (str "CWE-" n)) (gen/choose 1 1500))))
(s/def ::owasp (s/with-gen (s/and string? #(re-matches #"A\d{2}:2021" %))
                 #(gen/elements ["A01:2021" "A02:2021" "A03:2021" "A07:2021"])))

;; A relative or absolute file path, as a string or java.nio.file.Path.
(defn- gen-path-string []
  (gen/fmap (fn [[dirs base ext]]
              (str/join "/" (conj dirs (cond-> base ext (str "." ext)))))
            (gen/tuple (gen/vector (gen/elements ["src" "app" "a b" "node_modules"]) 0 3)
                       (gen/elements ["main" "App" "views" "db" "x"])
                       (gen/elements [nil "py" "pyw" "js" "jsx" "ts" "tsx" "java" "go" "css" "md" "PY"]))))

(s/def ::path-string (s/with-gen (s/and string? seq) gen-path-string))
(s/def ::path-like
  (s/with-gen (s/or :string ::path-string
                    :path #(instance? java.nio.file.Path %))
    gen-path-string))

;; --- Rule database (secure_code_analyzer.core/rules) ---

(s/def ::id ::rule-id)
(s/def ::name string?)
(s/def ::description string?)
(s/def ::langs (s/coll-of ::lang :kind set? :min-count 1))
(s/def ::regex
  (s/with-gen #(instance? java.util.regex.Pattern %)
    #(gen/fmap re-pattern (gen/elements ["\\beval\\s*\\(" "math/rand" "@csrf_exempt"]))))
(s/def ::message string?)
(s/def ::pattern (s/keys :req-un [::langs ::regex ::message]))
(s/def ::patterns (s/coll-of ::pattern :kind vector? :min-count 1 :gen-max 3))
(s/def ::rule (s/keys :req-un [::id ::name ::severity ::cwe ::owasp ::description ::patterns]))
(s/def ::rules
  (s/and (s/coll-of ::rule :kind vector? :gen-max 3)
         (fn [rs] (or (empty? rs) (apply distinct? (map :id rs))))))

;; --- Findings and scan results ---

(s/def ::rule-name string?)
(s/def ::file string?)
(s/def ::line pos-int?)
(s/def ::code string?)
(s/def ::finding
  (s/keys :req-un [::rule-id ::rule-name ::severity ::cwe ::owasp ::message ::file ::line ::code]))
(s/def ::findings (s/coll-of ::finding :kind vector? :gen-max 8))

(s/def ::directory string?)
(s/def ::files-scanned nat-int?)
(s/def ::total-findings nat-int?)
(s/def ::findings-by-severity (s/map-of ::severity pos-int?))
(s/def ::findings-by-rule (s/map-of ::rule-id pos-int?))

;; The scan-directory result: the totals are derived from :findings.
(s/def ::scan-results
  (s/with-gen
    (s/and (s/keys :req-un [::directory ::files-scanned ::total-findings
                            ::findings-by-severity ::findings-by-rule ::findings])
           (fn [r] (= (:total-findings r) (count (:findings r)))))
    #(gen/fmap (fn [[dir n fs]]
                 {:directory dir
                  :files-scanned n
                  :total-findings (count fs)
                  :findings-by-severity (frequencies (map :severity fs))
                  :findings-by-rule (frequencies (map :rule-id fs))
                  :findings fs})
               (gen/tuple (gen/elements ["/src/app" "/tmp/scan"]) (gen/choose 0 50)
                          (s/gen ::findings)))))

;; --- Output ---

;; --format is passed through; anything but json/edn renders text.
(s/def ::format (s/with-gen string? #(gen/elements ["text" "json" "edn" "xml"])))

(defn output-reads-back?
  "Shared by the format-* fdef :fns: json output parses back to the same
  total, edn output reads back to the same results, and text output starts
  with the report header."
  [fmt results ret]
  (case fmt
    "json" (= (:total-findings results) (get (json/parse-string ret) "total-findings"))
    "edn" (= results (edn/read-string ret))
    (str/starts-with? ret "SecureCodeAnalyzer")))
