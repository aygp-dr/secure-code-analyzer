(ns secure_code_analyzer.specs_test
  "Generative checks for every pure s/fdef'd fn, plus data-spec sanity.
  Per https://clojure.org/guides/spec (Testing)."
  (:require [clojure.spec.alpha :as s]
            [clojure.spec.test.alpha :as stest]
            [clojure.test :refer [deftest is testing]]
            [secure_code_analyzer.core :as sca]
            [secure_code_analyzer.specs :as specs]))

(def ^:private check-opts {:clojure.spec.test.check/opts {:num-tests 50}})

;; Side-effecting fns: fdef'd for instrumentation, never generatively checked.
;; find-source-files, scan-file and scan-directory read the filesystem;
;; -main prints and exits.
(def ^:private side-effecting
  #{`sca/find-source-files `sca/scan-file `sca/scan-directory `sca/-main})

(defn- checkable []
  (remove side-effecting (stest/enumerate-namespace 'secure_code_analyzer.core)))

(deftest fdefs-hold-under-generative-testing
  (let [results (stest/check (checkable) check-opts)]
    (is (seq results) "expected at least one fdef'd fn to check")
    (doseq [r results]
      (testing (str (:sym r))
        (is (nil? (:failure r))
            (pr-str (stest/abbrev-result r)))))))

(deftest data-specs-generate-and-conform
  (doseq [k [::specs/path-like ::specs/rule ::specs/finding ::specs/scan-results]]
    (testing (str k)
      (is (every? (fn [[v _]] (s/valid? k v)) (s/exercise k 10))))))

(deftest real-values-conform
  (testing "rule database and lookup tables"
    (is (s/valid? ::specs/rules sca/rules))
    (is (s/valid? (s/map-of string? ::specs/lang) sca/extension->lang))
    (is (s/valid? (s/map-of ::specs/severity nat-int?) sca/severity-levels)))
  (testing "a real scan of test/fixtures"
    (let [results (sca/scan-directory "test/fixtures" "info")]
      (is (s/valid? ::specs/scan-results results))
      (is (pos? (:total-findings results))))))
