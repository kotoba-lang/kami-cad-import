(ns cad-import.register-test
  "Ported 1:1 from `src/register.rs`'s `#[cfg(test)] mod tests` in the
   original kami-cad-import crate (kotoba-lang/kami-engine, deleted PR
   #82). ADR-2607010930."
  (:require [clojure.test :refer [deftest is]]
            [cad-import.part :as part]
            [cad-import.register :as reg]))

(defn- provenance []
  {:uri "scad://t" :sha256 (apply str (repeat 32 "ab")) :license "MIT"})

(defn- mk-part [id kind mat]
  {:id id :display-name id :kind kind :material mat
   :aabb-min [0.0 0.0 0.0] :aabb-max [1.0 0.5 0.3]
   :mass-kg nil :parent nil :break-group nil
   :source (provenance) :supplier part/default-supplier :revision "1.0.0"})

(deftest request-envelope-targets-atproto-xrpc
  (let [a (-> (part/new-assembly "v1" (provenance)) (part/add-part (mk-part "rail" :chassis :steel-hss)))
        [status req] (reg/register-request a)]
    (is (= status :ok))
    (is (= (:method req) "POST"))
    (is (clojure.string/includes? (:url req) "/xrpc/app.etzhayyim.sbom.registerArtifact"))
    (is (clojure.string/starts-with? (:url req) "https://atproto.etzhayyim.com"))))

(deftest body-carries-vehicle-metadata
  (let [a (-> (part/new-assembly "v1" (provenance))
              (part/add-part (mk-part "rail" :chassis :steel-hss))
              (part/add-part (mk-part "door" :body :steel-mild)))
        [status req] (reg/register-request a)
        body (:body req)]
    (is (= status :ok))
    (is (= (get body "format") "CycloneDX"))
    (is (= (get body "specVersion") "1.5"))
    (is (= (get body "vehicleId") "v1"))
    (is (= (get body "partCount") 2))
    (is (> (get body "totalMassKg") 0.0))
    (let [cdx (get body "cdxJson")]
      (is (= (get cdx "bomFormat") "CycloneDX"))
      (is (= (get cdx "specVersion") "1.5")))))

(deftest auth-header-added-when-token-supplied
  (let [a (-> (part/new-assembly "v1" (provenance)) (part/add-part (mk-part "rail" :chassis :steel-hss)))
        opts (assoc (reg/default-register-options) :bearer-token "eyJ.testtoken")
        [status req] (reg/register-request a opts)
        [_ v] (first (filter (fn [[k _]] (= k "Authorization")) (:headers req)))]
    (is (= status :ok))
    (is (= v "Bearer eyJ.testtoken"))))

(deftest curl-command-is-runnable
  (let [a (-> (part/new-assembly "v1" (provenance)) (part/add-part (mk-part "rail" :chassis :steel-hss)))
        [status cmd] (reg/curl-command a)]
    (is (= status :ok))
    (is (clojure.string/starts-with? cmd "curl -fsSL -X POST"))
    (is (clojure.string/includes? cmd "/xrpc/app.etzhayyim.sbom.registerArtifact"))
    (is (clojure.string/includes? cmd "Content-Type: application/json"))
    (is (clojure.string/includes? cmd "etzhayyim_TOKEN"))))

(deftest endpoint-override-respected
  (let [a (-> (part/new-assembly "v1" (provenance)) (part/add-part (mk-part "rail" :chassis :steel-hss)))
        opts (assoc (reg/default-register-options)
                    :endpoint "https://staging.atproto.etzhayyim.com/xrpc/app.etzhayyim.sbom.registerArtifact")
        [status req] (reg/register-request a opts)]
    (is (= status :ok))
    (is (clojure.string/starts-with? (:url req) "https://staging."))))
