(ns cryptopals.challenge.11
  (:require [clojure.test :refer :all]
            [cryptopals.core :refer :all]
            [cryptopals.block :refer [pkcs7-pad aes-ecb-encrypt aes-cbc-encrypt]]))

(defn encryption-oracle [bs]
  (let [block-size 16
        k (rand-bytes block-size)
        prefix (rand-bytes (+ 5 (rand-int 6)))
        suffix (rand-bytes (+ 5 (rand-int 6)))
        plaintext (pkcs7-pad block-size (concat prefix bs suffix))]
    (if (zero? (rand-int 2))
      {:mode   :ecb
       :output (aes-ecb-encrypt k plaintext)}
      {:mode   :cbc
       :output (aes-cbc-encrypt (rand-bytes block-size) k plaintext)})))

(defn detect-mode [bs block-size]
  (let [[a b] (take 2 (drop 1 (partition block-size bs)))]
    (if (= a b) :ecb :cbc)))

(deftest challenge-11-test
  (testing "An ECB/CBC detection oracle"
    (let [block-size 16
          input (byte-array (* block-size 3) (byte 0x00))]
      (is (every? #(= (:mode %) (:detected-mode %))
                  (map #(assoc % :detected-mode (detect-mode (:output %) block-size))
                       (repeatedly 20 #(encryption-oracle input))))))))
