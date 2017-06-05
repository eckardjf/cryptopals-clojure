(ns cryptopals.set-2-test
  (:require [clojure.test :refer :all]
            [cryptopals.core :refer :all]))

(deftest challenge-9-test
  (testing "Implement PKCS#7 padding"
    (let [bs (string->bytes "YELLOW SUBMARINE")
          result (pkcs7-pad 20 bs)]
      (is (= (count result) 20))
      (is (every? #(= 4 %) (take-last 4 result))))))

(deftest challenge-10-test
  (testing "Implement CBC mode"
    (let [k (string->bytes "YELLOW SUBMARINE")
          iv (repeat 16 0)
          ciphertext (->> "resources/10.txt" slurp base64->bytes)]
      (is (-> (bytes->string (aes-cbc-decrypt iv k ciphertext))
              (.startsWith "I'm back and I'm ringin' the bell"))))))

(deftest challenge-11-test
  (testing "An ECB/CBC detection oracle"
    (let [block-size 16
          input (byte-array (* block-size 3) (byte 0x00))]
      (is (every? #(= (:mode %) (:detected-mode %))
                  (map #(assoc % :detected-mode (detect-mode (:output %) block-size))
                       (repeatedly 20 #(encryption-oracle input))))))))
