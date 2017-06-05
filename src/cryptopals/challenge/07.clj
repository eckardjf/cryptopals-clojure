(ns cryptopals.challenge.07
  (:require [clojure.test :refer :all]
            [cryptopals.core :refer :all]
            [cryptopals.block :refer [aes-ecb-decrypt]]))

(deftest challenge-7-test
  (testing "AES in ECB mode"
    (let [k (string->bytes "YELLOW SUBMARINE")
          ciphertext (->> "resources/7.txt" slurp base64->bytes)
          plaintext (aes-ecb-decrypt k ciphertext)]
      (is (-> (bytes->string plaintext)
              (.startsWith "I'm back and I'm ringin' the bell"))))))
