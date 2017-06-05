(ns cryptopals.challenge.10
  (:require [clojure.test :refer :all]
            [cryptopals.core :refer :all]
            [cryptopals.block :refer [aes-cbc-decrypt]]))

(deftest challenge-10-test
  (testing "Implement CBC mode"
    (let [k (string->bytes "YELLOW SUBMARINE")
          iv (repeat 16 0)
          ciphertext (->> "resources/10.txt" slurp base64->bytes)]
      (is (-> (bytes->string (aes-cbc-decrypt iv k ciphertext))
              (.startsWith "I'm back and I'm ringin' the bell"))))))
