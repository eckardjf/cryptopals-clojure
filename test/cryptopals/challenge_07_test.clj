(ns cryptopals.challenge-07-test
  (:require [clojure.test :refer :all]
            [cryptopals.core :refer [aes-ecb-decrypt base64->bytes bytes->string string->bytes]]))

(deftest challenge7-test
  (let [k (string->bytes "YELLOW SUBMARINE")
        ciphertext (->> "resources/7.txt" slurp base64->bytes)
        plaintext (aes-ecb-decrypt k ciphertext)]
    (is (-> (bytes->string plaintext)
            (.startsWith "I'm back and I'm ringin' the bell")))))
