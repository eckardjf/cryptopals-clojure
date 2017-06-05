(ns cryptopals.challenge.05
  (:require [clojure.test :refer :all]
            [cryptopals.core :refer :all]))

(defn xor-cipher [k bs]
  (byte-array (map bit-xor bs (cycle k))))

(deftest challenge-5-test
  (testing "Implement repeating-key XOR"
    (is (= "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
           (bytes->hex (xor-cipher (string->bytes "ICE")
                                   (string->bytes "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")))))))
