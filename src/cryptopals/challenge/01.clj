(ns cryptopals.challenge.01
  (:require [clojure.test :refer :all]
            [cryptopals.core :refer :all]))

(deftest challenge-1-test
  (testing "Convert hex to base64"
    (let [input "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
          expected "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"]
      (is (= expected (hex->base64 input))))))
