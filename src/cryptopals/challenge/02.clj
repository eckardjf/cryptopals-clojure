(ns cryptopals.challenge.02
  (:require [clojure.test :refer :all]
            [cryptopals.core :refer :all]))

(deftest challenge-2-test
  (testing "Fixed XOR"
    (let [h1 "1c0111001f010100061a024b53535009181c"
          h2 "686974207468652062756c6c277320657965"
          expected "746865206b696420646f6e277420706c6179"]
      (is (= expected
             (bytes->hex (xor-bytes (hex->bytes h1) (hex->bytes h2))))))))
