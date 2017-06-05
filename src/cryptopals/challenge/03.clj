(ns cryptopals.challenge.03
  (:require [clojure.test :refer :all]
            [cryptopals.core :refer :all]
            [cryptopals.xor :refer [enumerate-guesses]]))

(deftest challenge-3-test
  (testing "Single-byte XOR cipher"
    (is (= \X (->> "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
                   hex->bytes
                   enumerate-guesses
                   (sort-by :score)
                   first
                   :ch)))))
