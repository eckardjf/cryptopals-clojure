(ns cryptopals.challenge.06
  (:require [clojure.test :refer :all]
            [cryptopals.core :refer :all]
            [cryptopals.xor :refer [break-repeating-key-xor determine-key-size]]))

(deftest challenge-6-test
  (testing "Break repeating-key XOR"
    (let [input (->> "resources/6.txt" slurp base64->bytes)
          key-size (determine-key-size input)]
      (is (= "Terminator X: Bring the noise"
             (break-repeating-key-xor key-size input))))))
