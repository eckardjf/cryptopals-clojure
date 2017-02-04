(ns cryptopals.challenge-06-test
  (:require [clojure.test :refer :all]
            [cryptopals.core :refer [base64->bytes break-repeating-key-xor determine-key-size]]))

(deftest challenge-06-test
  (let [input (->> "resources/6.txt" slurp base64->bytes)
        key-size (determine-key-size input)]
    (is (= "Terminator X: Bring the noise"
           (break-repeating-key-xor key-size input)))))
