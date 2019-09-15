(ns cryptopals.challenge.04
  (:require [clojure.string :as string]
            [clojure.test :refer :all]
            [cryptopals.core :refer :all]
            [cryptopals.xor :refer [enumerate-guesses]]))

(deftest challenge-4-test
  (testing "Detect single-character XOR"
    (is (= "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f"
           (->> "resources/4.txt"
                slurp
                string/split-lines
                (mapcat (comp enumerate-guesses hex->bytes))
                (apply min-key :score)
                :input)))))
