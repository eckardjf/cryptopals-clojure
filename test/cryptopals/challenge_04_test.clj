(ns cryptopals.challenge-04-test
  (:require [clojure.string :as string]
            [clojure.test :refer :all]
            [cryptopals.core :refer [enumerate-guesses]]))

;; Detect single-character XOR

;; One of the 60-character strings in this file (4.txt) has been encrypted by single-character XOR.

;; Find it.

;; (Your code from #3 should help.)

(deftest challenge-04-test
  (is (= "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f"
         (->> "resources/4.txt"
              slurp
              string/split-lines
              (map enumerate-guesses)
              flatten
              (sort-by :score)
              first
              :input))))
