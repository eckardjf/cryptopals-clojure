(ns cryptopals.challenge-02-test
  (:require [clojure.test :refer :all]
            [cryptopals.core :refer [hex->bytes bytes->hex xor-bytes]]))

;; Fixed XOR

;; Write a function that takes two equal-length buffers and produces their XOR combination.

;; If your function works properly, then when you feed it the string:
;; 1c0111001f010100061a024b53535009181c

;; ... after hex decoding, and when XOR'd against:
;; 686974207468652062756c6c277320657965

;; ... should produce:
;; 746865206b696420646f6e277420706c6179

(deftest challenge-02-test
  (let [h1 "1c0111001f010100061a024b53535009181c"
        h2 "686974207468652062756c6c277320657965"
        expected "746865206b696420646f6e277420706c6179"]
    (is (= expected
           (bytes->hex (xor-bytes (hex->bytes h1) (hex->bytes h2)))))))
