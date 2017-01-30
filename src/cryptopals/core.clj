(ns cryptopals.core
  (:import (java.util Base64))
  (:require [clojure.string :as string]))

(defn hex->bytes [h]
  (->> h
       (partition 2)
       (map #(Integer/parseInt (apply str %) 16))
       byte-array))

(defn bytes->hex [b]
  (apply str (map (partial format "%02x") b)))

(defn base64->bytes [^String s]
  (.decode (Base64/getMimeDecoder) s))

(defn bytes->base64 [b]
  (.encodeToString (Base64/getEncoder) b))

(defn hex->base64 [h]
  (bytes->base64 (hex->bytes h)))

(defn string->bytes [^String s]
  (.getBytes s))

(defn bytes->string [^bytes b]
  (String. b))

(defn xor-bytes [b1 b2]
  (byte-array (map bit-xor b1 b2)))

(defn xor-cipher [k b]
  (byte-array (map bit-xor b (cycle k))))

(def english-frequencies
  {\E 0.1249 \T 0.0928 \A 0.0804 \O 0.0764 \I 0.0757 \N 0.0723
   \S 0.0651 \R 0.0628 \H 0.0505 \L 0.0407 \D 0.0382 \C 0.0334
   \U 0.0273 \M 0.0251 \F 0.0240 \P 0.0214 \G 0.0187 \W 0.0168
   \Y 0.0166 \B 0.0148 \V 0.0105 \K 0.0054 \X 0.0023 \J 0.0016
   \Q 0.0012 \Z 0.0009 \space 0.1832})

(defn square [x]
  (* x x))

(defn chi-squared [observed expected]
  (/ (square (- observed expected)) expected))

(defn score-text [s]
  (reduce + (for [[c n] (frequencies (string/upper-case s))]
              (chi-squared n (* (count s) (get english-frequencies c 0.0004))))))

(defn enumerate-guesses [h]
  (let [b1 (hex->bytes h)]
    (for [c (range 32 128)]
      (let [b2 (byte-array (repeat (count b1) c))
            result (bytes->string (xor-bytes b1 b2))]
        {:ch (char c) :score (score-text result) :text result}))))

(defn hamming-distance [b1 b2]
  (reduce + (map #(Integer/bitCount %) (xor-bytes b1 b2))))

(defn transpose [n b]
  (apply map vector (partition n b)))
