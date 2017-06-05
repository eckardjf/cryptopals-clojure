(ns cryptopals.xor
  (:require [clojure.string :as string]
            [cryptopals.core :refer :all]))

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

(defn enumerate-guesses [bs]
  (for [c (range 32 128)]
    (let [ks (byte-array (count bs) (byte c))
          result (bytes->string (xor-bytes bs ks))]
      {:ch (char c)
       :score (score-text result)
       :input (bytes->hex bs)
       :output result})))

(defn break-single-char-xor [bs]
  (->> bs
       enumerate-guesses
       (sort-by :score)
       first
       :ch))

(defn hamming-distance [bs1 bs2]
  (reduce + (map #(Integer/bitCount %) (xor-bytes bs1 bs2))))

(defn transpose [n xs]
  (apply map vector (partition n xs)))

(defn avg [xs]
  (/ (reduce + xs) (count xs)))

(defn enumerate-key-size-guesses [start end bs]
  (for [n (range start (inc end))]
    (let [blocks (partition n bs)
          pairs (partition 2 blocks)]
      {:size  n
       :score (avg (map #(/ (apply hamming-distance %) n) pairs))})))

(defn determine-key-size [bs]
  (->> bs
       (enumerate-key-size-guesses 2 40)
       (sort-by :score)
       first
       :size))

(defn break-repeating-key-xor [n bs]
  (apply str (map break-single-char-xor (transpose n bs))))
