(ns cryptopals.core
  (:import (java.util Base64)
           (javax.crypto Cipher)
           (javax.crypto.spec SecretKeySpec))
  (:require [clojure.string :as string]))

(defn hex->bytes [h]
  (->> h
       (partition 2)
       (map #(Integer/parseInt (apply str %) 16))
       byte-array))

(defn bytes->hex [bs]
  (apply str (map (partial format "%02x") bs)))

(defn base64->bytes [^String s]
  (.decode (Base64/getMimeDecoder) s))

(defn bytes->base64 [bs]
  (.encodeToString (Base64/getEncoder) bs))

(defn hex->base64 [h]
  (bytes->base64 (hex->bytes h)))

(defn string->bytes [^String s]
  (.getBytes s))

(defn bytes->string [^bytes bs]
  (String. bs))

(defn xor-bytes [bs1 bs2]
  (byte-array (map bit-xor bs1 bs2)))

(defn xor-cipher [k bs]
  (byte-array (map bit-xor bs (cycle k))))

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
      {:ch (char c) :score (score-text result) :input (bytes->hex bs) :output result})))

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
      {:size n
       :score (avg (map #(/ (apply hamming-distance %) n) pairs))})))

(defn determine-key-size [bs]
  (->> bs
       (enumerate-key-size-guesses 2 40)
       (sort-by :score)
       first
       :size))

(defn break-repeating-key-xor [n bs]
  (apply str (map break-single-char-xor (transpose n bs))))

(defn aes-ecb-encrypt [k bs]
  (let [key-spec (SecretKeySpec. k "AES")
        cipher (Cipher/getInstance "AES/ECB/NoPadding")]
    (.init cipher Cipher/ENCRYPT_MODE key-spec)
    (.doFinal cipher bs)))

(defn aes-ecb-decrypt [k bs]
  (let [key-spec (SecretKeySpec. k "AES")
        cipher (Cipher/getInstance "AES/ECB/NoPadding")]
    (.init cipher Cipher/DECRYPT_MODE key-spec)
    (.doFinal cipher bs)))

(defn has-duplicates? [xs]
  (< (count (distinct xs)) (count xs)))

(defn has-duplicate-blocks? [bs]
  (->> bs (partition 16) has-duplicates?))

(defn pkcs7-pad [n bs]
  (let [p (- n (mod (count bs) n))]
    (byte-array (concat bs (repeat p p)))))

(defn aes-cbc-encrypt [iv k bs]
  (let [encrypt (partial aes-ecb-encrypt k)]
    (loop [acc []
           remaining (partition 16 bs)]
      (if (empty? remaining)
        (byte-array (mapcat seq acc))
        (let [current (first remaining)
              previous (or (last acc) iv)]
          (recur (conj acc (encrypt (xor-bytes current previous)))
                 (rest remaining)))))))

(defn aes-cbc-decrypt [iv k bs]
  (let [decrypt (partial aes-ecb-decrypt k)]
    (loop [acc []
           remaining (reverse (partition 16 bs))]
      (if (empty? remaining)
        (byte-array (mapcat seq (reverse acc)))
        (let [current (first remaining)
              previous (or (second remaining) iv)]
          (recur (conj acc (xor-bytes previous (decrypt (byte-array current))))
                 (rest remaining)))))))

(defn rand-bytes [n]
  (byte-array (repeatedly n #(rand-int 256))))

(defn encryption-oracle [bs]
  (let [block-size 16
        k (rand-bytes block-size)
        prefix (rand-bytes (+ 5 (rand-int 6)))
        suffix (rand-bytes (+ 5 (rand-int 6)))
        plaintext (pkcs7-pad block-size (concat prefix bs suffix))]
    (if (zero? (rand-int 2))
      {:mode   :ecb
       :output (aes-ecb-encrypt k plaintext)}
      {:mode   :cbc
       :output (aes-cbc-encrypt (rand-bytes block-size) k plaintext)})))

(defn detect-mode [bs block-size]
  (let [[a b] (take 2 (drop 1 (partition block-size bs)))]
    (if (= a b) :ecb :cbc)))
