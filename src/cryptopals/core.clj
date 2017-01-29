(ns cryptopals.core
  (:import (java.util Base64)))

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

(defn xor-bytes [b1 b2]
  (byte-array (map bit-xor b1 b2)))
