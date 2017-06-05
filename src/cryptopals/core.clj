(ns cryptopals.core
  (:import (java.util Base64)))

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

(defn rand-bytes [n]
  (byte-array (repeatedly n #(rand-int 256))))
