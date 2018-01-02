(ns cryptopals.core
  (:import (java.util Base64)))

(defn hex->bytes [h]
  (some->> h
           (partition 2)
           (map #(Integer/parseInt (apply str %) 16))
           byte-array))

(defn bytes->hex [bs]
  (some->> bs
           (map (partial format "%02x"))
           (apply str)))

(defn base64->bytes [^String s]
  (some->> s (.decode (Base64/getMimeDecoder))))

(defn bytes->base64 [bs]
  (some->> bs (.encodeToString (Base64/getEncoder))))

(defn hex->base64 [h]
  (some->> h hex->bytes bytes->base64))

(defn string->bytes [^String s]
  (some->> s (.getBytes)))

(defn bytes->string [^bytes bs]
  (some->> bs (String.)))

(defn xor-bytes [bs1 bs2]
  (byte-array (map bit-xor bs1 bs2)))

(defn rand-bytes [n]
  (some-> n (repeatedly #(rand-int 256)) byte-array))
