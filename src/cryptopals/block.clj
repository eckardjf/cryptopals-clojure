(ns cryptopals.block
  (:import (javax.crypto Cipher)
           (javax.crypto.spec SecretKeySpec))
  (:require [cryptopals.core :refer [xor-bytes]]))

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
