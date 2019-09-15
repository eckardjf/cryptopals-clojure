(ns cryptopals.block
  (:import (javax.crypto Cipher)
           (javax.crypto.spec SecretKeySpec))
  (:require [cryptopals.core :refer [xor-bytes]]))

(defn aes-ecb-encrypt [k bs]
  (-> (doto (Cipher/getInstance "AES/ECB/NoPadding")
        (.init Cipher/ENCRYPT_MODE (SecretKeySpec. k "AES")))
      (.doFinal bs)))

(defn aes-ecb-decrypt [k bs]
  (-> (doto (Cipher/getInstance "AES/ECB/NoPadding")
        (.init Cipher/DECRYPT_MODE (SecretKeySpec. k "AES")))
      (.doFinal bs)))
 
(defn pkcs7-pad [n bs]
  (let [p (- n (mod (count bs) n))]
    (byte-array (concat bs (repeat p p)))))

(defn aes-cbc-encrypt [iv k bs]
  (->> (reduce (fn [acc block]
                 (let [previous-block (or (last acc) iv)])
                 (conj acc (aes-ecb-encrypt k (xor-bytes block previous-block))))
               []
               (partition 16 bs))
       (mapcat seq)
       byte-array))

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
