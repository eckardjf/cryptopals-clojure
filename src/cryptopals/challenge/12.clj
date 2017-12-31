(ns cryptopals.challenge.12
  (:require [clojure.test :refer :all]
            [cryptopals.core :refer :all]
            [cryptopals.block :refer [pkcs7-pad aes-ecb-encrypt]]))

(def plaintext (-> (str "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
                        "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
                        "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
                        "YnkK")
                   base64->bytes))

(def unknown-block-size 16)
(def unknown-key (rand-bytes unknown-block-size))

(defn oracle [bs]
  (->> (concat bs plaintext)
       (pkcs7-pad unknown-block-size)
       (aes-ecb-encrypt unknown-key)))

(defn determine-block-size [f]
  (let [[a b] (distinct
               (map (fn [n]
                      (count (f (byte-array n (byte \A)))))
                    (range)))]
    (- b a)))

(defn ecb? [f block-size]
  (apply = (->> (f (byte-array (* block-size 2) (byte \A)))
                (partition block-size)
                (take 2))))

(defn recover-next-byte [f block-size known]
  (let [position (count known)
        block (int (quot position block-size))
        pad (dec (- block-size (mod position block-size)))
        prefix (byte-array pad (byte \A))
        target (nth (partition block-size (f prefix)) block)]
    (first (filter (fn [i]
                     (let [payload (concat prefix known [i])]
                       (= target (nth (partition block-size (f payload)) block))))
                   (range 256)))))

(defn recover-suffix [f]
  (let [block-size (determine-block-size f)]
    (loop [known []]
      (let [next-byte (recover-next-byte f block-size known)]
        (if (= 1 next-byte)
          (-> known byte-array bytes->string)
          (recur (conj known next-byte)))))))

(deftest challenge-12-test
  (testing "Byte-at-a-time ECB decryption (Simple)"
    (is (= (recover-suffix oracle)
           (str "Rollin' in my 5.0\n"
                "With my rag-top down so my hair can blow\n"
                "The girlies on standby waving just to say hi\n"
                "Did you stop? No, I just drove by\n")))))
