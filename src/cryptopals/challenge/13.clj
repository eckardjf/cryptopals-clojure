(ns cryptopals.challenge.13
  (:import (java.net URLEncoder URLDecoder))
  (:require [clojure.string :as string]
            [clojure.test :refer :all]
            [cryptopals.core :refer :all]
            [cryptopals.block :refer [pkcs7-pad aes-ecb-encrypt]]))

(def block-size 16)
(def fixed-key (rand-bytes block-size))

(defn url-encode [string]
  (some-> string
          (URLEncoder/encode "UTF-8")
          (.replace "+" "%20")))

(defn url-decode [string]
  (some-> string
          (URLDecoder/decode "UTF-8")))

(defn encode [m]
  (some->> (seq m)
           (map (fn [[k v]]
                  [(url-encode (name k)) "=" (url-encode (str v))]))
           (interpose "&")
           flatten
           (apply str)))

(defn split-param [param]
  (take 2 (concat (string/split param #"=") (repeat ""))))

(defn decode [s]
  (when (not (string/blank? s))
    (some->> (string/split s #"&")
             seq
             (mapcat split-param)
             (map url-decode)
             (apply hash-map))))

(defn profile-for [email]
  (->> (array-map :email email :uid 10 :role "user")
       encode))

(defn encrypt-profile [profile-string]
  (some-> profile-string
          string->bytes
          (pkcs7-pad block-size)
          (aes-ecb-encrypt fixed-key)))
