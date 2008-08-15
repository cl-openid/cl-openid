(in-package #:cl-openid)

(in-suite :cl-openid)

(test session-digest-type
  (is (eq :sha1 (session-digest-type "DH-SHA1")))
  (is (eq :sha256 (session-digest-type "DH-SHA256")))
  (is (eq nil (session-digest-type "no-encryption")))
  (is (eq nil (session-digest-type "")))
  (for-all ((s (gen-string)))
    (if (member s '("DH-SHA1" "DH-SHA256" "no-encryption" "")
                :test #'string=)
        (pass)                          ; already tested
        (signals error (session-digest-type s)))))
