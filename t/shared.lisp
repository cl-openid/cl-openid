(in-package #:cl-openid)

(in-suite :cl-openid)

(test btwoc
  ;; OpenID Authentication 2.0, 4.2.  Integer Representations
  ;; Non-normative example:
  (dolist (test-case '((0 . #(0))
                       (127 . #(127))
                       (128 . #(0 128))
                       (255 . #(0 255))
                       (32768 . #(0 128 0))))
    (let ((octets (btwoc (car test-case))))
      (is (equalp octets (cdr test-case)))
      (is (= (ironclad:octets-to-integer octets)
             (car test-case))))))

(test btwoc/random
  (for-all ((i (gen-integer :min 0)))
    (let ((octets (btwoc i)))
      (is (< (aref octets 0) 128))
      (is (= i (ironclad:octets-to-integer octets))))))

(test base64-btwoc/random
  (for-all ((i (gen-integer :min 0)))
    (is (= i (cl-base64:base64-string-to-integer (base64-btwoc i))))))

