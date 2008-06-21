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

(test parse-kv
  (dolist (test-case '(("mode:error
error:This is an example message
"
                        ("mode" . "error") ("error" . "This is an example message"))
                       ("")))
    (is (equal (parse-kv (string-to-utf-8-bytes (car test-case)))
               (cdr test-case)))))

(let ((gen-character (gen-character)))
  (defun gen-k-char ()
    (loop
       for char = (funcall gen-character)
       while (member char '(#\: #\Newline))
       finally (return char)))
  (defun gen-v-char ()
    (loop
       for char = (funcall gen-character)
       while (member char '(#\Newline))
       finally (return char))))


(defun gen-kv-alist (&optional (length (gen-integer :min 1 :max 100)))  
  (loop
     with gen-k = (gen-string :elements #'gen-k-char)
     with gen-v = (gen-string :elements #'gen-v-char)
     for i from 1 to (funcall length)
     for k = (funcall gen-k)
     for v = (funcall gen-v)
     collect (cons k v)))

(defun kv-alist-to-kv (alist)
  (string-to-utf-8-bytes
   (apply #'concatenate 'string
          (loop for (k . v) in alist
             collect k
             collect ":"
             collect v
             collect '(#\Newline)))))

(test parse-kv/random
  (for-all ((kv-alist #'gen-kv-alist))
    (is (equal kv-alist (parse-kv (kv-alist-to-kv kv-alist))))))

(test session-digest-type
  (is (eq :sha1 (session-digest-type "DH-SHA1")))
  (is (eq :sha256 (session-digest-type "DH-SHA256")))
  (is (eq nil (session-digest-type "no-encryption")))
  (is (eq nil (session-digest-type "")))
  (for-all ((s (gen-string)))
    (unless (member s '("DH-SHA1" "DH-SHA256" "no-encryption" ""))
      (signals error (session-digest-type s)))))
