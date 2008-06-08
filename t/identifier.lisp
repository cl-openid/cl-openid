(in-package #:cl-openid)

(in-suite :cl-openid)

(defparameter +gen-path-element+
  (gen-string :elements (gen-character :alphanumericp t)
              :length (gen-integer :min 1 :max 20)))

(defun insert-dots (initial-list
                    &key
                    (p-dot 1/2)
                    (p-ddot 1/4)
                    (p-empty 1/4)
                    (max-ddot 10)
                    (random-elt +gen-path-element+))
  "Return a list that, after traversing, should be identical to INITIAL-LIST."
  (let* ((rv (list 'junk))
         (rv-tail (last rv)))
    (labels ((do-collect (elt)
               (setf (rest rv-tail) (list elt)
                     rv-tail (rest rv-tail)))
             (collect (elt)
               (cond
                 ((< (random 1.0) p-empty) (collect ""))
                 ((< (random 1.0) p-dot) (collect "."))
                 ((< (random 1.0) p-ddot)
                  (let ((nddot (random max-ddot)))
                    (dotimes (i nddot)
                      (do-collect (funcall random-elt)))
                    (dotimes (i nddot)
                      (do-collect "..")))))
               (do-collect elt)))
      (when (< (random 1.0) p-ddot)
        (let ((nddot (random max-ddot)))
          (dotimes (i nddot)
            (collect (funcall random-elt)))
          (dotimes (i nddot)
            (collect ".."))
          (dotimes (i (random (- max-ddot nddot)))
            (collect ".."))))
      (dolist (elt initial-list)
        (collect elt)))
    (rest rv)))

(test remove-dot-segments
  (dolist (path '(("foo" "bar" "baz")
                  ("foo" "bar" "baz")
                  ("foo" "." "bar" "baz")
                  ("foo" "bar" "." "." "baz")
                  ("foo" "bar" ".." "bar" "baz")
                  ("bar" ".." ".." "foo" "bar" "baz")
                  ("foo" "bar" "quux" "xyzzy" ".." ".." "baz")
                  (".." ".." "." "foo" "bar" "baz")))
    ;; no trailing slash
    (is (equalp '(junk "foo" "bar" "baz")
                (remove-dot-segments (cons 'junk path))))
    ;; with trailing slash
    (dolist (appendix '(("") (".") ("" "") ("." "") ("." ".") ("" ".")))
      (is (equalp '(junk "foo" "bar" "baz" "")
                  (remove-dot-segments (append (cons 'junk path) appendix)))))))

(test remove-dot-segments/random
  (for-all ((original-list (gen-list :elements +gen-path-element+)))
    ;; no trailing slash
    (is (equalp (cons 'junk original-list)
                (remove-dot-segments
                 (cons 'junk (insert-dots original-list)))))
    ;; with trailing slash
    (dolist (appendix '(("") (".") ("" "") ("." "") ("." ".") ("" ".")))
      (is (equalp (append (cons 'junk original-list) '(""))
                  (remove-dot-segments (append (cons 'junk (insert-dots original-list)) appendix)))))))

(test normalize-identifier
  (signals error (normalize-identifier "xri://=test"))
  (signals error (normalize-identifier "=test"))
  (signals error (normalize-identifier "http://example.com/nonexistent"))
  (signals error (normalize-identifier "http://test.invalid/"))
  (dolist (test-case '(("example.com" . "http://example.com/")

                       ("http://example.com" . "http://example.com/")
                       ("http://example.com/" . "http://example.com/")
                       #+SSL ("https://example.com/" . "https://example.com/")
                       
                       ("http://common-lisp.net/project/cl-openid/index.shtml" . "http://common-lisp.net/project/cl-openid/index.shtml")
                       ("http://common-lisp.net/project/cl-openid/index.shtml/" . "http://common-lisp.net/project/cl-openid/index.shtml/")

                       ("http://Common-Lisp.NET/../t/../project/./%63l-openi%64/./index.shtml" . "http://common-lisp.net/project/cl-openid/index.shtml")))
    (is (string= (princ-to-string (cdr (assoc :claimed-id (normalize-identifier (car test-case)))))
                 (cdr test-case)))))

