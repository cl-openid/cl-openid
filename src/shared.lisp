;;; shared.lisp -- various macros and functions used later in the
;;; code, not specific to OpenID protocol.

(in-package #:cl-openid)

(defmacro define-constant (name value &rest options)
  "Do a DEFCONSTANT, but do not attempt to redefine if already bound."
  `(eval-when (:compile-toplevel :load-toplevel :execute)
     (unless (boundp ',name)
       (defconstant ,name ,value ,@options))))

(defun aget (key alist)
  "Get a CDR of an (ASSOC KEY ALIST).

Sequence (e.g. string) keys are searched with :TEST #'EQUAL."
  (cdr (typecase key
         (sequence (assoc key alist :test #'equal))
         (t (assoc key alist)))))

(defun ensure-integer (val)
  "For VAL being an integer, a Base64-encoded string representing
integer, or an octet vector representing integer, return its integer
value."
  (etypecase val
    (integer val)
    (string (base64-string-to-integer val))
    (vector (octets-to-integer val))))

(defun ensure-vector (val)
  "For VAL being an integer, a Base64-encoded string representing
integer, or an octet vector representing integer, return it as an
octet vector."
  (etypecase val
    (integer (btwoc val))
    (string (base64-string-to-usb8-array val))
    (vector val)))

;; Used for MAC generation.
(defun ensure-vector-length (vec len)
  "Shorten or enlarge vector VEC so that it has length LEN.

If (= (LENGTH VEC) LEN), returns VEC.  Otherwise, either pads with
zeroes on the left, or removes a number of leftmost elements."
  (cond ((= (length vec) len) vec)
        ((> (length vec) len)
         (subseq vec (- (length vec) len)))
        (t (let ((rv (adjust-array vec len))
                 (d (- len (length vec))))
             (psetf (subseq rv d)
                    (subseq rv 0 len)

                    (subseq rv 0 d)
                    (make-array d :initial-element 0))
             rv))))

(defmacro string-case (keyform &body clauses)
  "Like CASE, but for a string KEYFORM."
  (let ((key (gensym "key")))
    `(let ((,key ,keyform))
       (declare (ignorable ,key))
       (cond
	 ,@(loop
	       for (keys . forms) in clauses
	       for test-form = (etypecase keys
                                 (string `(string= ,key ,keys))
                                 (sequence `(find ,key ',keys :test 'string=))
                                 ((eql t) t))
	       collect
		 `(,test-form ,@forms))))))

;; FIXME: This should probably belong to examples.
(defun html (title body &rest body-args)
  "Simple HTML formatting."
  (format nil "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\"
   \"http://www.w3.org/TR/html4/strict.dtd\">
<html><head><title>~A</title></head>
<body>~?</body></html>"
          title body body-args))
