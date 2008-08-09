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

;; OpenID Authentication 2.0, 4.2.  Integer Representations,
;; http://openid.net/specs/openid-authentication-2_0.html#btwoc
(defun btwoc (i &aux (octets (integer-to-octets i)))
  "Return two's complement binary string representing integer I, as an octet vector."
  (if (or (zerop (length octets))
          (> (aref octets 0) 127))
      (concatenate '(simple-array (unsigned-byte 8) (*)) '(0) octets)
      octets))

(defun base64-btwoc (i)
  "Return two's complement binary string representing integer I, as Base64-encoded string."
  (usb8-array-to-base64-string (btwoc i)))

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

(defun new-uri (u)
  "Return U as new URI object.

If U is already an URI object, return a copy; otherwise, return (URI U)."
  (typecase u
    (uri (copy-uri u))
    (t (uri u))))

(defun maybe-uri (u)
  "Return (URI U), unless U is NIL."
  (when u
    (uri u)))

(defun add-postfix-to-uri (uri postfix
                           &aux (rv (new-uri uri)))
  "Add POSTFIX (string or symbol) to path part of URI, preserving
query and adding trailing slash to URI if necessary."
  (setf (uri-path rv)
        (concatenate 'string
                     (uri-path rv)
                     (unless (and (uri-path rv)
                                  (eql #\/ (aref (uri-path rv)
                                                 (1- (length (uri-path rv))))))
                       "/")
                     (string postfix)))
  rv)

