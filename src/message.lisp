;;; message.lisp -- functions dealing with protocol messages,
;;; represented by association lists.

(in-package #:cl-openid)

(define-constant +openid2-namespace+ "http://specs.openid.net/auth/2.0"
  "Namespace URI for OpenID 2.0 messages.")

(define-constant +openid2-ns-cons+ (cons "openid.ns" +openid-2.0-namespace+)
  "Helper constant pair for constructing messages.")

(defmacro in-ns (message &optional (namespace '+openid2-ns-cons+))
  "Add NAMESPACE cons to MESSAGE."
  `(cons ,namespace ,message))

;;; Data encoding and decoding

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

;; OpenID Authentication 2.0, 4.1.1.  Key-Value Form Encoding,
;; http://openid.net/specs/openid-authentication-2_0.html#anchor4
(defun parse-kv (array)
  "Parse key-value form message passed as an octet vector into parameter alist."
  (declare (type (simple-array (unsigned-byte 8) (*)) array))
  (loop
     for start = 0 then (1+ end)
     for end = (position 10 array :start start)
     for colon = (position #.(char-code #\:) array :start start)
     when colon collect
       (cons (utf-8-bytes-to-string array :start start :end colon)
             (utf-8-bytes-to-string array :start (1+ colon) :end (or end (length array))))
     while end))

; FIXME: optimize, reduce consing
(defun encode-kv (message)
  "Encode MESSAGE alist as key-value form octet vector"
  (string-to-utf-8-bytes
   (apply #'concatenate 'string
          (loop
             for (k . v) in message
             collect k
             collect ":"
             collect v
             collect '(#\Newline)))))

;;; Requests and responses
(define-condition openid-request-error (error)
  ((reason :initarg :reason :reader reason)
   (message :initarg :message :reader message))
  (:report (lambda (e s)
             (format s "OpenID request error: ~A" (reason e)))))

;; OpenID Authentication 2.0, 5.1.  Direct Communication
;; http://openid.net/specs/openid-authentication-2_0.html#direct_comm
(defun direct-request (uri message)
  "Send a direct request to URI, sending MESSAGE alist."
  (let ((*text-content-types* nil))
    (multiple-value-bind (body status-code)
        (http-request uri
                      :method :post
                      :parameters (in-ns message))
      (let ((response (parse-kv body)))
        (if (= 200 status-code)
            response
            (error 'openid-request-error
                   :reason (message-field "error" response)
                   :message response))))))

;; OpenID Authentication 2.0, 5.1.2.2.  Error Responses
;; http://openid.net/specs/openid-authentication-2_0.html#direct_comm
(defun error-response (err &key contact reference message)
  (setf (hunchentoot:return-code) 400) ; FIXME:hunchentoot

  ;; Spec is unclear on this, but it won't hurt.
  (push (cons "mode" "error") message)

  (push (cons "error" err) message)

  (when contact
    (push (cons "contact" contact) message))

  (when reference
    (push (cons "reference" reference) message))
  (encode-kv (in-ns message)))

;; OpenID Authentication 2.0, 5.2.  Indirect Communication,
;; http://openid.net/specs/openid-authentication-2_0.html#indirect_comm
(defun indirect-request-uri (endpoint message
                             &aux
                             (uri (new-uri endpoint))
                             (q (drakma::alist-to-url-encoded-string ; FIXME:unexported
                                 (in-ns message)
                                 :utf-8)))
  "Return an URI for an indirect request to OpenID Provider ENDPOINT, sending MESSAGE."
  (setf (uri-query uri)
        (if (uri-query uri)
            (concatenate 'string (uri-query uri) "&" q)
            q))
  uri)

(defun indirect-response-uri (return-to message
                           &aux (uri (new-uri return-to)))
  (setf (uri-query uri)
        (concatenate 'string
                     (uri-query uri)
                     (and (uri-query uri) "&")
                     (drakma::alist-to-url-encoded-string message :utf-8))) ; FIXME:unexported
  uri)

(defun indirect-response (return-to message)
  (hunchentoot:redirect                 ; FIXME:hunchentoot
   (princ-to-string (indirect-response-uri return-to message))))
