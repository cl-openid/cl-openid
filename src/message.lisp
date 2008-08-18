;;; message.lisp -- functions dealing with protocol messages,
;;; represented by association lists.

(in-package #:cl-openid)

(define-constant +openid2-namespace+ "http://specs.openid.net/auth/2.0"
  "Namespace URI for OpenID 2.0 messages.")

(define-constant +openid2-ns-cons+ (cons "openid.ns" +openid2-namespace+)
  "Helper constant pair for constructing messages.")

(defmacro in-ns (message &optional (namespace '+openid2-namespace+))
  "Add openid.namespace NAMESPACE to MESSAGE."
  (if (equal namespace +openid2-namespace+)
      `(cons ,namespace ,message)
      `(acons "openid.ns" ,namespace ,message)))

(defun message-field (message field-name)
  "get value of FIELD-NAME field from MESSAGE."
  (cdr (assoc field-name message :test #'string=)))

(defun message-v2-p (message)
  "True if MESSAGE is an OpenID v2 message (namespace check)."
  (string= +openid2-namespace+ (message-field message "openid.ns")))

(defun message-field-string (value)
  "Format VALUE as a string for protocol message."
  (etypecase value
    (string value)
    (symbol (string value))
    ((vector (unsigned-byte 8)) (usb8-array-to-base64-string value))
    ((or uri number) (princ-to-string value))))

(defun make-message (&rest parameters)
  "Make new message from arbitrary keyword parameters.

Keyword specifies a message field key (actual key is lowercased symbol
name), and value following the keyword specifies associated value.

Value can be a string (which will be literal field value),
symbol (symbol's name will be used as a value), vector
of (UNSIGNED-BYTE 8) (which will be Base64-encoded), URI object or
integer (which both will be PRINC-TO-STRING-ed).

If value is NIL, field won't be included in the message at all."
  (loop for (k v) on parameters by #'cddr
     if v collect (cons (string-downcase (string k))
                        (message-field-string v))))

(defun copy-message (message &rest parameters)
  "Create a copy of MESSAGE, updating PARAMETERS provided as keyword parameters.

If MESSAGE already includes provided key, new value is used in the
result; if a key is new, the field will be appended to result message.
PARAMETERS are interpreted as by MAKE-MESSAGE function."
  (if parameters
      (let ((rv (loop
                   for (k . v) in message
                   for kk = (intern (string-upcase k) :keyword)
                   for vv = (getf parameters kk)
                   if vv
                   collect (cons k (message-field-string vv)) and do (remf parameters kk)
                   else collect (cons k v))))
        (if parameters
            (nconc rv (apply #'make-message parameters))
            rv))
      (copy-alist message)))

;;; Data encoding and decoding

;; OpenID Authentication 2.0, 4.1.1.  Key-Value Form Encoding,
;; http://openid.net/specs/openid-authentication-2_0.html#anchor4
(defun parse-kv (array)
  "Parse key-value form message passed as an octet vector into parameter alist."
  (declare (type (vector (unsigned-byte 8)) array))
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
                   :reason (message-field response "error")
                   :message response))))))

;; OpenID Authentication 2.0, 5.1.2.2.  Error Responses
;; http://openid.net/specs/openid-authentication-2_0.html#direct_comm
(defun error-response-message (err &key contact reference message)
  (in-ns (copy-message message
                       :mode "error" ; Spec is unclear on this, but it won't hurt.
                       :error err
                       :contact contact
                       :reference reference )))

;; OpenID Authentication 2.0, 5.2.  Indirect Communication,
;; http://openid.net/specs/openid-authentication-2_0.html#indirect_comm
(defun indirect-message-uri (endpoint message
                             &aux (uri (new-uri endpoint)))
  "Return URI to send indirect message MESSAGE to endpoint URI ENDPOINT.

Usable for both indirect requests and responses."
  (setf (uri-query uri)
        (concatenate 'string
                     (uri-query uri)
                     (when (uri-query uri)
                       "&")
                     (drakma::alist-to-url-encoded-string message :utf-8))) ; FIXME:unexported
  uri)
