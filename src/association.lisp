(in-package #:cl-openid)

(defconstant +dh-prime+
  (parse-integer (concatenate 'string
                              "DCF93A0B883972EC0E19989AC5A2CE310E1D37717E8D9571BB7623731866E61E"
                              "F75A2E27898B057F9891C2E27A639C3F29B60814581CD3B2CA3986D268370557"
                              "7D45C2E7E52DC81C7A171876E5CEA74B1448BFDFAF18828EFD2519F14E45E382"
                              "6634AF1949E5B535CC829A483B8A76223E5D490A257F05BDFF16F2FB22C583AB")
                 :radix 16)
  "This is a confirmed-prime number, used as the default modulus for Diffie-Hellman Key Exchange.

OpenID Authentication 2.0 Appendix B.  Diffie-Hellman Key Exchange Default Value")

(defconstant +dh-generator+ 2)

(defun aget (k a)
  (cdr (typecase k
         (sequence (assoc k a :test #'equal))
         (t (assoc k a)))))

(defun btwoc (i &aux (octets (integer-to-octets i)))
  (if (or (zerop (length octets))
          (> (aref octets 0) 127))
      (concatenate '(simple-array (unsigned-byte 8) (*)) '(0) octets)
      octets))

(defun base64-btwoc (i)
  (usb8-array-to-base64-string (btwoc i)))

(defun parse-kv (array)
  "Parse key-value form message passed as an (unsigned-byte 8) array into alist.

OpenID Authentication 2.0 4.1.1.  Key-Value Form Encoding."
  (loop
     for start = 0 then (1+ end)
     for end = (position 10 array :start start)
     for colon = (position #.(char-code #\:) array :start start)
     when colon collect
       (cons (utf-8-bytes-to-string array :start start :end colon)
             (utf-8-bytes-to-string array :start (1+ colon) :end (or end (length array))))
     while end))

(define-condition openid-request-error (error)
  ((message :initarg :message :reader message)
   (parameters :initarg :parameters :reader parameters))
  (:report (lambda (e s)
             (format s "OpenID request error: ~A" (message e)))))

(defun direct-request (uri parameters)
  (let ((*text-content-types* nil))
    (multiple-value-bind (body status-code)
        (http-request uri
                      :method :post
                      :parameters (acons "openid.ns" "http://specs.openid.net/auth/2.0"
                                         parameters))
      (let ((parameters (parse-kv body)))
        (if (= 200 status-code)
            parameters
            (error 'openid-request-error
                   :message (aget "error" parameters)
                   :parameters parameters))))))

(defun session-digest-type (session-type)
  (or (aget session-type  '(("DH-SHA1" . :SHA1)
                            ("DH-SHA256" . :SHA256)))
      (unless (member session-type '("" "no-encryption")
                      :test #'string=)
        (error "Unknown session type."))))

(defun associate (id &key
                  (assoc-type (second (assoc :assoc-type id)))
                  (session-type (second (assoc :session-type id)))
                  &aux (parameters (list '("openid.mode" . "associate")
                                         `("openid.assoc_type" . ,assoc-type)
                                         `("openid.session_type" . ,session-type)))
                  xa)
  (handler-bind ((openid-request-error
                  #'(lambda (e)
                      (when (equal (cdr (assoc "error_code" (parameters e)
                                               :test #'string=))
                                   "unsupported-type")
                        (let ((supported-atype (aget "assoc_type" (parameters e)))
                              (supported-stype (aget "session_type" (parameters e))))
                          (return-from associate
                            (when (and (member supported-atype (aget :assoc-type id) :test #'equal)
                                       (member supported-stype (aget :session-type id) :test #'equal))
                              (associate id :assoc-type supported-atype :session-type supported-stype))))))))
    (when (string= "DH-" session-type :end2 3)
      (setf xa (random +dh-prime+))     ; FIXME: use safer prng generation
      (push (cons "openid.dh_consumer_public" (base64-btwoc (expt-mod +dh-generator+ xa +dh-prime+)))
            parameters))
    (let* ((association (direct-request (aget :op-endpoint-url id) parameters))
           (expires-in (parse-integer (aget "expires_in" association)))
           (timestamp (get-universal-time)))
      (setf (cdr (assoc :session-type id)) session-type
            (cdr (assoc :assoc-type id)) assoc-type)
      (push (cons :assoc-handle (aget "assoc_handle" association)) id)
      (push (cons :assoc-timestamp timestamp) id)
      (push (cons :expires-in expires-in) id)
      (push (cons :expires-at (+ expires-in timestamp)) id)
      (push (cons :mac (if (string= "DH-" session-type :end2 3)
                           ;; Diffie-Hellman
                           (let* ((g^xb (base64-string-to-integer (aget "dh_server_public" association)))
                                  (k (expt-mod g^xb xa +dh-prime+))
                                  (h (octets-to-integer
                                      (digest-sequence (session-digest-type session-type)
                                                       (btwoc k))))
                                  (emac (base64-string-to-integer (aget "enc_mac_key" association)))
                                  (mac (logxor h emac)))
                             mac)
                           (base64-string-to-integer (aget "mac_key" association))))
            id)
      association))
  id)
