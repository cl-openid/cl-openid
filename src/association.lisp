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

;; An association.  Endpoint URI is the hashtable key.
(defstruct association
  (expires nil :type integer)
  (handle nil :type string)
  (mac nil :type (simple-array (unsigned-byte 8) (*)))
  (hmac-digest nil :type keyword))

(defvar *associations* (make-hash-table))

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

(defun do-associate (endpoint
                     &key
                     v1
                     assoc-type session-type
                     &aux
                     (parameters '(("openid.mode" . "associate")))
                     xa)

  ;; optimize? move to constants?
  (let  ((supported-atypes  (if v1
                                '("HMAC-SHA1")
                                '("HMAC-SHA256" "HMAC-SHA1")))
         (supported-stypes (if v1
                               '("DH-SHA1" "")
                               (if (eq :https (uri-scheme (uri endpoint)))
                                   '("DH-SHA256" "DH-SHA1" "no-encryption")
                                   '("DH-SHA256" "DH-SHA1")))))
    (unless assoc-type
      (setf assoc-type  (first supported-atypes)))
    
    (unless session-type
      (setf session-type (first supported-stypes)))

    (hunchentoot:log-message :debug
                             "Associating~:[~; v1-compatible~] with ~A (assoc ~S, session ~S)"
                             v1 endpoint assoc-type session-type)

    (push (cons "openid.assoc_type" assoc-type) parameters)
    (push (cons "openid.session_type" session-type) parameters)

    (handler-bind ((openid-request-error
                    #'(lambda (e)
                        (when (equal (cdr (assoc "error_code" (parameters e)
                                                 :test #'string=))
                                     "unsupported-type")
                          (let ((supported-atype (aget "assoc_type" (parameters e)))
                                (supported-stype (aget "session_type" (parameters e))))
                            (return-from do-associate
                              (when (and (member supported-atype supported-atypes :test #'equal)
                                         (member supported-stype supported-stypes :test #'equal))
                                (do-associate endpoint
                                  :v1 v1
                                  :assoc-type supported-atype
                                  :session-type supported-stype))))))))

      (when (string= "DH-" session-type :end2 3) ; Diffie-Hellman
        (setf xa (random +dh-prime+)) ; FIXME: use safer prng generation
        (push (cons "openid.dh_consumer_public" (base64-btwoc (expt-mod +dh-generator+ xa +dh-prime+)))
              parameters))

      (let* ((response (direct-request endpoint parameters)))
        (values (make-association :handle  (aget "assoc_handle" response)
                                  :expires (+ (get-universal-time)
                                              (parse-integer (aget "expires_in" response)))
                                  :mac (if (string= "DH-" session-type :end2 3)
                                           ;; Diffie-Hellman
                                           (let* ((g^xb (base64-string-to-integer (aget "dh_server_public" response)))
                                                  (k (expt-mod g^xb xa +dh-prime+))
                                                  (h (octets-to-integer
                                                      (digest-sequence (session-digest-type session-type)
                                                                       (btwoc k))))
                                                  (emac (base64-string-to-integer (aget "enc_mac_key" response)))
                                                  (mac (logxor h emac)))
                                             (integer-to-octets mac))
                                           (base64-string-to-usb8-array
                                            (aget "mac_key" response)))
                                  :hmac-digest (or (aget assoc-type
                                                         '(("HMAC-SHA1" . :SHA1)
                                                           ("HMAC-SHA256" . :SHA256)))
                                                   (error "Unknown session type.")))
                endpoint)))))

(defun gc-associations (&aux (time (get-universal-time)))
  (maphash #'(lambda (ep association)
               (when (> time (association-expires association))
                 (hunchentoot:log-message :debug "GC association with ~A ~S" ep association)
                 (remhash ep *associations*)))
           *associations*))

(defun association (endpoint &optional v1)
  (gc-associations)                     ; keep clean
  (setf endpoint (intern-uri endpoint))
  (or (gethash endpoint *associations*)
      (setf (gethash endpoint *associations*)
            (do-associate endpoint :v1 v1))))
