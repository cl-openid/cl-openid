(in-package #:cl-openid)

(defparameter *assoc-types*
  '(("HMAC-SHA1" . :SHA1)
    ("HMAC-SHA256" . :SHA256)))

(defparameter *session-types*
  '(("DH-SHA1" . :SHA1)
    ("DH-SHA256" . :SHA256)))

(defparameter *https-session-types*
  '("no-encryption" ""))

(defvar *slime*)

(defun error-response (err &key contact reference parameters)
  (setf (hunchentoot:return-code) 400) ; FIXME:hunchentoot

  ;; For v1 RPs this field is meaningless.
  (push (cons "ns" "http://specs.openid.net/auth/2.0") parameters)

  ;; Spec is unclear on this, but it won't hurt.
  (push (cons "mode" "error") parameters)

  (push (cons "error" err) parameters)

  (when contact
    (push (cons "contact" contact) parameters))

  (when reference
    (push (cons "reference" reference) parameters))
  parameters)

(defvar *provider-associations* ())

(defun indirect-reply-uri (return-to parameters
                           &aux (uri (if (uri-p return-to)
                                         (copy-uri return-to)
                                         (uri return-to))))
  (setf (uri-query uri)
        (concatenate 'string
                     (uri-query uri)
                     (and (uri-query uri) "&")
                     (drakma::alist-to-url-encoded-string parameters :utf-8))) ; FIXME: unexported function
  uri)

(defun indirect-reply (return-to parameters)
  (hunchentoot:redirect                 ; FIXME: hunchentoot
   (princ-to-string (indirect-reply-uri return-to parameters))))

(defun handle-openid-provider-request
    (endpoint parameters
     &aux
     (v1-compat (not (string= "http://specs.openid.net/auth/2.0"
                              (aget "openid.ns" parameters)))))
  (string-case (aget "openid.mode" parameters)
    ("associate"
     (kv-encode ; Direct reply
      (handler-case
          (string-case (aget "openid.session_type" parameters)
            (("DH-SHA1" "DH-SHA256")
             (let ((private (random +dh-prime+)) ; FIXME:random
                   (mac (random +dh-prime+)))
               (multiple-value-bind (emac public)
                   (dh-encrypt/decrypt-key (session-digest-type (aget "openid.session_type" parameters))
                                           (ensure-integer (or (aget "openid.dh_gen" parameters) +dh-generator+))
                                           (ensure-integer (or (aget "openid.dh_modulus" parameters) +dh-prime+))
                                           (ensure-integer (aget "openid.dh_consumer_public" parameters))
                                           private
                                           mac)
                 (let ((association (make-association :association-type (aget "openid.assoc_type" parameters)
                                                      :mac mac)))
                   (push association *provider-associations*)
                   `(("ns" . "http://specs.openid.net/auth/2.0")
                     ("assoc_handle" . ,(association-handle association))
                     ("session_type" . ,(aget "openid.session_type" parameters))
                     ("assoc_type" . ,(aget "openid.assoc_type" parameters))
                     ("expires_in" . ,(princ-to-string (- (association-expires association)
                                                          (get-universal-time))))
                     ("dh_server_public" . ,(usb8-array-to-base64-string (btwoc public))) ; FIXME:btwoc produces 129-byte arrays, is it okay?
                     ("enc_mac_key" . ,(usb8-array-to-base64-string emac)))))))
            (("" "no-encryption")
             (if (hunchentoot:ssl-p)    ; FIXME:hunchentoot
                 (let ((association (make-association :association-type (aget "openid.assoc_type" parameters)
                                                      :mac (random +dh-prime+)))) ; FIXME:random
                   (push association *provider-associations*)
                   `(("ns" . "http://specs.openid.net/auth/2.0")
                     ("assoc_handle" . ,(association-handle association))
                     ("session_type" . ,(aget "openid.session_type" parameters))
                     ("assoc_type" . ,(aget "openid.assoc_type" parameters))
                     ("expires_in" . ,(princ-to-string (- (association-expires association)
                                                          (get-universal-time))))
                     ("mac_key" . ,(usb8-array-to-base64-string (association-mac association)))))
                 (openid-association-error "Unencrypted session is supported only with an encrypted connection.")))
            (t (openid-association-error "Unsupported association type")))

        (openid-association-error (e)
          (error-response (princ-to-string e)
                          :parameters `(("error_code" . "unsupported-type")
                                        ("session_type" . ,(if v1-compat "DH-SHA1" "DH-SHA256")) ; We do not prefer cleartext session, regardless of SSL
                                        ("assoc_type" . ,(if v1-compat "HMAC-SHA1" "HMAC-SHA256"))))))))

    ("checkid_immediate"
     (indirect-reply (aget "openid.return_to" parameters)
                     '(("openid.ns" . "http://specs.openid.net/auth/2.0")
                       ("openid.mode" . "setup_needed"))))

    ("checkid_setup"
     (indirect-reply (aget "openid.return_to" parameters)
                     '(("openid.ns" . "http://specs.openid.net/auth/2.0")
                       ("openid.mode" . "cancel")) ))

    (t (error-response "Unknown mode."))))

;; Hunchentoot-specific part
(defun provider-ht-handle (endpoint)
  (lambda ()
    (handle-openid-provider-request endpoint
                                    (append (hunchentoot:post-parameters)
                                            (hunchentoot:get-parameters)))))

(defun provider-ht-dispatcher (endpoint prefix)
  (hunchentoot:create-prefix-dispatcher prefix (provider-ht-handle (uri endpoint))))

; (push (provider-ht-dispatcher "http://example.com/cl-openid-op/" "/cl-openid-op/") hunchentoot:*dispatch-table*)
