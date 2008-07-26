(in-package #:cl-openid)

(defparameter *assoc-types*
  '(("HMAC-SHA1" . :SHA1)
    ("HMAC-SHA256" . :SHA256)))

(defparameter *session-types*
  '(("DH-SHA1" . :SHA1)
    ("DH-SHA256" . :SHA256)))

(defparameter *https-session-types*
  '("no-encryption" ""))

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
  (kv-encode parameters))

(defvar *provider-associations* ())

(defun indirect-response-uri (return-to parameters
                           &aux (uri (if (uri-p return-to)
                                         (copy-uri return-to)
                                         (uri return-to))))
  (setf (uri-query uri)
        (concatenate 'string
                     (uri-query uri)
                     (and (uri-query uri) "&")
                     (drakma::alist-to-url-encoded-string parameters :utf-8))) ; FIXME: unexported function
  uri)

(defun indirect-response (return-to parameters)
  (hunchentoot:redirect                 ; FIXME: hunchentoot
   (princ-to-string (indirect-response-uri return-to parameters))))

(defun nonce ()
  (multiple-value-bind (sec min hr day mon year wday dst tz)
      (decode-universal-time (get-universal-time) 0)
    (declare (ignore wday dst tz))
    (format nil "~4,'0D-~2,'0D-~2,'0DT~2,'0D:~2,'0D:~2,'0DZ~A"
            year mon day hr min sec (gensym))))

(defun successful-response (endpoint parameters)
  (let* ((assoc (or (when (aget "openid.assoc_handle" parameters)
                      (find (aget "openid.assoc_handle" parameters) *provider-associations*
                            :key #'association-handle :test #'string=))
                    (first (push (make-association :hmac-digest :sha256) *provider-associations*))))
         (rv `(("openid.ns" . "http://specs.openid.net/auth/2.0")
               ("openid.mode" . "id_res")
               ("openid.op_endpoint" . ,(princ-to-string endpoint))
               ("openid.claimed_id" . ,(aget "openid.identity" parameters))
               ("openid.identity" . ,(aget "openid.identity" parameters))
               ,(assoc "openid.return_to" parameters :test #'string=)
               ("openid.response_nonce" . ,(nonce))
               ("openid.assoc_handle" . ,(string (association-handle assoc)))
               ("openid.signed" . "op_endpoint,identity,claimed_id,return_to,assoc_handle,response_nonce"))))
    (push (cons "openid.sig" (sign assoc rv)) rv)
    rv))

(defun handle-openid-provider-request
    (endpoint parameters
     &aux
     (v1-compat (not (string= "http://specs.openid.net/auth/2.0"
                              (aget "openid.ns" parameters)))))
  (string-case (aget "openid.mode" parameters)
    ("associate"
     (kv-encode ; Direct response
      (handler-case
          (string-case (aget "openid.session_type" parameters)
            (("DH-SHA1" "DH-SHA256")
             (let ((private (random +dh-prime+)) ; FIXME:random
                   (association (make-association :association-type (aget "openid.assoc_type" parameters))))
               (multiple-value-bind (emac public)
                   (dh-encrypt/decrypt-key (session-digest-type (aget "openid.session_type" parameters))
                                           (ensure-integer (or (aget "openid.dh_gen" parameters) +dh-generator+))
                                           (ensure-integer (or (aget "openid.dh_modulus" parameters) +dh-prime+))
                                           (ensure-integer (aget "openid.dh_consumer_public" parameters))
                                           private
                                           (association-mac association))
                 (push association *provider-associations*)
                 `(("ns" . "http://specs.openid.net/auth/2.0")
                   ("assoc_handle" . ,(association-handle association))
                   ("session_type" . ,(aget "openid.session_type" parameters))
                   ("assoc_type" . ,(aget "openid.assoc_type" parameters))
                   ("expires_in" . ,(princ-to-string (- (association-expires association)
                                                        (get-universal-time))))
                   ("dh_server_public" . ,(usb8-array-to-base64-string (btwoc public)))
                   ("enc_mac_key" . ,(usb8-array-to-base64-string emac))))))
            (("" "no-encryption")
             (if (hunchentoot:ssl-p)    ; FIXME:hunchentoot
                 (let ((association (make-association :association-type (aget "openid.assoc_type" parameters)))) ; FIXME:random
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
     (indirect-response (aget "openid.return_to" parameters)
                        #+nil  '(("openid.ns" . "http://specs.openid.net/auth/2.0")
                                 ("openid.mode" . "setup_needed"))
                        (successful-response endpoint parameters)))

    ("checkid_setup"
     (indirect-response (aget "openid.return_to" parameters)
                        #+nil '(("openid.ns" . "http://specs.openid.net/auth/2.0")
                                ("openid.mode" . "cancel"))
                        (successful-response endpoint parameters)))

    ("check_authentication" ; FIXME: invalidate_handle flow, invalidate unknown/old handles, gc handles, separate place for private handles.
     (kv-encode `(("ns" . "http://specs.openid.net/auth/2.0")
                  ("is_valid" . ,(if (string= (sign (find (aget "openid.assoc_handle" parameters)
                                                          *provider-associations*
                                                          :key #'association-handle :test #'string=)
                                                    parameters)
                                              (aget "openid.sig" parameters))
                                     "true"
                                     "false")))))

    (t (error-response (format nil "Unknown openid.mode ~S" (aget "openid.mode" parameters))))))

;; Hunchentoot-specific part
(defun provider-ht-handle (endpoint)
  (lambda ()
    (handle-openid-provider-request endpoint
                                    (append (hunchentoot:post-parameters)
                                            (hunchentoot:get-parameters)))))

(defun provider-ht-dispatcher (endpoint prefix)
  (hunchentoot:create-prefix-dispatcher prefix (provider-ht-handle (uri endpoint))))

; (push (provider-ht-dispatcher "http://example.com/cl-openid-op/" "/cl-openid-op/") hunchentoot:*dispatch-table*)
; FIXME: Hunchentoot headers.lisp:136 (START-OUTPUT): (push 400 hunchentoot:*approved-return-codes*)