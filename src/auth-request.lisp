(in-package #:cl-openid)

;; OpenID Authentication 2.0, 9.  Requesting Authentication
;; http://openid.net/specs/openid-authentication-2_0.html#requesting_authentication
(defun request-authentication-uri (id &key return-to realm immediate-p
                                   &aux (association (associate id)))
  "Return URI for an authentication request for ID"
  (unless (or return-to realm)
    (error "Either RETURN-TO, or REALM must be specified."))
  (indirect-request-uri (aget :op-endpoint-url id)
                        `(("openid.mode" . ,(if immediate-p
                                                "checkid_immediate"
                                                "checkid_setup"))
                          ("openid.claimed_id" . ,(princ-to-string (aget :claimed-id id)))
                          ("openid.identity" . ,(or (aget :op-local-identifier id)
                                                    (princ-to-string (aget :claimed-id id))))
                          ,@(when association
                                  `(("openid.assoc_handle" . ,(association-handle association))))
                          ,@(when return-to
                                  `(("openid.return_to" . ,(princ-to-string return-to))))
                          ,@(when realm
                                  `((,(if (equal '(2 . 0)  ; OpenID 1.x compat: trust_root instead of realm
                                                 (aget :protocol-version id))
                                          "openid.realm"
                                          "openid.trust_root")
                                      . ,(princ-to-string realm)))))))

(define-condition openid-assertion-error (error)
  ((code :initarg :code :reader code)
   (reason :initarg :reason :reader reason)
   (reason-format-parameters :initarg :reason-format-parameters :reader reason-format-parameters)
   (id :initarg :id :reader id)
   (message :initarg :message :reader message))
  (:report (lambda (e s)
             (format s "OpenID assertion error: ~?"
                     (reason e) (reason-format-parameters e))))
  (:documentation "Error during OpenID assertion verification"))

(defvar *nonces* nil ; FIXME:gc
  "A list of openid.nonce response parameters to avoid duplicates.")

(defvar *nonce-timeout* 3600
  "Number of seconds the nonce times out.")

(defun nonce-universal-time (nonce)
  (encode-universal-time (parse-integer nonce :start 17 :end 19) ; second
                         (parse-integer nonce :start 14 :end 16) ; minute
                         (parse-integer nonce :start 11 :end 13) ; hour
                         (parse-integer nonce :start 8  :end 10) ; date
                         (parse-integer nonce :start 5  :end 7)  ; month
                         (parse-integer nonce :start 0  :end 4)  ; year
                         0                                       ; GMT
                         ))

(defun gc-nonces (&aux (time-limit (- (get-universal-time) *nonce-timeout*)))
  (setf *nonces* (delete-if #'(lambda (nonce-time)
                                (< nonce-time time-limit))
                            *nonces* :key #'nonce-universal-time)))

(defun handle-indirect-response (message id
                                 &aux (v1-compat (not (equal '(2 . 0) (aget :protocol-version id)))))
  "Handle indirect response MESSAGE directed for ID.

Returns ID on success, NIL on failure."
  (macrolet ((err (code reason &rest args)
               `(error 'openid-assertion-error
                       :code ,code
                       :reason ,reason
                       :reason-format-parameters (list ,@args)
                       :message message
                       :id id))
             (ensure (test-form code message &rest args)
               `(unless ,test-form
                  (err ,code ,message ,@args)))
             (same-uri (id-field message-field)
               `(uri= (uri (aget ,id-field id))
                      (uri (aget ,message-field message)))))

    (string-case (aget "openid.mode" message)
      ("error" (err :server-error "Assertion error"))

      ("setup_needed" (err :setup-needed "Setup needed."))

      ("cancel" nil)

      ("id_res"

       ;; Handle assoc invalidations
       (gc-associations (aget "openid.invalidate_handle" message))

       ;; 11.1.  Verifying the Return URL
       (ensure (uri= (aget :return-to id)
                     (uri (aget "openid.return_to" message)))
               :invalid-return-to
               "openid.return_to ~A doesn't match server's URI" (aget "openid.return_to" message))

       ;; 11.2.  Verifying Discovered Information
       (unless v1-compat
         (ensure (string= "http://specs.openid.net/auth/2.0" (aget "openid.ns" message))
                 :invalid-namespace
                 "Wrong namespace ~A" (aget "openid.ns" message)))

       (unless (and v1-compat (null (aget "openid.op_endpoint" message)))
         (ensure (same-uri :op-endpoint-url "openid.op_endpoint")
                 :invalid-endpoint
                 "Endpoint URL does not match previously discovered information."))

       (unless (or (and v1-compat (null (aget "openid.claimed_id" message)))
                   (same-uri :claimed-id "openid.claimed_id"))
         (let ((cid (discover (normalize-identifier (aget "openid.claimed_id" message)))))
           (if (uri= (aget :op-endpoint-url cid)
                     (aget :op-endpoint-url id))
               (setf (cdr (assoc :claimed-id id))
                     (aget :claimed-id cid))
               (err :invalid-claimed-id
                    "Received Claimed ID ~A differs from user-supplied ~A, and discovery for received one did not find the same endpoint."
                    (aget :op-endpoint-url id) (aget :op-endpoint-url cid)))))

       ;; 11.3.  Checking the Nonce
       (let ((nonce (aget "openid.response_nonce" message)))
         (if nonce
             (progn (ensure (not (or (> (- (get-universal-time)
                                           (nonce-universal-time nonce))
                                        *nonce-timeout*)
                                     (member nonce *nonces* :test #'string=)))
                            :invalid-nonce
                            "Repeated nonce.")
                    (push nonce *nonces*))
             (unless v1-compat
               (err :missing-nonce "No openid.response_noce"))))
       (gc-nonces)

       ;; 11.4.  Verifying Signatures
       (ensure (if (association-by-handle (aget "openid.assoc_handle" message))
                   ;; 11.4.1.  Verifying with an Association
                   (check-signature message)
                   ;; 11.4.2.  Verifying Directly with the OpenID Provider
                   (let ((response (direct-request (aget :op-endpoint-url id)
                                                (acons "openid.mode" "check_authentication"
                                                       (remove "openid.mode" message
                                                               :key #'car
                                                               :test #'string=)))))

                     (when (aget "invalidate_handle" response)
                       (gc-associations (aget "invalidate_handle" response)))
                     (string= "true" (aget "is_valid" response))))
               :invalid-signature
               "Invalid signature")

       (unless v1-compat             ; Check list of signed parameters
         (let ((signed (split-sequence #\, (aget "openid.signed" message))))
           (ensure (every #'(lambda (f)
                              (member f signed :test #'string=))
                          `("op_endpoint"
                            "return_to"
                            "response_nonce"
                            "assoc_handle"
                            ,@(when (aget "openid.claimed_id" message)
                                    '("claimed_id" "identity"))))
                   :invalid-signed-fields
                   "Not all fields that are required to be signed, are so.")))

       id))))
