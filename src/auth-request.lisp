(in-package #:cl-openid)

(defun indirect-request-uri (endpoint parameters
                             &aux
                             (uri (if (uri-p endpoint)
                                      (copy-uri endpoint)
                                      (uri endpoint)))
                             (q (drakma::alist-to-url-encoded-string ; FIXME: use of unexported function
                                 (acons "openid.ns" "http://specs.openid.net/auth/2.0"
                                        parameters)
                                 :utf-8)))
  (setf (uri-query uri)
        (if (uri-query uri)
            (concatenate 'string (uri-query uri) "&" q)
            q))
  uri)

(defun request-authentication-uri (id &key return-to realm immediate-p
                                   &aux (association (associate id)))
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
                                  `(("openid.realm" . ,(princ-to-string realm)))))))

(defmacro string-case (keyform &body clauses)
  (let ((key (gensym "key")))
    `(let ((,key ,keyform))
       (declare (ignorable ,key))
       (cond
	 ,@(loop
	       for (keys . forms) in clauses
	       for test = (etypecase keys
			    (string `(string= ,key ,keys))
			    (sequence `(find ,key ',keys :test 'string=))
			    ((eql t) t))
	       collect
		 `(,test ,@forms))))))

(define-condition openid-assertion-error (error)
  ((message :initarg :message :reader message)
   (id :initarg :id :reader id)
   (assertion :initarg :assertion :reader assertion))
  (:report (lambda (e s)
             (format s "OpenID assertion error: ~A" (message e)))))

(defvar *nonces* nil)

;;; FIXME: roll into a MACROLET.
(defmacro %err (message)
  `(error 'openid-assertion-error
          :message ,message
          :assertion parameters
          :id id))

(defmacro %check (test message)
  `(unless ,test
     (%err ,message)))

(defmacro %uri-matches (id-field parameters-field)
  `(uri= (uri (aget ,id-field id))
         (uri (aget ,parameters-field parameters))))

(defun handle-indirect-reply (parameters id uri
                              &aux
                              #+later (v1 (not (string= "http://specs.openid.net/auth/2.0" (aget "openid.ns" parameters)))))
  (string-case (aget "openid.mode" parameters)
    ("setup_needed" :setup-needed)
    ("cancel" nil)
    ("id_res" ;; FIXME: verify

     ;; 11.1.  Verifying the Return URL
     (%check (uri= uri (uri (aget "openid.return_to" parameters)))
            "openid.return_to doesn't match server's URI")

     ;; 11.2.  Verifying Discovered Information
     (%check (%uri-matches :op-endpoint-url "openid.op_endpoint")
            "Endpoint URL does not match previously discovered information.")

     ;; 11.3.  Checking the Nonce
     (%check (not (member (aget "openid.nonce" parameters) *nonces*
                          :test #'string=))
             "Repeated nonce.")

     ;; 11.4.  Verifying Signatures
     (%check (check-signature parameters) "Invalid signature")

     (push (aget "openid.nonce" parameters) *nonces*)
     t)))

