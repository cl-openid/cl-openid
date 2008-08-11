(defpackage #:cl-openid.example-provider
  (:use #:common-lisp #:cl-openid #:puri #:hunchentoot))

(in-package #:cl-openid.example-provider)

(defun html (title body &rest body-args)
  "Simple HTML formatting."
  (format nil "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\"
   \"http://www.w3.org/TR/html4/strict.dtd\">
<html><head><title>~A</title></head>
<body>~?</body></html>"
          title body body-args))

;;; Store handled requests
(defvar *requests* (make-hash-table :test #'equal))
(defvar *requests-counter* 0)
(defun store-request
    (message &aux (handle (cl-base64:integer-to-base64-string (incf *requests-counter*) :uri t)))
  (setf (gethash handle *requests*) message)
  handle)


(defclass sample-hunchentoot-op (openid-provider)
  ((finish-uri :initarg :finish-uri :reader finish-uri)))

(defmethod allow-unencrypted-association-p ((op sample-hunchentoot-op) message)
  "Allow unencrypted association in HTTPS sessions."
  (declare (ignore message))
  (ssl-p))


(defvar *checkid-immediate-counter* 0)
(defmethod handle-checkid-immediate ((op sample-hunchentoot-op) message)
  "Handle checkid_immediate: accept every second request"
  (declare (ignore message))
  (oddp (incf *checkid-immediate-counter*)))

(defmethod handle-checkid-setup
    ((op sample-hunchentoot-op) message
     &aux (handle (store-request message)))

  (html "Log in?"
        "<h2>Message:</h2>
<dl>~:{<dt>~A</dt><dd>~A</dd>~}</dl>
<strong><a href=\"~A\">Log in</a> or <a href=\"~A\">cancel</a>?</strong>"
        (mapcar #'(lambda (c)
                    (list (car c) (cdr c)))
                message)
        (copy-uri (finish-uri op) :query (format nil "handle=~A&allow=1" handle))
        (copy-uri (finish-uri op) :query (format nil "handle=~A&deny=1" handle))))

(defun finish-checkid-setup (op &aux
                             (handle (get-parameter "handle"))
                             (message (gethash handle *requests*)))
  (remhash handle *requests*)
  (if (get-parameter "allow")           ; Lame and possibly insecure
      (successful-response op message)
      (cancel-response op message)))


(defvar *openid-provider* nil)

(defun hunchentoot-openid-response (body &optional code)
  (cond
    ((not code) body)

    ((= code +indirect-response-code+)
     (redirect (princ-to-string body) :code +indirect-response-code+)
     nil)

    (t (setf (return-code) code)
       body)))

(defun finish-checkid-handle ()
  (multiple-value-call 'hunchentoot-openid-response
    (finish-checkid-setup *openid-provider*)))

(defun provider-ht-handle ()
  (multiple-value-call 'hunchentoot-openid-response
    (handle-openid-provider-request *openid-provider*
                                    (append (post-parameters)
                                            (get-parameters)))))

(defun init-provider (base-uri prefix
                      &aux
                      (op-endpoint-uri (merge-uris prefix base-uri))
                      (finish-prefix (concatenate 'string prefix "finish-setup"))
                      (finish-uri (merge-uris finish-prefix base-uri)))
  (setf *openid-provider*
        (make-instance 'sample-hunchentoot-op
                       :op-endpoint-uri op-endpoint-uri
                       :finish-uri finish-uri)

        *dispatch-table*
        (nconc (list (create-prefix-dispatcher finish-prefix 'finish-checkid-handle)
                     (create-prefix-dispatcher prefix 'provider-ht-handle))))

  (pushnew 400 *approved-return-codes*))

; (init-provider "http://example.com/" "/cl-openid-op/")
