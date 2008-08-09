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

(defun handle-checkid-setup (message
                             &aux
                             (handle (cl-openid::register-op-request message))
                             (finish-uri (merge-uris "finish-setup" cl-openid::*endpoint-uri*)))
  (html "Log in?"
        "<h2>Message:</h2>
<dl>~:{<dt>~A</dt><dd>~A</dd>~}</dl>
<strong><a href=\"~A\">Log in</a> or <a href=\"~A\">cancel</a>?</strong>"
        (mapcar #'(lambda (c)
                    (list (car c) (cdr c)))
                message)
        (copy-uri finish-uri :query (format nil "handle=~A&allow=1" handle))
        (copy-uri finish-uri :query (format nil "handle=~A&deny=1" handle))))

(defun finish-checkid-setup (&aux
                             (handle (get-parameter "handle"))
                             (message (gethash handle cl-openid::*op-requests*)))
  (if (get-parameter "allow")
      (cl-openid::indirect-response (cl-openid::message-field message "openid.return_to")
                                    (cl-openid::successful-response message))
      (cl-openid::indirect-response (cl-openid::message-field message "openid.return_to")
                                    (cl-openid::cancel-response))))

(defun finish-checkid-handle (endpoint)
  (lambda ()
    (let ((cl-openid::*endpoint-uri* endpoint))
      (finish-checkid-setup))))

(defun provider-ht-handle (endpoint)
  (lambda ()
    (let ((cl-openid::*endpoint-uri* endpoint))
      (cl-openid::handle-openid-provider-request (append (post-parameters) (get-parameters))))))

(defun provider-ht-dispatcher (endpoint prefix)
  (list (create-prefix-dispatcher (concatenate 'string prefix "finish-setup")
                                  (finish-checkid-handle endpoint))
        (create-prefix-dispatcher prefix
                                  (provider-ht-handle (uri endpoint)))))

#+eval-to-initialize
(progn
  (setf *dispatch-table*
        (nconc (provider-ht-dispatcher "http://example.com/cl-openid-op/" "/cl-openid-op/")
               *dispatch-table*))

  (setf cl-openid::*checkid-immediate-callback* (constantly t) ; trivial example
        cl-openid::*checkid-setup-callback* 'handle-checkid-setup)

  ;; FIXME: Hunchentoot headers.lisp:136 (START-OUTPUT)
  (push 400 *approved-return-codes*))
