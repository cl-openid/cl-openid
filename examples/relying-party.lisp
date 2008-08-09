(defpackage #:cl-openid.example-rp
  (:use #:common-lisp #:cl-openid #:puri #:hunchentoot))

(in-package #:cl-openid.example-rp)

(defun html (title body &rest body-args)
  "Simple HTML formatting."
  (format nil "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\"
   \"http://www.w3.org/TR/html4/strict.dtd\">
<html><head><title>~A</title></head>
<body>~?</body></html>"
          title body body-args))

(defun handle-openid-request (uri realm message postfix)
  "Handle single OpenID Relying Party request for the received MESSAGE, using URI as return_to address and REALM as a realm.

Returns a string with HTML response and a redirect URI if applicable."
  (if (null postfix)
      (if (cl-openid::message-field message "openid_identifier")
          (values nil
                  (cl-openid::initiate-authentication (cl-openid::message-field message "openid_identifier") uri realm
                                                      :immediate-p (cl-openid::message-field message "checkid_immediate")))
          (html "CL-OpenID login"
                "<form method=\"GET\"><fieldset><legend>OpenID Login</legend>
<input type=\"text\" name=\"openid_identifier\" value=\"\" style=\"background-image: url('http://openid.net/wp-content/uploads/2007/10/openid_small_logo.png');background-position: 0px 0px;background-repeat: no-repeat;padding-left: 20px;\">
<input type=\"submit\" name=\"openid_action\" value=\"Login\">
<br><label><input type=\"checkbox\" name=\"checkid_immediate\"> Immediate request</label></form>"))
      (handler-case
          (html "CL-OpenID result"
                "~A <p><strong>realm:</strong> ~A</p>
<h2>Response:</h2>
<dl>~:{<dt>~A</dt><dd>~A</dd>~}</dl>
<p style=\"text-align:right;\"><a href=\"~A\">return</a><p>"
                (let ((id (cl-openid::handle-indirect-response message (gethash postfix cl-openid::*authprocs*)))) ; FIXME: accept a postfix
                  (if id
                      (format nil
                              "<h1 style=\"color: green; text-decoration: blink;\">ACCESS GRANTED !!!</h1><p>ID: <code>~A</code></p>"
                              (escape-for-html (prin1-to-string id)))
                      "<h1 style=\"color: red; text-decoration: blink;\">ACCESS DENIED !!!</h1>"))
                realm
                (mapcar #'(lambda (c)
                            (list (car c) (cdr c)))
                        message)
                uri)

        (openid-assertion-error (e)
          (html "CL-OpenID assertion error"
                "<h1 style=\"color: red; text-decoration: blink;\">ERROR ERROR ERROR !!!</h1>
<p><strong>~S</strong> ~A</p>
<h2>Response:</h2>
<dl>~:{<dt>~A</dt><dd>~A</dd>~}</dl>
<p style=\"text-align:right;\"><a href=\"~A\">return</a><p>
"
                (cl-openid::code e) e
                (mapcar #'(lambda (c)
                            (list (car c) (cdr c)))
                        (cl-openid::message e))
                uri)))))

;; Hunchentoot-specific part
(defun openid-ht-handler (uri realm prefix)
  "Return a Hunchentoot handler for OpenID request for URI and REALM (closure over HANDLE-OPENID-REQUEST)."
  (let ((u (uri uri))
        (r (uri realm))
        (l (1+ (length prefix))))
    #'(lambda ()
        (multiple-value-bind (content uri)
            (handle-openid-request u r (get-parameters)
                                   ;; Postfix
                                   (when (> (length (script-name)) l)
                                     (subseq (script-name) l)))
          (when uri
            (redirect (princ-to-string uri)))
          content))))

(defun openid-ht-dispatcher (prefix realm &optional uri)
  "Return a prefix dispatcher for OPENID-HT-HANDLER.

If URI is not supplied, the PREFIX is merged with REALM uri"
  (unless uri
    (setf uri (merge-uris prefix realm)))

  (create-prefix-dispatcher prefix (openid-ht-handler uri realm prefix)))

; (push (openid-ht-dispatcher "/cl-openid" "http://example.com/") *dispatch-table*)
