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

(defun alist-to-lol (alist)
  "Return ALIST as list-of-lists for pretty formatting"
  (mapcar #'(lambda (c)
              (list (car c) (cdr c)))
          alist))

(defun handle-openid-request (rp message postfix)
  "Handle single OpenID Relying Party request for the received MESSAGE and URI postfix POSTFIX.

Returns a string with HTML response and a redirect URI if applicable."
  (if (null postfix) ;; POSTFIX is given for auth finalization
      (if (null (cl-openid::message-field message "openid_identifier"))
          ;; No ID received, return login form.
          (html "CL-OpenID login"
                "<form method=\"GET\"><fieldset><legend>OpenID Login</legend>
<input type=\"text\" name=\"openid_identifier\" value=\"\" style=\"background-image: url('http://openid.net/wp-content/uploads/2007/10/openid_small_logo.png');background-position: 0px 0px;background-repeat: no-repeat;padding-left: 20px;\">
<input type=\"submit\" name=\"openid_action\" value=\"Login\">
<br><label><input type=\"checkbox\" name=\"checkid_immediate\"> Immediate request</label></form>")
          ;; ID received, initiate authentication process
          (values nil
                  (cl-openid::initiate-authentication rp
                                                      (cl-openid::message-field message "openid_identifier")
                                                      :immediate-p (cl-openid::message-field message "checkid_immediate"))))
      ;; POSTFIX received, finalize authentication process
      (handler-case
          (html "CL-OpenID result" ;; Format the result
                "~A <p><strong>realm:</strong> ~A</p>
<h2>Response:</h2>
<dl>~:{<dt>~A</dt><dd>~A</dd>~}</dl>
<p style=\"text-align:right;\"><a href=\"~A\">return</a><p>"
                (let ((id (cl-openid::handle-indirect-response rp message postfix)))
                  (if id
                      (format nil
                              "<h1 style=\"color: green; text-decoration: blink;\">ACCESS GRANTED !!!</h1><p>ID: <code>~A</code></p>"
                              (escape-for-html (prin1-to-string id)))
                      "<h1 style=\"color: red; text-decoration: blink;\">ACCESS DENIED !!!</h1>"))
                (cl-openid::realm rp) (alist-to-lol message) (cl-openid::root-uri rp))

        ;; Catch assertion verification error
        (cl-openid::openid-assertion-error (e)
          (html "CL-OpenID assertion error"
                "<h1 style=\"color: red; text-decoration: blink;\">ERROR ERROR ERROR !!!</h1>
<p><strong>~S</strong> ~A</p>
<h2>Response:</h2>
<dl>~:{<dt>~A</dt><dd>~A</dd>~}</dl>
<p style=\"text-align:right;\"><a href=\"~A\">return</a><p>"
                (cl-openid::code e) e (alist-to-lol message) (cl-openid::root-uri rp))))))

(defun openid-ht-handler (uri realm prefix)
  "Return a Hunchentoot handler for OpenID request for URI and REALM (closure over HANDLE-OPENID-REQUEST)."
  (let ((l (1+ (length prefix)))
        (rp (make-instance 'cl-openid::relying-party
                           :root-uri uri :realm realm)))
    #'(lambda ()
        (multiple-value-bind (content uri)
            (handle-openid-request rp
                                   (get-parameters)
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
