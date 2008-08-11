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

(defvar *relying-party* nil
  "A relying party instance.")

(defparameter *login-form*
  (html "CL-OpenID login"
        "<form method=\"GET\"><fieldset><legend>OpenID Login</legend>
<input type=\"text\" name=\"openid_identifier\" value=\"\" style=\"background-image: url('http://openid.net/wp-content/uploads/2007/10/openid_small_logo.png');background-position: 0px 0px;background-repeat: no-repeat;padding-left: 20px;\">
<input type=\"submit\" name=\"openid_action\" value=\"Login\">
<br><label><input type=\"checkbox\" name=\"checkid_immediate\"> Immediate request</label></form>"))

(defun access-denied-screen ()
  (html "CL-OpenID result"
        "<h1 style=\"color: red; text-decoration: blink;\">ACCESS DENIED !!!</h1>
<p><strong>realm:</strong> ~A</p>
<h2>Response:</h2>
<dl>~:{<dt>~A</dt><dd>~A</dd>~}</dl>
<p style=\"text-align:right;\"><a href=\"~A\">return</a><p>"
        (realm *relying-party*)
        (alist-to-lol (get-parameters))
        (root-uri *relying-party*)))

(defun access-granted-screen (id)
  (html "CL-OpenID result"
        "<h1 style=\"color: green; text-decoration: blink;\">ACCESS GRANTED !!!</h1><p>ID: <code>~A</code></p>
<p><strong>realm:</strong> ~A</p>
<h2>Response:</h2>
<dl>~:{<dt>~A</dt><dd>~A</dd>~}</dl>
<p style=\"text-align:right;\"><a href=\"~A\">return</a><p>"
        (escape-for-html (prin1-to-string id))
        (realm *relying-party*)
        (alist-to-lol (get-parameters))
        (root-uri *relying-party*)))

(defun assertion-error-screen (err)
  (html "CL-OpenID assertion error"
                "<h1 style=\"color: red; text-decoration: blink;\">ERROR ERROR ERROR !!!</h1>
<p><strong>~S</strong> ~A</p>
<h2>Response:</h2>
<dl>~:{<dt>~A</dt><dd>~A</dd>~}</dl>
<p style=\"text-align:right;\"><a href=\"~A\">return</a><p>"
                (code err)
                err
                (alist-to-lol (get-parameters))
                (root-uri *relying-party*)))

(defun handle-openid-request ()
  "Handle request for an OpenID Relying Party."
  (if (null (get-parameter +authproc-handle-parameter+)) ; parameter included on authentication process finalization

      (if (null (get-parameter "openid_identifier"))
          *login-form*          ; No ID supplied, present login form
          (redirect             ; ID supplied, initiate authentication
           (princ-to-string
            (initiate-authentication *relying-party* (get-parameter "openid_identifier")
                                     :immediate-p (get-parameter "checkid_immediate")))))

      (handler-case
          (let ((id (handle-indirect-response *relying-party* (get-parameters))))
            (if id
                (access-granted-screen id)
                (access-denied-screen)))
        (openid-assertion-error (e)
          (assertion-error-screen e)))))


(defun init-relying-party (realm prefix &optional (uri (merge-uris prefix realm)))
  (setf *relying-party* (make-instance 'relying-party
                                       :root-uri uri
                                       :realm (uri realm)))

  (push (create-prefix-dispatcher prefix 'handle-openid-request)
        *dispatch-table*))

; (init-relying-party "http://example.com/" "/cl-openid/")
