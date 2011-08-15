(defpackage #:cl-openid.example-rp
  (:use #:common-lisp #:cl-openid #:puri #:hunchentoot))

(in-package #:cl-openid.example-rp)


(defvar *relying-party* nil
  "A relying party instance, filled when calling INIT-RELYING-PARTY.")

;;; Formatting HTML
(defun html (title body &rest body-args)
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

(defparameter *login-form*
  (html "CL-OpenID login"
        "<form method=\"GET\"><fieldset><legend>OpenID Login</legend>
<input type=\"text\" name=\"openid_identifier\" value=\"\" style=\"background-image: url('http://openid.net/wp-content/uploads/2007/10/openid_small_logo.png');background-position: 0px 0px;background-repeat: no-repeat;padding-left: 20px;\">
<input type=\"submit\" name=\"openid_action\" value=\"Login\">
<br><label><input type=\"checkbox\" name=\"checkid_immediate\"> Immediate request</label></form>")
  "Initial login form")

(defun access-denied-screen ()
  "Screen displayed on cancel response"
  (html "CL-OpenID result"
        "<h1 style=\"color: red; text-decoration: blink;\">ACCESS DENIED !!!</h1>
<p><strong>realm:</strong> ~A</p>
<h2>Response:</h2>
<dl>~:{<dt>~A</dt><dd>~A</dd>~}</dl>
<p style=\"text-align:right;\"><a href=\"~A\">return</a><p>"
        (realm *relying-party*)
        (alist-to-lol (get-parameters*))
        (root-uri *relying-party*)))

(defun access-granted-screen (authproc)
  "Screen displayed on successful id_res response."
  (html "CL-OpenID result"
        "<h1 style=\"color: green; text-decoration: blink;\">ACCESS GRANTED !!!</h1><p>ID: <code>~A</code></p>
<h2>Response:</h2>
<dl>~:{<dt>~A</dt><dd>~A</dd>~}</dl>
<p style=\"text-align:right;\"><a href=\"~A\">return</a><p>"
        (escape-for-html (prin1-to-string authproc))
        (alist-to-lol (get-parameters*))
        (root-uri *relying-party*)))

(defun assertion-error-screen (err)
  "Screen displayed on wrong id_res response."
  (html "CL-OpenID assertion error"
                "<h1 style=\"color: red; text-decoration: blink;\">ERROR ERROR ERROR !!!</h1>
<p><strong>~S</strong> ~A</p>
<h2>Response:</h2>
<dl>~:{<dt>~A</dt><dd>~A</dd>~}</dl>
<p style=\"text-align:right;\"><a href=\"~A\">return</a><p>"
                (code err)
                err
                (alist-to-lol (get-parameters*))
                (root-uri *relying-party*)))

;;; Actual handler
(defun handle-openid-request ()
  "Handle request for an OpenID Relying Party."

  ;; I decided to implement RP on single URI.  It is used for three
  ;; different things: for displaying the login form to the user, for
  ;; accepting the ID and initiating authentication, and for accepting
  ;; indirect reply and displaying result.  We distinguish these
  ;; situations by looking at GET parameters:

  (cond
    ;; CL-OpenID sends unique handle of authentication process in GET
    ;; parameter named +AUTHPROC-HANDLE-PARAMETER+.  If such parameter
    ;; is present, this request is an indirect response.
    ((get-parameter +authproc-handle-parameter+)
     (handler-case
	 (let ((authproc (handle-indirect-response
                          *relying-party* (get-parameters*) ; The incoming message alist consists of GET parameters.
                          (merge-uris (request-uri*) (root-uri *relying-party*))))) ; Figuring out actual request URI may be more complicated with proxies
	   (if authproc	; On successful id_res, AUTH-PROCESS structure is returned; on cancel response, we get NIL.
	       (access-granted-screen authproc)
	       (access-denied-screen)))
       (openid-assertion-error (e) ; On incorrect id_res OPENID-ASSERTION-ERROR is signaled
	 (assertion-error-screen e))))

    ;; If the request is not an indirect response, we check for
    ;; openid_identifier parameter, in which our own login form sends
    ;; us user's claimed ID, as suggested by OpenID 2.0 specification,
    ;; section 7.1 Initiation.
    ((get-parameter "openid_identifier")
     (redirect            
      (initiate-authentication *relying-party* (get-parameter "openid_identifier")
                               :immediate-p (get-parameter "checkid_immediate"))))

    ;; When there are no parameters, or there are some unexpected
    ;; ones, we just assume it is an initial request and show the
    ;; login form.
    (t
     *login-form*)))

;;; Initialization
(defun init-relying-party (realm prefix &optional (uri (merge-uris prefix realm)))
  (setf *relying-party* (make-instance 'relying-party
                                       :root-uri uri
                                       :realm (uri realm)))

  (push (create-prefix-dispatcher prefix 'handle-openid-request)
        *dispatch-table*))

(init-relying-party "http://localhost:4242/" "/cl-openid/")
