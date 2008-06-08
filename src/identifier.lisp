;;; -*- lisp -*-
;;; identifier.lisp - OpenID Identifier API

(in-package #:cl-openid)

(defun remove-dot-segments (parsed-path)
  "Remove . and .. from parsed URI path, to correctly identify same
  paths and prevent URI traversal attacks."
  (loop
     with traversed = nil  
     for element in (loop
                       for (element next) on (rest parsed-path)
                       for ignored = (member element '("" ".") :test #'string=)
                       when (and next (not ignored)) collect element
                       else when (not next) collect (if ignored
                                                        ""
                                                        element))
     if (and (stringp element)
             (string= element ".."))
     do (pop traversed)
     else do (push element traversed)
     finally (return (cons (first parsed-path)
                           (nreverse traversed)))))

(defun normalize-identifier (id)
  "Normalize a user-given identifier ID, return alist token.

An XRDS URL for Yadis discovery discovered by a HEAD request may be
also included in the token.."
  ;; OpenID Authentication 2.0 Final, Section 7.2.  Normalization

  ;; 1., 2.
  (let ((possible-xri (if (string= "xri://" (subseq id 0 6))
                          (subseq id 6)
                          id)))
    (when (member (char possible-xri 0)
                  '(#\= #\@ #\+ #\$ #\! #\())
      ;; input SHOULD be treated as an XRI
      (error "XRI identifiers are not supported.")))

  ;; 3. the input SHOULD be treated as an http URL

  ;; if it does not include a "http" or "https" scheme, the Identifier
  ;; MUST be prefixed with the string "http://"
  (unless (or (string= (subseq id 0 5) "http:")
              (string= (subseq id 0 6) "https:"))
    (setf id (concatenate 'string "http://" id)))
  
  (let ((id (uri id)))
    ;; If the URL contains a fragment part, it MUST be stripped off
    ;; together with the fragment delimiter character "#"
    (setf (uri-fragment id) nil)

    ;; Host is case-insensitive
    (setf (uri-host id) (string-downcase (uri-host id)))

    ;; Traverse dots and double dots.  What about // in middle of path?
    (setf (uri-parsed-path id)
          (if (uri-parsed-path id)
              (remove-dot-segments (uri-parsed-path id))
              '(:absolute "")))         ; An empty path component is
                                  ; normalized to a slash

    ;; URL Identifiers MUST then be further normalized by both
    ;; following redirects when retrieving their content and finally
    ;; applying the rules in Section 6 of [RFC3986] to the final
    ;; destination URL.
    (multiple-value-bind
          (body-or-stream status-code headers uri stream must-close reason-phrase)
        (http-request id :method :head :close t)
      (declare (ignore body-or-stream stream must-close))
      (unless (= 2 (floor (/ status-code 100))) ; 2xx succesful response
        (error "Could not reach ~A: ~A ~A" id status-code reason-phrase))

      ;; Construct return alist
      (let ((rv ())
            (xrds (assoc :x-xrds-location headers)))
        (push (cons :claimed-id uri) rv)
        (when xrds
          (push xrds rv))
        rv))))

(defparameter +entities+
  '(("amp" . #\&) ("gt" . #\>) ("lt" . #\<) ("quot" . #\"))
  "Alist of HTML entities to be unquoted.")

(defun n-remove-entities (str)
  (loop
     for s = (position #\& str) then (position #\& str :start (1+ s))
     for e = (when s
               (position #\; str :start (1+ s)))
     for replacement = (when (and s e)
                         (cdr (assoc (subseq str (1+ s) e) +entities+
                                     :test #'string-equal)))
     while s
     #|DEBUG do (print (list s e (subseq str (1+ s) e) '-> replacement)) |#
     when replacement
     do (setf (aref str s) replacement
              (subseq str (1+ s)) (subseq str (1+ e))
              str (adjust-array str (- (length str) (- e s))))
     finally (return str)))

(defun perform-html-discovery (id body &aux href-cache)
  (labels ((href (link)
             "The HREF attribute of LINK, cached."
             (or href-cache
                 (setf href-cache
                       (n-remove-entities
                        (getf (cdar link) :href)))))

           (remember (name key rel link)
             "When NAME is in REL, push (CONS KEY (HREF LINK)) to ID."
             (when (member name rel :test #'string-equal)
               (push (cons key (href link)) id)))

           (handle-link-tag (link       ; ((:link attrs...))
                             &aux
                             (rel (split-sequence #\Space (getf (cdar link) :rel))))
             (remember "openid2.provider" :op-endpoint-url rel link)
             (remember "openid2.local_id" :op-local-identifier rel link)
             (remember "openid.server" :v1.op-endpoint-url rel link)
             (remember "openid.delegate" :v1.op-local-identifier rel link))

           (handle-meta-tag (meta)
             (when (string-equal "X-XRDS-Location" (getf (cdar meta) :http-equiv))
               (push (cons :x-xrds-location (getf (cdar meta) :content)) id))))

    (parse-html body :callback-only t
                :callbacks (acons :link #'handle-link-tag
                                  (acons :meta #'handle-meta-tag
                                         nil))))
  id)

(defun perform-xrds-discovery (id body)
  (declare (ignore body))
  (warn "XRDS not supported (yet)")
  id)

(defun discover (id
                 &aux
                 (id-x-xrds-location (assoc :x-xrds-location id))
                 (request-uri (cdr (or id-x-xrds-location
                                       (assoc :claimed-id id)))))
  "Perform discovery."
  ;; OpenID Authentication 2.0 Final, Section 7.3.  Discovery
  (let ((*text-content-types* (append '(("application" . "xhtml+xml") ("application" . "xrds+xml"))
                                      *text-content-types*)))
    (multiple-value-bind
          (body status-code headers uri stream must-close reason-phrase)
        (http-request request-uri :additional-headers '((:accept-encoding "")))
      (declare (ignore uri stream must-close))
      
      (unless (= 2 (floor (/ status-code 100))) ; 2xx succesful response
        (error "Could not reach ~A: ~A ~A" request-uri status-code reason-phrase))

      ;; X-XRDS-Location: header check
      (let ((x-xrds-location (assoc :x-xrds-location headers)))
        (when x-xrds-location
          (if id-x-xrds-location
              (setf (cdr id-x-xrds-location) (cdr x-xrds-location))
              (push x-xrds-location id))
          ;; FIXME: what if document (erroneously) points X-XRDS-Location: to itself?
          (return-from discover
            (discover id))))

      ;; Content-Type: check
      (let ((content-type (multiple-value-list (get-content-type headers))))
        (setf (cddr content-type) nil)  ; drop parameters
        (cond
          ((or id-x-xrds-location ; wikitravel returns XRDS as
                                  ; text/html, so when we asked
                                  ; explicitly for XRDS we assume we
                                  ; receive XRDS.
               (equalp '("application" "xrds+xml") content-type))
           (perform-xrds-discovery id body))

          ((member content-type '(("text" "html")
                                  ("application" "xhtml+xml"))
                   :test #'equalp)
           (let ((new-id (perform-html-discovery id body)))
             (if (assoc :x-xrds-location new-id)
                 (discover new-id)      ; go through Yadis discovery
                 new-id)))

          (t (error "Unsupported content-type ~S at ~A" content-type request-uri)))))))
