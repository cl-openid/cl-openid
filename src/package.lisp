(defpackage #:cl-openid
  (:use #:common-lisp
        #:drakma
        #-allegro puri #+allegro net.uri
        #:net.html.parser
        #:split-sequence
        #:cl-base64
        #:trivial-utf-8
        #:ironclad
        #:anaphora)
  (:shadowing-import-from :cl #:null) ; Ironclad shadows NULL, we don't want to
  (:export))
