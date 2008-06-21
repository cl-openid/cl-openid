(defpackage #:cl-openid
  (:use #:common-lisp
        #:drakma
        #-allegro puri #+allegro net.uri
        #:net.html.parser
        #:split-sequence
        #:cl-base64
        #:trivial-utf-8
        #:ironclad)
  (:export))
