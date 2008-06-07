; -*- lisp -*-

(defpackage #:cl-openid.system
  (:use #:common-lisp #:asdf))
(in-package #:cl-openid.system)

(defsystem #:cl-openid
  :name "cl-openid"
  :description "cl-openid"
  :version "0.1"
  :author "Maciej Pasternacki"
  :maintainer "Maciej Pasternacki"
  :licence "LLGPL, see http://opensource.franz.com/preamble.html for details"

  :components
  ((:module #:src
            :components ((:file "package")
                         (:file "identifier" :depends-on ("package")))))
  :depends-on (#:hunchentoot #:drakma #:ironclad #:xmls #:split-sequence
                             #-allegro #:puri
                             #-allegro #:cl-html-parse))

#+allegro
(defmethod asdf:perform :after ((op load-op)
                                (component (eql (find-system :cl-openid))))
  "Use Allegro's own version of ported libraries."
  (require 'uri)
  (require 'phtml))

(defsystem #:cl-openid.test
  :version "0.1"
  :description "Test suite for cl-openid"
  :components
  ((:module #:t
    :components ((:file "suite")
                 (:file "identifier" :depends-on ("suite")))))
  :depends-on (#:cl-openid #:fiveam))

(defmethod perform ((op asdf:test-op)
                    (system (eql (find-system :cl-openid))))
  "Perform unit tests for cl-openid"
  (asdf:operate 'asdf:load-op :cl-openid.test)
  (funcall (intern (string :run!) (string :it.bese.fiveam))
           (intern (string :cl-openid) (string :cl-openid))))
